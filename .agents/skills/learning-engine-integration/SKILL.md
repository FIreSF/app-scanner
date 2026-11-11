---
name: Learning Engine Integration
description: Use when persisting engagement results into the SQLite learning engine — sessions, findings, tested variants, triage feedback and lessons (orchestrator-only standard).
---

# SKILL — Learning Engine Integration (`.agents/skills/learning-engine-integration/SKILL.md`)

**Owner:** `orchestrator-agent` (the only agent allowed to persist learning)
**Runtime:** `learning_engine/engine.py` · SQLite at `learning_engine/learning_memory.db`
**Referenced by:** `runtime/registry.json` → `orchestrator-agent.skills`, `deepseek_markdown_20261031_3cb07b.md` §14, `README.md`

---

## 1. Purpose

The learning engine is the durable memory of the framework. It records what was
tested, what was found, what triage rejected, and which lessons must be applied
to the next engagement. Sub-agents never write to it — they return a structured
summary and the orchestrator persists the outcome.

The engine is **append-only in spirit**: never edit history to make a session
look better. A false positive is valuable data; keep it.

---

## 2. The five lifecycle hooks

| Hook | When to call | What it stores |
|---|---|---|
| `before_recon(target, technologies, session_id=None, mode="hunt")` | Phase 0, after scope lock | Session row + returns past `lessons_learned` so the hunt starts informed |
| `during_testing(session_id, surface, variant_tested, result, ...)` | After every meaningful test/variant | One row in `tested_variants` (`PASS`, `VULN`, `BLOCKED`, `FP`) |
| `after_finding(finding_dict)` | When a lead changes state | `findings` row keyed by `finding_id`, with `signature_hash`, state, evidence |
| `before_summary(session_id)` | Before the HUNT SUMMARY | Aggregates findings, severity breakdown and tested surfaces |
| `after_triage(feedback)` | On program triage feedback | `triage_feedback` row; a `FALSE_POSITIVE` verdict also writes a lesson |

`after_triage` accepts either a dict
(`{"finding_id": ..., "verdict": ..., "comment": ...}`) or positional arguments
`after_triage(finding_id, verdict, comment)`.

---

## 3. Contract rules

1. **One session per engagement.** `before_recon` returns the `session_id`; store
   it in `testing/<pkg>/notes/bootstrap.md` and use it for every hook call.
2. **Never fabricate outcomes.** Only call `after_finding` with evidence that
   exists on disk. Demo/sample commands must run with a throwaway database.
3. **State changes are gated.** The engine records the state it is given; the
   authority for promotion is `scripts/findings.py` (state machine + Hard FP
   Gate), not the engine.
4. **Signature hashes are canonical.** Always compute with
   `scripts/findings.py hash` (or `signature_hash()`), never by hand.
5. **Triage feedback is the only source of learning.** Never feed a session's
   own conclusions back as "lessons".
6. **Privacy:** never store live PII, tokens, or customer identifiers in
   `impact`, `notes`, or `poc_path`. Redact before writing.

---

## 4. CLI

```bash
# Session lifecycle + summary
python -m learning_engine init --target com.example.app --technologies "okhttp,sqlite"
python -m learning_engine summary --session sess_20261031_120000_ab12cd
python -m learning_engine stats

# Direct module use
python learning_engine/engine.py
```

From Python:

```python
from learning_engine import LearningEngine

engine = LearningEngine()
session = engine.before_recon("com.example.app", ["flutter", "okhttp"])
engine.during_testing(session["session_id"], "ipc", "exported-activity-intent-redirection",
                      "VULN", skill_used="skills/ipc-deeplink-exploitation.md",
                      evidence_path="testing/com.example.app/ipc/poc_redirect.sh")
engine.after_finding({
    "session_id": session["session_id"],
    "target_package": "com.example.app",
    "title": "Intent redirection to unexported activity",
    "severity": "High",
    "state": "CONFIRMED",
    "masvs_category": "MASVS-PLATFORM",
    "impact": "Attacker launches unexported activity with victim privileges",
    "poc_path": "testing/com.example.app/ipc/poc_redirect.sh",
    "verified": 0,
})
print(engine.before_summary(session["session_id"]))
engine.end_session(session["session_id"])
```

---

## 5. Storage schema (read-only reference)

```
sessions(session_id PK, target_package, start_time, end_time, technologies, mode)
tested_variants(id PK, session_id FK, surface, variant_tested, skill_used,
                result, evidence_path, tested_at, notes)
findings(finding_id PK, session_id FK, target_package, title, severity, state,
         signature_hash, masvs_category, impact, poc_path, verified, created_at)
triage_feedback(id PK, finding_id FK, verdict, comment, recorded_at)
lessons_learned(id PK, surface, pattern, lesson, effective_technique, created_at)
```

Foreign keys are enforced (`PRAGMA foreign_keys = ON`); a hook that references an
unknown session or finding raises `sqlite3.IntegrityError` instead of silently
writing orphan rows.

---

## 6. Failure handling

| Situation | Behaviour |
|---|---|
| Database missing | Created from `schema.sql` on first use (idempotent) |
| Unknown `session_id` in `during_testing` | Raises `IntegrityError` — call `before_recon` first |
| Engine unavailable in a script | Script continues and logs a warning; evidence files remain the source of truth |
| Corrupted database | Restore from backup; never delete `memory/*.md` history to "fix" it |
