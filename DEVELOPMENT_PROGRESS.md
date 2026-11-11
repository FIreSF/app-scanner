# DEVELOPMENT PROGRESS

**Project:** Mobile-Pentesting Multi-Agent Framework (v1.2.0)
**Window:** 2026-10-31 (second pass: 2026-11-11 — see §11)
**Scope of this pass:** audit → P0/P1 remediation → test coverage → documentation
**Status:** P0 + P1 + P2 complete; the P3 quality items were completed in the continuation pass (§10). Only the destructive demo-row cleanup and device-bound verification remain with the operator.

---

## 1. Approach

The repository is a documentation-first framework with a small Python runtime, so the work
was sequenced as:

1. **Audit first** — read the spec (`deepseek_markdown_20261031_3cb07b.md`, 906 lines),
   `AGENTS.md`, the registry, all 17 agent briefings, skills, memory templates and scripts;
   reproduce each suspected defect before changing anything.
2. **Fix P0 before building P1** — an unusable CLI and a gate that fabricates evidence make
   every later feature meaningless.
3. **Implement missing documented behaviour as new modules**, not rewrites: existing public
   entry points (`orchestrator_runner.py`, `runtime_preflight.py`, `skill_registry.py`,
   `learning_engine/`) keep their interfaces and delegate to new, testable code.
4. **Test every change** with `unittest` (no new dependencies), using temporary databases and
   workspaces so the shipped state is never mutated by tests.
5. **Document honestly** — anything that needs a device or an APK is recorded as unverified.

Non-negotiables honoured: no mock data in production paths, no fake success output, no TODO
placeholders, no hardcoded secrets, no new third-party dependencies, and no destructive
database operations without operator approval.

---

## 2. Phase 1 — Audit

Produced `PROJECT_AUDIT.md` with:

- a feature matrix of 22 capabilities (as-found status),
- 10 reproduced bugs with exact symptoms,
- a security/data-integrity table,
- a P0–P3 roadmap and an implementation sequence.

Key findings: `bootstrap` was unusable (`--target` after the subcommand crashed argparse);
`test-gate --verified` wrote a fabricated `REPORTABLE` finding into the **production** SQLite
memory; the FP database was matched by naive substring; preflight accepted any string as a
target and always reported `READY`; the registry was never structurally validated; and
`writeups/`, wave planning, the state machine, the compliance matrix and the tests did not
exist at all.

---

## 3. Phase 2 — P0 fixes (correctness & data integrity)

| Change | File | Verification |
|---|---|---|
| Order-independent CLI options (`--target` before or after the subcommand) | `scripts/orchestrator_runner.py` | `test_bootstrap_accepts_target_after_subcommand`, `test_plan_accepts_target_*` |
| Demo gate can no longer fabricate `REPORTABLE`; dry-run by default; `--persist` explicit | `scripts/orchestrator_runner.py` | `test_test_gate_does_not_persist_by_default`, `test_test_gate_verdict_is_not_a_real_verification` |
| Missing canonical skill created | `.agents/skills/learning-engine-integration/SKILL.md` | `link-check` resolves it |
| Full registry validation wired into `link-check` | `scripts/registry.py` | `tests/test_registry.py` (21 tests) |
| Real scope gate: target regex, workspace containment, artifact SHA-256, READY/DEGRADED/BLOCKED, exit codes 0/1/2 | `scripts/runtime_preflight.py` | `tests/test_preflight.py` (14 tests) |
| Bootstrap exit code aligned with the preflight contract (DEGRADED → 2) | `scripts/orchestrator_runner.py` | `test_bootstrap_exit_code_matches_preflight_contract` |

---

### 3.1 Late fixes found during documentation review

Writing the docs against real command output caught two further defects:

| Defect | Fix | Test |
|---|---|---|
| `bootstrap` reported `DEGRADED` but exited `0`, contradicting the documented 0/1/2 contract | runner now mirrors `runtime_preflight.py` (2 DEGRADED, 1 with `--strict`) | `test_bootstrap_exit_code_matches_preflight_contract`, `test_bootstrap_strict_fails_on_degraded` |
| `python learning_engine/engine.py` (documented in the skill) crashed with `ModuleNotFoundError` | `__main__` block inserts the repository root on `sys.path` before importing the CLI package | `test_engine_runs_as_plain_script`, `test_module_entry_point_matches_script_entry_point` |

---

## 4. Phase 3 — P1 features

| Feature | Module | Notes |
|---|---|---|
| Dependency waves, phase plan, concurrency-aware dispatch | `scripts/registry.py` | `PHASES`, `dependency_waves()`, `next_dispatchable()`; on-demand agents excluded by default |
| Finding state machine + 7-question gate + reporting gate | `scripts/findings.py` (new, 479 lines) | Legal-transition table; `REPORTABLE` needs all checks **and** `user_approved` |
| Structured FP database | `scripts/findings.py` | 17 parsed signatures, exact-hash matching, `fp-db list/check/add` |
| MASVS v2.0 coverage matrix + gap list | `scripts/compliance_matrix.py` (new, 414 lines) | 23 controls, status derived from real workspace artifacts, writes `compliance/*.md` |
| Skill resolver completion | `scripts/skill_registry.py` | 17 scenarios, aliases, explicit no-match, `--list`, `--validate` |
| Learning-engine hardening | `learning_engine/engine.py`, `cli.py`, `__main__.py` | Context-managed connections, FK enforcement, session lifecycle, queries, `prune` |
| Ledger + evidence scaffolding | `scripts/orchestrator_runner.py`, `scripts/runtime_preflight.py` | `ledger` appends; `tested-variants.md`, `auth_session.md`, `evidence/artifact.json` |
| Writeup pipeline | `scripts/writeup_index.py` (new, 155 lines), `writeups/` | Front-matter parsing, sorted index, `--check`, `--json` |

Design decisions worth recording:

- **No auto-promotion.** Even with all seven gate answers passing, the state stops at
  `VALIDATED` unless `user_approved` is true. This makes the reporting gate a real control,
  not a label.
- **Demo verdicts are distinct values.** `DEMO_CONFIRMED_VALIDATED` is rejected by the gate,
  so a demo run can never be mistaken for an independent verification.
- **Registry is the single source of truth.** Every script and test reads
  `runtime/registry.json` through `scripts/registry.py`, so docs and roster cannot drift
  silently.
- **Tests never touch shipped state.** Temporary SQLite files via
  `MOBILE_AGENT_LEARNING_DB`, temporary workspaces via `tempfile.mkdtemp`.

---

## 5. Phase 4 — Test suite

`python -m unittest discover -s tests -t .` → **161 tests, OK** (≈3.6 s).

| Module | Tests | Covers |
|---|---|---|
| `tests/test_registry.py` | 21 | loading, field/index/graph validation, cycles, waves, concurrency, dispatch, link-check |
| `tests/test_findings.py` | 31 | FP parsing/matching, 7-question gate, reporting gate, state machine, CLI |
| `tests/test_preflight.py` | 14 | target validation, containment, artifact hashing, statuses, scaffolding, idempotence |
| `tests/test_learning_engine.py` | 16 | schema, hooks, FKs, session lifecycle, queries, prune, CLI |
| `tests/test_skill_registry.py` | 11 | scenario coverage, aliases, no-match, validation |
| `tests/test_compliance_matrix.py` | 7 | control catalog, artifact-derived status, reports, CLI |
| `tests/test_orchestrator_cli.py` | 21 | argument order, bootstrap contract, gate, transitions, fp-db, waves, coverage, ledger, summary |
| `tests/test_assets.py` | 7 | JSON validity, Frida parse, doc references, secrets hygiene |
| `tests/test_writeups.py` | 12 | front matter, fallbacks, sorting, rendering, freshness, registry wiring |
| `tests/test_mindmap.py` | 7 | evidence grouping, finding ordering, escaping, write/check, JSON CLI |
| `tests/test_report_builder.py` | 9 | dry-run gate, approval write, exclusion rules, ordering, coverage embed |

Also verified: the suite is clean under `python -W error::ResourceWarning -m unittest ...`
(no leaked SQLite handles).

---

## 6. Phase 5 — Documentation

- `README.md` — rewritten quick start against **verified** commands, accurate exit codes,
  complete directory map, explicit status/limitations section.
- `PROJECT_AUDIT.md` — as-found record preserved; added post-fix status column, per-bug
  resolution table and a remediation-verification table.
- `DEVELOPMENT_PROGRESS.md` — this file.
- `FINAL_PROJECT_REPORT.md` — delivery summary, evidence, limitations, next steps.
- `writeups/README.md` — pipeline rules for the `/update` flow.

---

## 7. Repository state (end of pass)

New files:

```
scripts/registry.py                 scripts/findings.py
scripts/compliance_matrix.py        scripts/writeup_index.py
scripts/__init__.py                 learning_engine/cli.py
learning_engine/__main__.py         .agents/skills/learning-engine-integration/SKILL.md
writeups/README.md                  writeups/index.md
writeups/raw/.gitkeep               writeups/processed/.gitkeep
tests/__init__.py                   tests/support.py
tests/test_registry.py              tests/test_findings.py
tests/test_preflight.py             tests/test_learning_engine.py
tests/test_skill_registry.py        tests/test_compliance_matrix.py
tests/test_orchestrator_cli.py      tests/test_assets.py
tests/test_writeups.py              DEVELOPMENT_PROGRESS.md
FINAL_PROJECT_REPORT.md             PROJECT_AUDIT.md
```

Continuation pass added `scripts/mindmap.py`, `scripts/report_builder.py`,
`tests/test_mindmap.py` and `tests/test_report_builder.py`.

Modified files: `README.md`, `scripts/orchestrator_runner.py`, `scripts/runtime_preflight.py`,
`scripts/skill_registry.py`, `learning_engine/engine.py`. `learning_engine/schema.sql` was left
unchanged (the existing tables already support the work; FK enforcement is enabled at
connection level, not by migration).

The working tree is **uncommitted** (git root `E:\Depi-project`, single commit `ae29dd5`).
No commit was made: the operator has not asked for one.

---

## 8. Verification snapshot

| Check | Command | Result |
|---|---|---|
| Tests | `python -m unittest discover -s tests -t .` | 161 OK |
| Warnings | `python -W error::ResourceWarning -m unittest discover -s tests -t .` | OK |
| Links | `python scripts/orchestrator_runner.py link-check` | PASS (93 references) |
| Registry | `python scripts/orchestrator_runner.py validate-registry` | PASS |
| Skills | `python scripts/skill_registry.py --validate` | 17/17 mapped |
| Doctor | `python scripts/orchestrator_runner.py doctor` | OK (see tool gaps below) |
| Writeups | `python scripts/writeup_index.py --check` | up to date |
| Mindmap | `mindmap --check` on a scaffolded workspace | up to date |
| Report gate | `report` on a VALIDATED finding | preview only; file written only with `--approve` |
| Bootstrap (temp workspace) | `bootstrap --target com.example.demoapp ...` | DEGRADED, exit 2 |
| Scope rejection | `bootstrap --target "not a package!!"` | BLOCKED, exit 1 |

Host tooling is environment-dependent. On the current Linux host `jadx`, `sqlite3`,
`mitmproxy` and `python` are found, while `adb`, `frida` and `apktool` are missing → `bootstrap`
reports `DEGRADED` (exit 2). This is environmental, not a code defect.

---

## 9. Remaining / deferred work

| Item | Reason | Action for operator |
|---|---|---|
| Remove legacy demo rows (`FIND-37243040`, `FIND-DEDBCC04`, 1 orphan `triage_feedback`) from `learning_engine/learning_memory.db` | Destructive DB write; requires explicit approval | Review with `python -m learning_engine prune --orphans --demo` (dry-run), then re-run with `--apply` |
| Execute Frida templates against a live app | Needs an authorized device/emulator and target APK | Out of scope for this pass; document per-engagement results in `testing/<pkg>/` |
| Real APK static analysis (apktool/jadx) | Tools absent, no target artifact | Install tools, then `bootstrap --artifact <apk> --require-tools apktool,jadx` |
| Traffic interception (mitmproxy) | Tool absent, no authorized target | Install mitmproxy and a test CA on the owned device |
| Push the work | Local commit created; HTTPS remote needs credentials | Push the pass commit after authenticating |

---

## 10. Continuation pass — P3 completion (2026-10-31)

This pass closed the remaining quality items without changing any safety
control or public entry point.

| Change | Module | Verification |
|---|---|---|
| Attack-surface mindmap rebuilt from real evidence and `findings/*.json` | `scripts/mindmap.py` (new) | `tests/test_mindmap.py` (7 tests), `mindmap --check` |
| User-gated final report assembly; recomputes the Hard FP Gate and excludes state/evidence mismatches | `scripts/report_builder.py` (new) | `tests/test_report_builder.py` (9 tests), `report` CLI dry-run/approve |
| `findings/` directory added to every scaffolded workspace | `scripts/runtime_preflight.py` | existing preflight suite |
| Tested-variant markdown ledger updated by `ledger --record` | `scripts/orchestrator_runner.py` | `test_ledger_record_updates_tested_variants` |
| `--json` on the remaining commands (`fp-db`, `hash`, learning-engine `init/end/stats/prune`, `mindmap`, `report`) | `scripts/findings.py`, `scripts/orchestrator_runner.py`, `learning_engine/cli.py` | `test_fp_db_commands_support_json`, `test_transition_apply_json_is_valid`, `test_mindmap`/`report` CLI tests |
| Transition `--apply --json` emits one valid JSON document | both transition CLIs | `test_transition_apply_json_is_valid` |
| New modules wired into canonical link validation | `scripts/registry.py` | `link-check` PASS (93 references) |

Test suite: **161 tests, OK**; `link-check` PASS (93 references);
`doctor` still reports the two legacy orphan rows only because they are
deliberately retained until the operator approves deletion.

**Not changed:** no destructive database operation was executed; the legacy
rows can be removed with `python -m learning_engine prune --orphans --demo --apply`
after review.

---

## 11. Second pass — runtime wiring, intel, CI (2026-11-11)

The first pass made the *runtime* trustworthy. This pass made the *framework* real: the roster
became loadable agents, the intel agent got a data source, the memory stopped losing findings,
and the documentation stopped claiming a host that no longer exists.

### 11.1 What changed

| Change | Module | Verification |
|---|---|---|
| Registry → loadable OpenCode agents (`.opencode/agents/*.md`) and project config (`.opencode/opencode.json`) | `scripts/sync_agent_runtime.py` (new) | `sync_agent_runtime.py --check`; runtime reports 24 agents (7 built-in + 17 project) |
| Constitution encoded as permissions: `subagent: deny` for every sub-agent (AGENTS.md §2.6), roster allow-list + blanket deny for `orchestrator-agent` (AGENTS.md §1) | same | `tests/test_agent_runtime.py` (10 tests) |
| All 29 skills given `name` + `description` frontmatter so the model can select them | `skills/*.md`, `.agents/skills/learning-engine-integration/SKILL.md` | `tests/test_agent_runtime.py`; skills visible in the runtime |
| MCP stdio server for `mcp-bug-intel-agent` (NVD API 2.0, OSV, CISA KEV, offline FP-DB check via `scripts.findings.FalsePositiveDB`) | `scripts/mcp_intel_server.py` (new) | `--self-test` 10/10; 49 new tests; server connected, tools return live data |
| `orchestrator_runner.py findings` — reconciles workspace findings with the learning engine (dry-run / `--apply`, gate-recomputed state only) | `scripts/orchestrator_runner.py` | `tests/test_findings_sync.py` (9 tests) |
| `gate --persist` keeps the workspace finding id (was minting a random `FIND-<uuid>`) | `scripts/orchestrator_runner.py` | `test_persist_finding_keeps_the_workspace_finding_id` |
| Per-target finding identity: `findings.finding_id` is a global primary key, but every engagement reuses `FIND-0001` — a colliding id is now stored as `<target>#<finding_id>` | `learning_engine/engine.py` (`resolve_finding_id`, `after_finding`, `get_finding(target_package=...)`) | `test_same_finding_id_in_two_targets_never_overwrites` |
| `doctor` reports the optional Apple toolchain and instructs recording the gap | `scripts/runtime_preflight.py`, `scripts/orchestrator_runner.py` | `doctor` output; `ios_tools` in `--json` |
| Opt-in device-bound test suite (adb device, frida, jadx/apktool/mitmdump, `node --check` on all Frida templates) | `tests/test_lab_integration.py` (new) | `MOBILE_AGENT_LAB=1 python -m unittest tests.test_lab_integration` → 5 OK |
| CI: tests (×2, incl. `-W error::ResourceWarning`), `link-check`, `validate-registry`, skill `--validate`, writeup `--check`, agent-drift `--check`, `doctor` | `.github/workflows/ci.yml` (new) | mirrors the local verification table below |
| Dependency-free project metadata | `pyproject.toml` (new) | `dependencies = []`; `lab` extras documented |
| `runtime/opencode/ORCHESTRATION.md` rewritten — it mandated a `sessions_spawn context="isolated"` API that does not exist | `runtime/opencode/ORCHESTRATION.md` | §0 materialization/dispatch, §3 dispatch checklist |

### 11.2 Verification snapshot (2026-11-11)

Host: Linux WSL2, Python 3.14.7, OpenCode v2.2.7, device `127.0.0.1:21513` connected,
frida 17.25.2.

| Check | Command | Result |
|---|---|---|
| Tests | `python -m unittest discover -s tests -t .` | **234 OK** (5 skipped — the opt-in lab suite) |
| Device-bound tests | `MOBILE_AGENT_LAB=1 python -m unittest tests.test_lab_integration` | **5 OK** |
| Warnings | `python -W error::ResourceWarning -m unittest discover -s tests -t .` | OK |
| Links | `python scripts/orchestrator_runner.py link-check` | **PASS — 94 references** |
| Registry | `python scripts/orchestrator_runner.py validate-registry` | PASS |
| Agent runtime | `python scripts/sync_agent_runtime.py --check` | in sync (18 managed files) |
| Skills | `python scripts/skill_registry.py --validate` | 17/17 mapped |
| Writeups | `python scripts/writeup_index.py --check` | up to date |
| MCP server | `python scripts/mcp_intel_server.py --self-test` | PASS (10/10) |
| Environment | `python scripts/orchestrator_runner.py doctor` | OK (all 7 Android-side tools FOUND; iOS tooling reported absent) |
| Memory reconciliation | `orchestrator_runner.py findings --target <pkg>` (×4 workspaces) | 10 findings recorded and target-attributed; every re-check `in-sync` |

### 11.3 Data decisions taken by the operator

- **Import approved:** the 10 engagement findings were written into
  `learning_engine/learning_memory.db` with their gate-recomputed states
  (carteira `VALIDATED`, XP Clear `REPORTABLE`, XP Empresas `VALIDATED` +
  `CONFIRMED`, Smartsheet 5 × `OBSERVATION` + 1 × `CONFIRMED`).
- **Cleanup declined:** the legacy demo rows stay; `doctor --strict` still exits 1
  and `prune --orphans --demo --apply` remains available.

### 11.4 Environment correction

The first pass recorded "on the current Linux host `jadx`, `sqlite3`, `mitmproxy`
and `python` are found, while `adb`, `frida` and `apktool` are missing". That is
no longer true: as of 2026-11-11 **all seven** checked tools are present, and a
device is attached. The iOS toolchain (`otool`, `plutil`, `class-dump`,
`codesign`, `idb`, `ios-deploy`) is absent and is now reported by `doctor`.
