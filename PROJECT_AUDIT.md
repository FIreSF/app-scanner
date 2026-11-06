# PROJECT AUDIT — Mobile-Pentesting Multi-Agent Framework (v1.2.0)

**Audit date:** 2026-10-31
**Auditor role:** Senior engineer / architect / QA
**Repository root:** `Mobile-Agent/` (git repo root: `E:\Depi-project`, single commit `ae29dd5`, working tree untracked)
**Remediation status:** P0 and P1 complete, P2 complete except the destructive DB cleanup (deferred to the operator). See §8.

---

## 1. What this project actually is

This is **not** a web application. It is an **agentic mobile-pentesting framework**: a
documentation-first "constitution" plus a small Python runtime that is supposed to make the
multi-agent workflow executable and auditable.

| Layer | Implementation |
|---|---|
| Agent definitions / prompts | `runtime/opencode/agents/*.md` (17 briefings), `runtime/registry.json` (canonical roster) |
| Constitution / methodology | `AGENTS.md`, `deepseek_markdown_20261031_3cb07b.md`, `skills/*.md`, `memory/*.md` |
| Runtime logic | `scripts/orchestrator_runner.py`, `scripts/registry.py`, `scripts/runtime_preflight.py`, `scripts/skill_registry.py`, `scripts/findings.py`, `scripts/compliance_matrix.py`, `scripts/writeup_index.py`, `scripts/mindmap.py`, `scripts/report_builder.py` |
| Persistence | `learning_engine/` (SQLite: sessions, tested_variants, findings, triage_feedback, lessons_learned) |
| Instrumentation assets | `templates/frida/*.js` (6 scripts) |
| Per-engagement artifacts | `testing/<app-package>/...` (18 sub-directories) |

There is no server, no HTTP API, no frontend, no auth system in the classical sense. The
"backend" is the Python CLI + SQLite memory; the "interface" is the CLI and the agent
briefings. Therefore this audit maps the requested checklist onto the framework's own
equivalent concepts (agent contract = API, registry = schema, workspace = storage).

---

## 2. Verified inventory (what exists and works)

| Component | Files | Verified behaviour |
|---|---|---|
| Agent roster | 17 briefings + registry entries, indices 0–16 | Consistent ids/indexes; `link-check` resolves all briefings |
| Constitution | `AGENTS.md` (v1.2.0), spec md (906 lines) | Consistent concurrency cap (3), finding states, FP gate |
| Skills library | 8 files in `skills/` + `.agents/skills/learning-engine-integration/SKILL.md` | Substantive methodology content, no placeholders |
| Memory templates | `memory/*.md`, `memory/targets/*.md` (7 classes) | Present; FP DB has 17 structured signatures |
| Frida templates | 6 `.js` files | `node --check` parses all 6 (runtime execution untested — no device) |
| Learning engine | `engine.py`, `schema.sql`, `cli.py`, `__main__.py` | Hooks execute; FK enforcement; connections closed; `python -m learning_engine` works |
| CLI | 9 modules | 15 orchestrator subcommands + 5 standalone CLIs, all exercised by tests |
| Workspace scaffolder | `runtime_preflight.py` | Scope gate + 18 sub-dirs + notes/evidence skeleton + artifact hash |
| Tests | 11 modules + support, 161 tests | `python -m unittest discover -s tests -t .` → OK |

---

## 3. Feature status matrix

Legend: **COMPLETE** · **PARTIALLY COMPLETE** · **INCOMPLETE** · **NOT IMPLEMENTED** · **NEEDS IMPROVEMENT** · **BROKEN**
Status column is **post-remediation**; the "as found" evidence is preserved in §4.

| # | Feature | As found | Post-fix | Evidence / remaining gap |
|---|---|---|---|---|
| 1 | Agent roster & briefings | COMPLETE | COMPLETE | 17/17 briefings, registry indices unique and contiguous |
| 2 | Constitution / methodology docs | COMPLETE | COMPLETE | `AGENTS.md`, spec, skills, memory are substantive |
| 3 | Registry as authoritative schema | PARTIALLY COMPLETE | COMPLETE | `validate_registry()` checks required fields, id/key match, contiguous unique indexes, dependency existence + self-deps + cycles, concurrency bounds, skill/briefing existence, phase coverage, single root; wired into `link-check` |
| 4 | Canonical skill references resolve | BROKEN | COMPLETE | `.agents/skills/learning-engine-integration/SKILL.md` created; `link-check` now FAILs on missing refs |
| 5 | Orchestrator CLI argument handling | BROKEN | COMPLETE | Common options use `argparse.SUPPRESS` parents → `--target`/`--workspace`/`--json` accepted before **or** after the subcommand |
| 6 | Orchestrator bootstrap command | BROKEN | COMPLETE | Full tool report, session, artifact hash, status; exit codes now match `runtime_preflight.py` (0 READY / 1 BLOCKED / 2 DEGRADED) |
| 7 | Hard FP Gate | PARTIALLY COMPLETE | COMPLETE | 7 checks + `user_approved` reporting gate; `--verified` is explicitly DEMO and cannot yield `REPORTABLE`; verdict/state separation |
| 8 | Finding state machine | NOT IMPLEMENTED | COMPLETE | `scripts/findings.py` enforces legal transitions; `transition` CLI validates and optionally applies; illegal jumps exit non-zero |
| 9 | FP database integration | PARTIALLY COMPLETE | COMPLETE | Structured parser (17 rows), exact-hash matching, `fp-db list/check/add`; substring false positives eliminated |
| 10 | Learning-engine persistence integrity | BROKEN | COMPLETE | `test-gate` no longer persists; `--persist` is explicit; FK enforcement enabled (`PRAGMA foreign_keys=ON`) |
| 11 | Learning-engine resource handling | NEEDS IMPROVEMENT | COMPLETE | Connections closed via context manager; `end_session`, finding/variant queries, `cli.py`, `__main__.py`, `prune` |
| 12 | Runtime preflight / scope gate | INCOMPLETE | COMPLETE | Target regex, workspace containment, artifact existence + SHA-256 pinning, required tools, READY/DEGRADED/BLOCKED, exit codes |
| 13 | Wave planning / dependency enforcement | NOT IMPLEMENTED | COMPLETE | `scripts/registry.py` dependency waves + `next_dispatchable()` honouring the concurrency ceiling and on-demand exclusions; `waves` CLI |
| 14 | Skill resolver coverage | PARTIALLY COMPLETE | COMPLETE | 17 scenarios + aliases + explicit no-match + `--list`/`--validate`; unknown scenario no longer falls back silently |
| 15 | Compliance / MASVS coverage matrix | NOT IMPLEMENTED | COMPLETE | `compliance_matrix.py`: 23 MASVS v2.0 controls, artifact-derived status, `compliance/masvs-coverage.md` + `compliance/gap-list.md` |
| 16 | Context ledger tooling | PARTIALLY COMPLETE | COMPLETE | `ledger` CLI appends to `notes/CONTEXT_LEDGER.md`; `tested-variants.md` initialized |
| 17 | Workspace evidence scaffold | PARTIALLY COMPLETE | COMPLETE | Adds `notes/tested-variants.md`, `notes/auth_session.md`, `evidence/artifact.json` |
| 18 | Tests | NOT IMPLEMENTED | COMPLETE | 161 `unittest` tests, no third-party deps, temp DBs/workspaces; clean under `-W error::ResourceWarning` |
| 19 | Docs accuracy | PARTIALLY COMPLETE | COMPLETE | README rewritten against verified commands; `DEVELOPMENT_PROGRESS.md`, `FINAL_PROJECT_REPORT.md` added |
| 20 | Writeup ingestion pipeline (`/update`) | NOT IMPLEMENTED | COMPLETE | `writeups/{raw,processed}` scaffold, `writeups/README.md`, `scripts/writeup_index.py` (+ `--check`, `--json`), generated `writeups/index.md` |
| 21 | Secrets hygiene | COMPLETE | COMPLETE | `login.md` uses `example.com` placeholders only; no keys in repo |
| 22 | Cross-platform (Windows) support | NEEDS IMPROVEMENT | PARTIALLY COMPLETE | Paths are `os.path`-safe, JSON reads use `utf-8-sig`, generated files use LF; docs are now shell-neutral. Remaining: non-ASCII box/em-dash output can render as `?` under legacy Windows console code pages (cosmetic only) |
| 23 | Attack-surface MINDMAP generation | PARTIALLY COMPLETE (static skeleton only) | COMPLETE | `scripts/mindmap.py` derives groups, evidence counts and findings from real workspace artifacts; `mindmap --check` detects staleness |
| 24 | Final report assembly (user gated) | NOT IMPLEMENTED | COMPLETE | `scripts/report_builder.py` recomputes the FP gate, includes only evidence-supported VALIDATED/REPORTABLE findings, and writes only with `--approve` |
| 25 | Machine-readable output on every command | PARTIALLY COMPLETE | COMPLETE | `--json` added to `fp-db`, `hash`, learning-engine `init/end/stats/prune`, `mindmap`, `report`; transition JSON is a single document |

---

## 4. Bugs found (reproduced) and resolution

| # | Bug (as found) | Resolution |
|---|---|---|
| 1 | **`bootstrap` unusable** — `python scripts/orchestrator_runner.py bootstrap --target com.x` → argparse exit 2 | Fixed via SUPPRESS-default common parents; regression test `test_bootstrap_accepts_target_after_subcommand` |
| 2 | **Fabricated finding persisted** — `test-gate --verified` inserted `state=REPORTABLE, verified=1` into the production DB | `test-gate` is dry-run; `--persist` explicit and labelled; test `test_test_gate_does_not_persist_by_default` |
| 3 | **Fabricated verification** — `--verified` set `verification_verdict=CONFIRMED_VALIDATED` with no verification run | Demo verdict is `DEMO_CONFIRMED_VALIDATED`, which the gate rejects; `REPORTABLE` requires all 7 checks + `user_approved` |
| 4 | **Broken canonical reference** — `.agents/skills/learning-engine-integration/SKILL.md` missing while three docs + registry required it | File created; `link-check` covers it and fails on absence |
| 5 | **Silent scope bypass** — preflight accepted `not a package!!` and any path, always `READY` | Scope gate: package regex, workspace containment, artifact checks; `test_bootstrap_invalid_target_exits_one` |
| 6 | **Silent resolver fallback** — unknown scenario returned `static` | Explicit no-match + `--validate`; tests assert no silent fallback |
| 7 | **FK integrity** — `triage_feedback` could reference non-existent findings | `PRAGMA foreign_keys=ON` on every connection; `after_triage` validates the finding first |
| 8 | **Connection leak** — engine connections never closed | Context-managed connections; suite runs clean under `-W error::ResourceWarning` |
| 9 | **`check_tools()` result dropped** in `bootstrap` (dead assignment) | Bootstrap renders the full tool table and status |
| 10 | **Substring FP match** — `check_fp_database("abc")` matched prose/other hashes | Structured exact-hash matching over parsed rows |
| 11 | **Exit-code divergence** — `bootstrap` returned 0 while reporting `DEGRADED`, contradicting the documented 0/1/2 contract | Runner now mirrors preflight (`2` DEGRADED, `1` with `--strict`); test `test_bootstrap_exit_code_matches_preflight_contract` |
| 12 | **Stale demo rows** — 2 findings (`FIND-37243040`, `FIND-DEDBCC04`) + 1 `triage_feedback` orphaned in `learning_engine/learning_memory.db` | Non-destructive `python -m learning_engine prune --orphans --demo` (dry-run); `doctor --strict` reports them. **Not executed** — destructive, awaiting operator approval |
| 13 | **Documented engine invocation broken** — `python learning_engine/engine.py stats` → `ModuleNotFoundError: No module named 'learning_engine'` (the `from cli import main` fallback imported a module that itself needed the package root) | `__main__` block now puts the repository root on `sys.path` when run as a plain script; tests cover both `engine.py` and `python -m learning_engine` |

---

## 5. Security & data-integrity concerns

| Severity | Concern (as found) | Status |
|---|---|---|
| High (data integrity) | Demo commands wrote fabricated `REPORTABLE` findings into the persistent memory DB used by reporting. | Fixed — dry-run default, explicit `--persist`, demo verdict rejected by gate |
| Medium | FP DB matching was substring-based → known-FP hashes in prose could suppress real findings. | Fixed — exact-hash matching |
| Medium | Preflight did not verify artifact hash or target identity → evidence could be misattributed. | Fixed — optional artifact + `--expect-sha256` pinning, SHA-256 recorded in `evidence/artifact.json` |
| Low | Workspace path was user-controlled and could point outside `testing/`. | Fixed — containment check; escape requires explicit `--allow-external-workspace` |
| Low | No validation that `tools_allowed` / `skills` in registry exist. | Fixed — `validate_registry()` checks skill/briefing paths |
| Low | Legacy demo rows remain in the shipped DB. | Open — `doctor` warns; `prune` command available but not run (destructive) |

---

## 6. Prioritized roadmap

### P0 — Critical (correctness / data integrity)
1. ✅ Fix `orchestrator_runner` argument parsing (order-independent common options).
2. ✅ Remove fabricated persistence: gate/test-gate dry-run by default; explicit `--persist`; demo verdicts labelled `DEMO`.
3. ✅ Create the missing canonical skill `.agents/skills/learning-engine-integration/SKILL.md`.
4. ✅ Full registry validation, wired into `link-check`.
5. ✅ Real scope gate in `runtime_preflight.py` (target format, containment, artifact hash, tools, READY/DEGRADED/BLOCKED, exit codes).

### P1 — High (core unfinished features)
6. ✅ Dependency-aware wave planning + concurrency accounting (`waves`).
7. ✅ Finding state machine with guarded transitions and the reporting gate.
8. ✅ Structured FP DB parsing/lookup/append; substring matching removed.
9. ✅ MASVS coverage matrix + gap-list generation.
10. ✅ Skill resolver completed (17 scenarios, aliases, no-match, `--list`, `--validate`).
11. ✅ Learning engine hardened (connection lifecycle, FK, session end, queries, CLI).
12. ✅ Ledger append tooling + `tested-variants.md` / `auth_session.md` initialization.

### P2 — Medium (quality, tests, docs)
13. ✅ `unittest` suite across registry, gate, state machine, preflight, resolver, engine, coverage, CLI, assets, writeups.
14. ✅ README rewritten; `DEVELOPMENT_PROGRESS.md` + `FINAL_PROJECT_REPORT.md` added.
15. ✅ Writeup index pipeline (`writeups/` scaffold + `scripts/writeup_index.py`).
16. ⏸ Demo-row cleanup — command implemented and documented; **execution deferred** to the operator (destructive).

### P3 — Low
17. ✅ Evidence-derived MINDMAP generation (`scripts/mindmap.py`, `mindmap --check`).
18. ✅ `--json` on the remaining CLIs and a valid single-document JSON transition apply.
19. ✅ User-gated final report assembly with evidence/state reconciliation (`scripts/report_builder.py`).

---

## 7. Recommended implementation sequence

```
P0.1 argparse  ─┬─► P0.2 dry-run gate ──► P1.7 state machine
P0.3 skill     ─┤
P0.4 registry  ─┼─► P1.6 waves ──► P1.9 coverage
P0.5 preflight ─┘
P1.8 FP DB ──► P1.7 gate correctness
P1.10 resolver ─► P1.11 engine ─► P1.12 ledger
        └────────► P2.13 tests after each step
```

**Definition of done for this pass:** all P0/P1 items implemented, full test suite green,
`link-check` validates every canonical reference, docs updated, demo commands no longer
mutate state, and remaining device-dependent work documented as a limitation.

---

## 8. Remediation verification (2026-10-31)

| Check | Command | Result |
|---|---|---|
| Full test suite | `python -m unittest discover -s tests -t .` | **161 tests OK** |
| Resource warnings | same, `-W error::ResourceWarning` | **clean** |
| Link/reference integrity | `python scripts/orchestrator_runner.py link-check` | **PASS, 93 references** |
| Registry only | `python scripts/orchestrator_runner.py validate-registry` | **PASS** |
| Skill mapping | `python scripts/skill_registry.py --validate` | **17/17 scenarios mapped** |
| Environment | `python scripts/orchestrator_runner.py doctor` | OK (adb/frida/sqlite3/python found; apktool/jadx/mitmproxy missing) |
| Writeup index freshness | `python scripts/writeup_index.py --check` | up to date |
| Bootstrap contract | `bootstrap` on a temp workspace | DEGRADED → exit 2, workspace created |
| Scope rejection | `bootstrap --target "not a package!!"` | BLOCKED → exit 1 |

**Not verified (no device/APK in scope):** execution of the six Frida templates against a
running app, real APK decompilation/inventory, traffic interception with mitmproxy, and any
end-to-end exploitation chain. These are recorded as limitations in
`FINAL_PROJECT_REPORT.md` rather than claimed as working.
