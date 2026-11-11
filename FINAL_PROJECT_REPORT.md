# FINAL PROJECT REPORT

**Project:** Mobile-Pentesting Multi-Agent Framework (v1.2.0)
**Report date:** 2026-10-31
**Scope:** repository audit, defect remediation, missing-feature implementation, test coverage, documentation
**Outcome:** Delivered. All P0/P1 items, all non-destructive P2 items and the P3 quality items are complete and verified. One destructive cleanup and all device-bound verification remain with the operator.

---

## 1. Executive summary

The repository is a documentation-first multi-agent mobile-pentesting framework with a small
Python runtime. Before this pass it was **described** well but **not executable**: the main CLI
was unusable in its documented form, the false-positive gate fabricated evidence and wrote it
to the production database, the registry was never validated, and major documented features
(wave planning, finding state machine, FP database integration, MASVS coverage, writeup
pipeline) did not exist.

After this pass:

- the documented commands work as written, and fail with meaningful exit codes when they should;
- no command can fabricate a `REPORTABLE` finding;
- every canonical reference is validated mechanically (`link-check` → PASS, 93 references);
- the roster, dependency waves and 3-agent concurrency ceiling are enforced in code;
- the finding lifecycle, FP signature database, MASVS coverage matrix, ledger and writeup index
  are implemented and tested;
- the attack-surface MINDMAP is derived from real evidence, and report assembly is user-gated
  and reconciles declared states against the FP gate;
- **161 automated tests pass** with no third-party dependencies.

Everything that requires a real device, APK or network path is explicitly listed as
unverified in §6 rather than claimed as working.

---

## 2. What was delivered

### 2.1 Working orchestrator CLI

```bash
python scripts/orchestrator_runner.py link-check          # all canonical references
python scripts/orchestrator_runner.py validate-registry   # roster structure + graph
python scripts/orchestrator_runner.py plan                # phases, tooling, session
python scripts/orchestrator_runner.py doctor [--strict]   # tools + DB integrity
python scripts/orchestrator_runner.py bootstrap --target com.example.app
python scripts/orchestrator_runner.py waves [--running ...] [--phase 4A] [--next]
python scripts/orchestrator_runner.py gate --file <finding.json> [--save]
python scripts/orchestrator_runner.py test-gate ...       # DEMO, dry-run
python scripts/orchestrator_runner.py transition --file <f> --to CONFIRMED [--apply]
python scripts/orchestrator_runner.py fp-db list|check|add
python scripts/orchestrator_runner.py coverage --target com.example.app
python scripts/orchestrator_runner.py ledger --agent ... --surface ... --action ... --result ...
python scripts/orchestrator_runner.py summary --target com.example.app
python scripts/orchestrator_runner.py mindmap --target com.example.app [--check]
python scripts/orchestrator_runner.py report --target com.example.app [--approve]
```

Global options (`--target`, `--workspace`, `--json`) work **before or after** the subcommand.

### 2.2 Enforced safety model

| Control | Behaviour |
|---|---|
| Scope lock | `bootstrap` rejects invalid package ids (exit 1) and writes only inside `testing/` unless `--allow-external-workspace` is explicit |
| Artifact integrity | Optional `--artifact` + `--expect-sha256`; SHA-256 recorded in `evidence/artifact.json`; mismatch blocks |
| Tool readiness | `READY` / `DEGRADED` / `BLOCKED` with exit codes `0` / `2` / `1` (DEGRADED becomes `1` under `--strict`), identical from both entry points |
| FP gate | Seven questions must pass; `REPORTABLE` additionally requires `user_approved: true` |
| Demo isolation | `test-gate` is dry-run; `--persist` is explicit; its verdict `DEMO_CONFIRMED_VALIDATED` is rejected by the real gate |
| State machine | Illegal lifecycle jumps are rejected; `--apply` is required to persist |
| Concurrency | Dispatch planner never returns more agents than the registry's `concurrency_limit` (3) minus running agents |

### 2.3 New modules

| Module | Lines | Responsibility |
|---|---|---|
| `scripts/registry.py` | 471 | registry load/validate, phases, dependency waves, dispatch planning, link-check |
| `scripts/findings.py` | 479 | FP DB parsing, 7-question gate, reporting gate, state machine, CLI |
| `scripts/compliance_matrix.py` | 414 | MASVS v2.0 (23 controls) coverage matrix + gap list |
| `scripts/writeup_index.py` | 155 | `/update` pipeline index builder with `--check` / `--json` |
| `scripts/mindmap.py` | 414 | evidence-derived attack-surface MINDMAP with staleness check |
| `scripts/report_builder.py` | 368 | gated final report with state/evidence reconciliation and coverage embed |
| `learning_engine/cli.py` + `__main__.py` | 190 | `python -m learning_engine` (init/summary/end/findings/sessions/stats/prune) |
| `tests/` (11 modules + support) | 1 600 | full `unittest` suite |

### 2.4 Documentation

- `README.md` — rewritten and verified against real command output.
- `PROJECT_AUDIT.md` — as-found record + post-fix status + resolution log.
- `DEVELOPMENT_PROGRESS.md` — phase-by-phase work log and decisions.
- `FINAL_PROJECT_REPORT.md` — this document.
- `writeups/README.md` — ingestion rules for source material.

---

## 3. Defects fixed

| # | Defect | Fix |
|---|---|---|
| 1 | `bootstrap --target X` crashed argparse | SUPPRESS-default common parents |
| 2 | `test-gate --verified` persisted a fabricated `REPORTABLE` finding | dry-run default, explicit `--persist`, demo verdict rejected |
| 3 | `--verified` faked `CONFIRMED_VALIDATED` | distinct `DEMO_` verdict; real gate unaffected |
| 4 | Required skill file missing while `link-check` passed | file created; link-check now fails on missing refs |
| 5 | Invalid targets and external paths accepted, always `READY` | target regex, containment, artifact checks, real statuses |
| 6 | Unknown skill scenario silently resolved to `static` | explicit no-match + `--validate` |
| 7 | Foreign keys never enforced | `PRAGMA foreign_keys=ON` + validation before insert |
| 8 | SQLite connections leaked | context-managed connections (clean under `-W error::ResourceWarning`) |
| 9 | `check_tools()` result discarded in bootstrap | full tool table + status rendered |
| 10 | FP matching by substring | exact-hash matching over 17 structured rows |
| 11 | Bootstrap exit code contradicted the documented contract | aligned to preflight (0/1/2) with regression tests |
| 12 | Stale demo rows in the shipped DB | `prune` implemented; execution deferred (destructive) |
| 13 | `python learning_engine/engine.py` crashed with `ModuleNotFoundError` despite being documented | plain-script bootstrap adds the repo root to `sys.path`; both entry points tested |

---

## 4. Verification evidence

Environment: Linux (WSL2), Python 3.14.7 (the original audit pass ran on Windows 11 with Python 3.14.4).

| Check | Command | Result |
|---|---|---|
| Full suite | `python -m unittest discover -s tests -t .` | **161 tests, OK** (~3.6 s) |
| Resource warnings | `python -W error::ResourceWarning -m unittest discover -s tests -t .` | OK |
| Canonical references | `python scripts/orchestrator_runner.py link-check` | **PASS — 93 references** |
| Registry only | `python scripts/orchestrator_runner.py validate-registry` | PASS |
| Skill mapping | `python scripts/skill_registry.py --validate` | 17/17 scenarios mapped |
| Diagnostics | `python scripts/orchestrator_runner.py doctor` | OK; `--strict` exits 1 on the known legacy rows |
| Writeup index | `python scripts/writeup_index.py --check` | up to date |
| Bootstrap contract | temp workspace, real tools | `DEGRADED` → exit 2, workspace fully scaffolded |
| Scope rejection | `--target "not a package!!"` | `BLOCKED` → exit 1 |
| Gate safety | `gate` on a fully-populated finding without `user_approved` | `VALIDATED`, reporting gate **CLOSED** |

Test distribution: registry 21 · findings 31 · preflight 14 · learning engine 16 · skills 11 ·
compliance 7 · orchestrator CLI 26 · assets 7 · writeups 12 · mindmap 7 · report 9.

---

## 5. Repository state

- Git root is `E:\Depi-project` (history: `ae29dd5`, `8855289`, `be39e80`), later commits added the MASTG/MobSF skills and the writeup ingestion work. The 2026-11-11 pass (§9) was committed separately from the Linux checkout at `Depi-project/Depi-project-main/Mobile-Agent`; it contains the runtime wiring, the intel server, the tests, the CI workflow and the corrected documentation described there.
- No new third-party dependencies; the runtime and tests use the standard library only.
- No secrets added; `login.md` still contains only `example.com` placeholders.
- Generated artifacts (`writeups/index.md`, `compliance/*.md`) are reproducible from scripts and documented as generated.

---

## 6. Limitations and unverified work

These are **not** claims of failure; they are work this pass could not honestly verify.

1. **No device / emulator / APK was in scope.** The six Frida templates (`templates/frida/*.js`)
   parse with `node --check`, but were not injected into a running process. Real SSL-pinning
   bypass, root-detection bypass, keystore hooks and WebView hooks are unverified.
2. **Static analysis tools absent on this host.** `apktool`, `jadx` and `mitmproxy` are
   `NOT_FOUND`, so `bootstrap` correctly reports `DEGRADED` (exit 2). No decompilation,
   library inventory or traffic capture was performed.
   *(Superseded 2026-11-11: all three tools are now installed, and decompilation has since
   been performed for four targets — `testing/<package>/static/` holds the jadx/apktool
   output. Traffic capture with mitmproxy still has not been executed.)*
3. **No end-to-end exploitation chain** was executed. The gate, state machine and evidence
   scaffolding are tested with synthetic inputs; they gate real work but do not perform it.
4. **Legacy demo rows remain** in `learning_engine/learning_memory.db`:
   2 findings (`FIND-37243040`, `FIND-DEDBCC04`) and 1 `triage_feedback` row are orphaned.
   `doctor` warns; `doctor --strict` exits 1. The non-destructive dry run is:

   ```bash
   python -m learning_engine prune --orphans --demo
   ```

   Deletion requires explicit operator approval (`--apply`). It was deliberately not run.
   *(2026-11-11: the operator reviewed the dry run and chose to keep the rows. The 10
   engagement findings were imported into the same database, target-attributed and with
   their gate-recomputed states.)*
5. **Windows console rendering.** Under legacy code pages, non-ASCII separators in some CLI
   output can appear as `?`. This is cosmetic; piping to a UTF-8 file or setting the console to
   UTF-8 resolves it.
6. **New P3 tooling is host-independent but not device-tested.** `mindmap.py` and
   `report_builder.py` operate on workspace artifacts; they were verified with synthetic
   evidence trees, not with a live engagement.

---

## 7. How to use the framework now

```bash
# 1. verify the repository
python scripts/orchestrator_runner.py link-check
python -m unittest discover -s tests -t .

# 2. open an engagement (creates testing/<pkg>/ only)
python scripts/orchestrator_runner.py bootstrap --target com.example.app --artifact ./app.apk

# 3. drive the waves
python scripts/orchestrator_runner.py waves --next
python scripts/orchestrator_runner.py waves --completed static-agent --next

# 4. record work as it happens
python scripts/orchestrator_runner.py ledger --agent static-agent --surface manifest \
    --action "enumerate exported components" --result "3 exported activities" \
    --evidence static/manifest.json --record

# 5. gate a finding, then transition it
python scripts/orchestrator_runner.py gate --file testing/com.example.app/findings/FIND-0001.json
python scripts/orchestrator_runner.py transition --file testing/com.example.app/findings/FIND-0001.json \
    --to CONFIRMED --apply

# 6. coverage, mindmap and gated report
python scripts/orchestrator_runner.py coverage --target com.example.app
python scripts/orchestrator_runner.py mindmap --target com.example.app
python scripts/orchestrator_runner.py report --target com.example.app          # preview
python scripts/orchestrator_runner.py report --target com.example.app --approve
python scripts/orchestrator_runner.py summary --target com.example.app
python scripts/writeup_index.py
```

---

## 8. Recommended next steps

*(Superseded by §9.5. As of 2026-11-11 the optional tooling is installed, the legacy-row
cleanup was reviewed and declined by the operator, and the first real engagements exist.)*

1. **Review and push** the commit created by this pass (local commit exists; the HTTPS
   remote needs credentials to push).
2. **Approve or reject** the legacy-row cleanup: dry-run
   `python -m learning_engine prune --orphans --demo`, then `--apply` if acceptable.
3. **Install optional tooling** (`apktool`, `jadx`, `mitmproxy`) and re-run
   `bootstrap --strict` to reach `READY`.
4. **Run a first real engagement** on an authorized app with an owned device; the framework
   will now record scope, hashes, ledger entries, coverage and gate decisions as you go.
5. **Extend tests** with device-bound integration checks once a lab device is available.

---

## 9. Second delivery — runtime wiring, intel, CI (2026-11-11)

### 9.1 Executive summary

The first pass fixed the runtime. This pass fixed the *framework*: the roster became
agents an agent runtime can actually dispatch, the CVE agent received a real intelligence
source, the learning engine stopped losing and cross-clobbering findings, the iOS gap
became visible in diagnostics, and CI started enforcing the invariants. It also corrected
the documentation, which had drifted into claiming a host without `adb`, `frida` or
`apktool` and a repository with a single commit.

Everything that requires real exploitation work is still listed as open in §9.4 rather
than claimed as done.

### 9.2 Delivered

| Item | Where | What it changes |
|---|---|---|
| Agent materialization | `scripts/sync_agent_runtime.py` → `.opencode/agents/*.md`, `.opencode/opencode.json` | The 17 registry agents become loadable, dispatchable agents; `--check` detects drift and runs in CI |
| Constitution as permissions | generated agent frontmatter | Sub-agents cannot spawn sub-agents; only `orchestrator-agent` may launch the registered roster |
| Skill discoverability | `skills/*.md` frontmatter + `opencode.json` | All 29 methodology skills are advertised to the model by description |
| CVE/bug intelligence | `scripts/mcp_intel_server.py` (stdio MCP) | `mcp-bug-intel-agent` gains NVD, OSV, CISA KEV and an offline FP-DB check; verified live |
| Memory reconciliation | `orchestrator_runner.py findings [--apply]` | Workspace findings reach the learning engine with gate-recomputed states; the workspace id is preserved |
| Per-target finding identity | `learning_engine/engine.py` | `FIND-0001` from two engagements no longer overwrite each other (`<target>#<id>`) |
| iOS diagnostics | `doctor` | Optional Apple toolchain reported; gaps must be recorded, not claimed as coverage |
| Device-bound tests | `tests/test_lab_integration.py` | Opt-in (`MOBILE_AGENT_LAB=1`) checks against the real toolchain and device — now passing |
| CI + metadata | `.github/workflows/ci.yml`, `pyproject.toml` | Every push runs the suite, link/registry/skill/writeup validation and the drift check |
| Generated artifacts | `testing/*/compliance/`, `testing/*/notes/MINDMAP.md` | MASVS coverage for all five workspaces; every `mindmap --check` green |
| Documentation | README + the three audit documents | Stale tool/commit/host claims corrected; this pass documented |

### 9.3 Verification evidence (2026-11-11)

Environment: Linux WSL2, Python 3.14.7, OpenCode v2.2.7, frida 17.25.2, device
`127.0.0.1:21513` attached.

| Check | Command | Result |
|---|---|---|
| Full suite | `python -m unittest discover -s tests -t .` | **234 tests OK** (5 skipped — the opt-in lab suite) |
| Device-bound suite | `MOBILE_AGENT_LAB=1 python -m unittest tests.test_lab_integration` | **5 OK** |
| Resource warnings | `python -W error::ResourceWarning -m unittest discover -s tests -t .` | OK |
| Canonical references | `python scripts/orchestrator_runner.py link-check` | **PASS — 94 references** |
| Registry | `python scripts/orchestrator_runner.py validate-registry` | PASS |
| Agent runtime drift | `python scripts/sync_agent_runtime.py --check` | in sync (18 managed files) |
| Loaded roster | runtime agent/skill list | 24 agents (7 built-in + 17 project), 32 skills advertised |
| Skill mapping | `python scripts/skill_registry.py --validate` | 17/17 mapped |
| Writeup index | `python scripts/writeup_index.py --check` | up to date |
| MCP server | `python scripts/mcp_intel_server.py --self-test` | PASS (10/10); server connected, 4 tools returning live NVD/OSV/KEV data |
| Environment | `python scripts/orchestrator_runner.py doctor` | OK — 7/7 Android tools FOUND, iOS tooling reported absent |
| Memory reconciliation | `orchestrator_runner.py findings --target <pkg>` × 4 | 10 findings recorded and target-attributed; every re-check `in-sync` |

### 9.4 Still open

1. **Live exploitation work** is incomplete: `frida/`, `traffic/`, `crypto/`, `webview/`
   are empty for 3–4 targets, `MASVS-RESILIENCE-*` is 0 tested on every target, and
   Smartsheet has no verification or exploitation artifacts (its `report` preview
   includes 0 and excludes 6).
2. **iOS** has no target, no host toolchain and no coverage; `doctor` now says so
   explicitly instead of staying silent.
3. **Legacy demo rows** remain in the shipped database at the operator's decision;
   `doctor --strict` exits 1 until they are pruned.
4. **No linter or type-checker** is installed on the host, so none is configured; CI
   enforces the suite, the reference graph, the registry, the skill map, the writeup
   index and the agent-drift check instead.

### 9.5 Recommended next steps

1. Work the resilience and traffic gaps on the existing four engagements — those are
   the two MASVS groups that are effectively untouched.
2. Push the commits (the HTTPS remote still needs credentials).
3. Install the iOS toolchain on a macOS host if an iOS scope is ever in play.
4. Keep `sync_agent_runtime.py --check` and `link-check` in any pre-commit hook; they
   are the two cheapest guards against silent drift.
