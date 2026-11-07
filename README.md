# App Scanner — DEPI Mobile Pentesting Framework (v1.2.0)

> Mobile application security scanner / penetration-testing framework for Android & iOS: static analysis, dynamic instrumentation (Frida), network traffic, crypto, storage, IPC and WebView testing — orchestrated by 16 specialized agents with a hard false-positive gate and MASVS coverage tracking.

A professional multi-agent mobile application penetration testing system (Android / iOS) structured around an authoritative **Orchestrator** and **16 specialized sub-agents** covering static analysis, MCP vulnerability intelligence, dynamic instrumentation, traffic decryption, cryptography, on-device storage, IPC, WebView bridge abuse, MASVS-R resilience, weaponization, and adversarial verification.

The repository is the **constitution + tooling** layer: markdown doctrine that constrains the agents, plus a Python runtime (registry, CLIs, SQLite learning engine) that makes the doctrine executable and checkable.

---

## How to Use the Agent — What It Can Do

### What the agent can do

App Scanner is an **automated mobile security testing assistant** for Android/iOS apps. Given an
authorized target app, it can:

- **Analyze the app statically** — decompile with jadx/apktool, read the manifest, find exported
  components, libraries, hardcoded keys, insecure crypto, and native code risks.
- **Test it dynamically** — run Frida hook scripts (`templates/frida/*.js`) to bypass SSL pinning
  and root detection, log crypto/storage/WebView calls, and watch intents/deep links at runtime.
- **Intercept traffic** — decrypt TLS with mitmproxy, map APIs, and find tokens/PII leaking in transit.
- **Check storage & crypto** — inspect SharedPreferences, SQLite databases, Android Keystore,
  clipboard, backups, weak algorithms, static IVs, and hardcoded keys.
- **Attack IPC & WebView** — test exported activities/services/receivers, intent redirection,
  deep links, content providers, JS bridges, `file://` abuse, and universal XSS.
- **Check resilience** — test root/jailbreak detection, anti-debug, anti-Frida, and obfuscation (MASVS-R).
- **Look up known bugs** — the intel agent matches findings against CVE/bug intel — without touching
  the device or target network.
- **Prove findings are real** — every finding must pass the **7-question Hard FP Gate** and an
  independent adversarial verification before it can be reported. Fake/weak findings are rejected
  automatically.
- **Track MASVS coverage** — maps everything tested against the 23 OWASP MASVS v2.0 controls and
  lists what is still untested.
- **Learn from writeups** — processed writeups feed `memory/` and `skills/` so future runs reuse
  proven techniques and avoid known false positives.
- **Generate a final report** — an OWASP-structured report (see `templates/report/owasp-masvs-report.md`):
  introduction, executive summary, findings with likelihood/impact/risk/remediation, MASVS coverage,
  and appendices. Reports are only written with explicit user approval (`--approve`).

### The agents (who does what)

| Agent | What it does |
|---|---|
| **orchestrator-agent** | The boss. Takes the target, locks the scope, plans the work in waves, and controls the final reporting gate. |
| static-agent | Decompilation, manifest, libraries, native binaries |
| mcp-bug-intel-agent | CVE / vulnerability intel lookup (no device, no network to target) |
| dynamic-agent | Runtime exploration, tracing, class dump |
| frida-script-agent | Generates targeted Frida scripts from static + CVE findings |
| network-traffic-agent | TLS decryption, API mapping, token/PII exposure |
| crypto-analysis-agent | Weak crypto, hardcoded keys, key management |
| storage-analysis-agent | SharedPrefs, databases, Keystore, backups, clipboard |
| ipc-attack-agent | Exported components, intents, deep links, content providers |
| webview-agent | JS bridges, `file://` abuse, universal XSS |
| resilience-agent | Root/jailbreak, anti-debug, anti-Frida, obfuscation (MASVS-R) |
| root-device-agent / emulator-agent | Prepares a rooted device or emulator (frida-server, CA certs) |
| exploitation-agent | Turns high-confidence leads into reproducible PoCs |
| verification-agent | Independent falsifier — tries to prove each finding WRONG |
| compliance-agent | MASVS/MASTG coverage matrix and gap list |
| reporting-agent | Builds the final report from validated findings only (user gated) |

Max 3 sub-agents run at the same time. Sub-agents never make final risk decisions — only the
orchestrator can promote a finding to REPORTABLE.

### How to use it (end-to-end)

**Requirements:** Python 3.9+, plus the mobile tools you need for your scope:
`adb`, `frida` + `frida-tools`, `jadx`, `apktool`, `mitmproxy` — check with `doctor` below.

```bash
# 1. Make sure the repo is healthy and tools are installed
python scripts/orchestrator_runner.py doctor
python scripts/orchestrator_runner.py validate-registry

# 2. Create a scope-locked workspace for ONE authorized target app
python scripts/orchestrator_runner.py bootstrap --target "com.example.targetapp"

# 3. See the agent plan (which agents run, in which waves)
python scripts/orchestrator_runner.py plan
python scripts/orchestrator_runner.py waves

# 4. Run the work (following AGENTS.md rules of engagement):
#    static → intel → frida/dynamic → traffic/crypto/storage/ipc/webview/resilience
#    → exploitation → verification → compliance
#    Findings are written as JSON into testing/<package>/findings/

# 5. Gate each finding (must pass all 7 FP questions + user approval to reach REPORTABLE)
python scripts/orchestrator_runner.py gate --file testing/com.example.targetapp/findings/FIND-0001.json

# 6. Check MASVS coverage and untested gaps
python scripts/orchestrator_runner.py coverage --target "com.example.targetapp"

# 7. Generate the final OWASP-structured report (dry run by default)
python scripts/orchestrator_runner.py report --target "com.example.targetapp"
python scripts/orchestrator_runner.py report --target "com.example.targetapp" --approve
# → testing/com.example.targetapp/reports/final-report.md
```

> **Golden rules (from `AGENTS.md`):** test only apps/accounts you own or are authorized to test;
> never exfiltrate real user data; keep evidence (artifact SHA-256, baseline vs manipulated payload,
> device info, exact commands) for every finding. Full details: `AGENTS.md`, `memory/methodology.md`,
> and the step-by-step commands in §1 below.

---

## 1. Quick Start

All commands are run from the repository root. Python 3.9+ is required; the
runtime and test suite have **no third-party dependencies**.

### 1. Validate the repository

```bash
python scripts/orchestrator_runner.py link-check        # registry + every canonical reference
python scripts/orchestrator_runner.py validate-registry # roster structure and dependency graph only
python scripts/orchestrator_runner.py doctor            # tools, workspace and DB integrity
```

`doctor --strict` exits non-zero on data-integrity warnings (for example a
learning-engine row that is not attached to a session).

### 2. Inspect the execution plan

```bash
python scripts/orchestrator_runner.py plan
python scripts/orchestrator_runner.py waves                      # next dispatchable set
python scripts/orchestrator_runner.py waves --running static-agent,dynamic-agent
python scripts/orchestrator_runner.py waves --phase 4A,4B --next
python scripts/orchestrator_runner.py waves --include-on-demand  # + exploitation/verification/reporting
```

### 3. Bootstrap a scope-locked workspace

```bash
python scripts/orchestrator_runner.py bootstrap --target "com.example.targetapp"
```

This is the only supported way to create `testing/<package>/`. The scope gate
validates the package name, refuses to write outside `testing/`, records the
artifact SHA-256 when an APK is supplied, and scaffolds the session layout.
Exit codes: `0` READY, `1` BLOCKED (scope violation; with `--strict` also
DEGRADED), `2` DEGRADED (missing optional tooling — the workspace is still
created).

Equivalent direct invocation:

```bash
python scripts/runtime_preflight.py --target "com.example.targetapp" \
    --scenario "mobile static analysis" --mode hunt --ensure-session
```

### 4. Resolve skills for an attack surface

```bash
python scripts/skill_registry.py --scenario "webview intent storage crypto"
python scripts/skill_registry.py --validate
```

Unknown scenarios return an explicit no-match instead of silently falling back
to an unrelated skill.

### 5. Run the Hard FP Gate

```bash
python scripts/orchestrator_runner.py gate --file testing/com.example.targetapp/findings/FIND-0001.json
python scripts/orchestrator_runner.py gate --file <finding.json> --save   # also write verification/ gate result
python scripts/orchestrator_runner.py test-gate --title "Insecure Deep Link Intent Redirection" \
    --category "MASVS-PLATFORM" --severity "High" --verified
```

`test-gate` is a **dry-run demo** of a synthetic finding; it never writes to the
learning engine unless you pass `--persist`. `gate` evaluates a real finding file
and returns the achieved state. Promotion to `REPORTABLE` requires all seven gate
answers *and* `user_approved: true`; without approval the finding stops at
`VALIDATED` and the reporting gate stays closed.

### 6. Track the finding lifecycle

```bash
python scripts/orchestrator_runner.py transition --file <finding.json> --to CONFIRMED
python scripts/orchestrator_runner.py transition --file <finding.json> --to VALIDATED --apply
```

Transitions are validated against the state machine in `AGENTS.md` §3; illegal
jumps are rejected. `--apply` persists the new state to the finding file.

### 7. MASVS coverage

```bash
python scripts/orchestrator_runner.py coverage --target "com.example.targetapp"
```

Writes `compliance/masvs-coverage.md` and `compliance/gap-list.md` covering all
23 MASVS v2.0 controls, derived from the artifacts actually present in the
workspace.

### 8. Memory, ledger and writeups

```bash
python scripts/orchestrator_runner.py ledger --target "com.example.targetapp" \
    --agent static-agent --surface manifest --action "dump exported components" \
    --result "3 exported activities" --evidence "static/manifest.json" --record
python scripts/orchestrator_runner.py summary  --target "com.example.targetapp"
python scripts/orchestrator_runner.py fp-db list --json
python scripts/orchestrator_runner.py fp-db check --hash "<sha256 signature>"
python -m learning_engine --help
python scripts/writeup_index.py            # rebuild writeups/index.md
python scripts/writeup_index.py --check    # fail if the index is stale
```

`ledger --record` appends the measured variant to both the SQLite memory and
`notes/tested-variants.md`. Every command that emits structured data accepts
`--json`, including `fp-db`, `mindmap` and `report`.

### 9. Refresh the attack-surface mindmap

```bash
python scripts/orchestrator_runner.py mindmap --target "com.example.targetapp"
python scripts/orchestrator_runner.py mindmap --check   # fail if notes/MINDMAP.md is stale
```

The map is rebuilt from the real evidence directories and `findings/*.json`;
it never claims a surface was tested when no artifact exists.

### 10. Assemble the final report (user gated)

```bash
python scripts/orchestrator_runner.py report --target "com.example.targetapp"          # preview
python scripts/orchestrator_runner.py report --target "com.example.targetapp" --approve  # write
```

Only findings whose declared state **and** recomputed Hard FP Gate evidence
agree at `VALIDATED`/`REPORTABLE` are included. A preview never writes a file;
`--approve` is the explicit user gate and writes `reports/final-report.md` with
the MASVS coverage summary and an exclusion table.

### 11. Run the test suite

```bash
python -m unittest discover -s tests -t .
```

---

## 2. Architecture & Agents

```
USER
 │
 ▼
orchestrator-agent  (ROOT — intake, scope, sequencing, exploitation, validation, reporting gate)
 │
 ├── COLLECTION
 │   ├── static-agent            (decompilation, manifest, native binaries, library inventory)
 │   ├── mcp-bug-intel-agent     (CVE & bug intel lookup via MCP; strictly NO device/network)
 │   ├── dynamic-agent           (runtime exploration, tracing, class dump, IPC)
 │   ├── network-traffic-agent   (TLS decryption, API map, token exposure, PII in transit)
 │   ├── storage-analysis-agent  (shared_prefs, SQLite DBs, keystore, backups, clipboard)
 │   ├── crypto-analysis-agent   (insecure algorithms, static IVs, hardcoded keys, custom crypto)
 │   ├── ipc-attack-agent        (exported components, intent redirection, deep links, content providers)
 │   ├── webview-agent           (JS bridges, file:// scheme abuse, universal XSS)
 │   ├── resilience-agent        (MASVS-R: root/jailbreak, anti-debug, anti-Frida, obfuscation)
 │
 ├── TOOLING
 │   └── frida-script-agent      (targeted Frida script generation from static + CVE findings)
 │
 ├── INFRASTRUCTURE
 │   ├── root-device-agent       (physical rooted device readiness, frida-server, CA certs)
 │   └── emulator-agent          (arch-matched emulator instances, snapshots, rollbacks)
 │
 ├── EXPLOITATION
 │   └── exploitation-agent      (weaponizes HIGH-CONFIDENCE leads into working 2x reproducible PoCs)
 │
 ├── VERIFICATION & COVERAGE
 │   ├── verification-agent      (mandatory adversarial falsifier — independent FP killer)
 │   └── compliance-agent        (MASVS/MASTG coverage matrix & gap analyzer)
 │
 └── REPORTING
     └── reporting-agent         (generates final report from VALIDATED findings only — user gated)
```

The roster itself lives in `runtime/registry.json` and is validated by
`scripts/registry.py`; `AGENTS.md` §2 caps concurrent sub-agents at 3.

---

## 3. Directory Structure

- `AGENTS.md`: Mobile pentesting constitution, rules of engagement, and finding state machine.
- `agent-briefing.md`: Startup briefing loaded at session boot.
- `prioritization.md`: Signal engine priority levels (P1–P4) and circuit breakers.
- `login.md`: Test credentials template for owned accounts.
- `runtime/`:
  - `registry.json`: Authoritative machine-readable agent registry, dependencies, and limits.
  - `opencode/ORCHESTRATION.md`: Multi-agent wave sequencing and isolation manual.
  - `opencode/agents/*.md`: Briefings for all 17 individual agents.
- `scripts/`:
  - `orchestrator_runner.py`: Orchestrator CLI façade (link-check, plan, bootstrap, waves, gate, transition, fp-db, coverage, ledger, summary, doctor).
  - `registry.py`: Registry loader/validator, phase plan, dependency waves, dispatch planner.
  - `runtime_preflight.py`: Scope gate, workspace scaffolding, tool verification.
  - `skill_registry.py`: Scenario-to-skill resolver.
  - `findings.py`: Finding state machine, 7-question Hard FP Gate, FP signature database.
  - `compliance_matrix.py`: MASVS v2.0 coverage matrix and gap list.
  - `writeup_index.py`: Writeup index builder (`writeups/raw` → `writeups/processed` → `writeups/index.md`).
  - `mindmap.py`: Attack-surface mindmap builder (`notes/MINDMAP.md`) from real evidence.
  - `report_builder.py`: Gated final report assembly (`reports/final-report.md`).
- `learning_engine/`:
  - `engine.py`: SQLite-backed engine implementing the 5 lifecycle memory hooks.
  - `schema.sql`: Database schema for sessions, variants, findings, and triage feedback.
  - `cli.py` / `__main__.py`: `python -m learning_engine ...` (session, finding, feedback, prune, doctor).
- `memory/`:
  - `FALSE_POSITIVE_DB.md`: Signature-hash false-positive database.
  - `CONTEXT_LEDGER.md`: Session context ledger template.
  - `report-lessons.md`: Triager quality rules and guidelines.
  - `patterns.md`: Mobile attack patterns and exploit primitives.
  - `methodology.md`: OWASP MASVS / MASTG coverage map.
  - `targets/*.md`: Per-vulnerability category checklists.
- `skills/`: 29 methodology skills resolved by `skill_registry.py` (scenario -> skill), including:
  - `master-bugbounty-rules.md`: Master rules of engagement.
  - `frida-lab-and-runtime.md`: Frida lab setup & runtime bypass playbook (from Medium writeups).
  - `crypto-keymanagement-audit.md`, `android-insecure-randomness.md`, `android-keystore-extraction.md`, `android-biometric-auth-bypass.md`: crypto/auth.
  - `storage-data-at-rest.md`, `android-backup-extraction.md`, `android-sqlite-and-database.md`, `android-clipboard-and-intent-leakage.md`, `ios-keychain-and-storage.md`, `android-screen-and-multitasking-leakage.md`: storage.
  - `ipc-deeplink-exploitation.md`, `android-exported-components.md`, `android-content-provider-traversal.md`, `android-intent-redirection-pendingintent.md`, `ios-url-scheme-pasteboard.md`: IPC/platform.
  - `network-api-security.md`, `android-network-security-config.md`, `ios-ats-and-transport.md`, `mobile-api-backend-testing.md`: network/API.
  - `webview-security-testing.md`, `android-webview-file-access.md`: WebView.
  - `resilience-antitamper.md`, `android-debuggable-and-logging.md`, `ios-jailbreak-and-debug.md`, `android-obfuscation-and-packing.md`: resilience.
  - `flutter-android-security.md`, `adversarial-falsification.md`: Flutter + FP falsification.
- `.agents/skills/learning-engine-integration/SKILL.md`: Learning engine integration standard.
- `templates/frida/`:
  - `ssl_pinning_bypass.js`: Universal Android SSL Pinning bypass.
  - `root_detection_bypass.js`: Root and anti-debug bypass.
  - `intent_monitor.js`: IPC and deep-link hook logger.
  - `crypto_logger.js`: Java cryptographic cipher inspection.
  - `storage_keystore_hook.js`: Keystore / SharedPreferences access logger.
  - `webview_hook.js`: WebView bridge and `loadUrl` instrumentation.
- `writeups/`: `raw/` (untouched source), `processed/` (normalised markdown), generated `index.md`.
- `tests/`: `unittest` suite (registry, gate, preflight, engine, skills, coverage, CLI, assets, writeups).
- `testing/<package>/`: Per-engagement workspace created by `bootstrap` (including `findings/`, `notes/`, `evidence/`, `reports/`).

---

## 4. Status & Limitations

- The Python runtime is covered by an automated test suite; run it before and
  after any change.
- Device-bound work (Frida hook execution, APK static/dynamic analysis, traffic
  interception) is **not** exercised by the test suite: it requires an
  authorized device/emulator and a target artifact. The framework's job is to
  gate and record that work, not to fabricate it.
- `apktool`, `jadx` and `mitmproxy` are optional; when missing, `bootstrap`
  reports `DEGRADED` (exit 2) and the corresponding agents must record the gap
  rather than claim results.
- See `PROJECT_AUDIT.md`, `DEVELOPMENT_PROGRESS.md` and
  `FINAL_PROJECT_REPORT.md` for the audit trail and the exact verified state.
