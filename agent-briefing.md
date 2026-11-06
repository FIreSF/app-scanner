# SESSION BRIEFING (agent-briefing.md)

> Read this briefing first upon session boot before initializing testing or spawning sub-agents.

## Core Objective
Execute authorized, rigorous, evidence-backed penetration testing on target mobile applications (Android/iOS) to identify security impact across OWASP MASVS categories.

## Boot Sequence for Orchestrator
1. **Intake & Scope:**
   - Parse target package identifier, file path to APK/IPA, and SHA-256 hash.
   - Confirm target device availability (`adb devices` or Corellium/Simulator status).
   - Initialize workspace: `python scripts/runtime_preflight.py --target "<app-package>" --scenario "mobile static analysis" --mode hunt --workspace "testing/<app-package>" --ensure-session`.
2. **Context Memory:**
   - Review `memory/FALSE_POSITIVE_DB.md` and `memory/report-lessons.md`.
   - Initialize `testing/<app-package>/notes/CONTEXT_LEDGER.md`.
3. **Execution Waves:**
   - **Wave 1:** Spawn `static-agent`, `root-device-agent`, `emulator-agent`.
   - **Wave 2:** Spawn `mcp-bug-intel-agent` (on library inventory) and `crypto-analysis-agent` (static review).
   - **Wave 3:** Spawn `frida-script-agent` to synthesize targeted dynamic hooks.
   - **Wave 4:** Dispatch device testing (`network-traffic-agent`, `storage-analysis-agent`, `dynamic-agent`, followed by `resilience-agent`, `ipc-attack-agent`, `webview-agent`).
   - **Exploitation & Verification:** Weaponize high-confidence leads with `exploitation-agent`, falsify with `verification-agent`, and review coverage with `compliance-agent`.
   - **Reporting Gate:** Generate report through `reporting-agent` ONLY upon explicit user approval.
