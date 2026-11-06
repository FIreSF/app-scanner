# MULTI-AGENT ORCHESTRATION MANUAL (runtime/opencode/ORCHESTRATION.md)

## 1. Architecture Principles
- **Root-Driven Execution:** `orchestrator-agent` is always active and never spawned as a child. It holds the session context and directs all phases.
- **Strict Isolation:** When sub-agents are dispatched, `sessions_spawn` must ALWAYS use `context="isolated"`. Never `fork`. Raw execution logs from sub-agents are discarded after their structured summary is returned to the orchestrator.
- **Concurrency Cap:** Maximum of 3 concurrent sub-agents running at any moment.
- **Wave Sequencing:**
  - **Phase 0:** Intake & Scope Lock (`orchestrator-agent` solo)
  - **Phase 1:** Static analysis + Infrastructure prep in parallel (`static-agent`, `root-device-agent`, `emulator-agent`)
  - **Phase 2:** CVE Intel & Static Crypto (`mcp-bug-intel-agent`, `crypto-analysis-agent`)
  - **Phase 3:** Targeted Frida Script Generation (`frida-script-agent`)
  - **Phase 4:** Device-Bound Exploration in waves (Wave A: `network-traffic-agent`, `storage-analysis-agent`, `dynamic-agent`; Wave B: `resilience-agent`, `ipc-attack-agent`, `webview-agent`)
  - **Phase 5:** Weaponization of high-confidence leads (`exploitation-agent`)
  - **Phase 6:** Adversarial verification (`verification-agent`)
  - **Phase 7:** Coverage check (`compliance-agent`)
  - **Phase 8:** Report assembly (`reporting-agent`)
  - **Phase 9:** Wrap-up and Learning Engine persistence

## 2. Structured Output Contracts
Sub-agents must output concise summaries (under 10 lines) in the standardized format defined in their respective briefing files.
Raw PoCs, traffic captures, and decompiled files must be written directly to `testing/<app-package>/<category>/`.
