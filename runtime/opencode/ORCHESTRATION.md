# MULTI-AGENT ORCHESTRATION MANUAL (runtime/opencode/ORCHESTRATION.md)

## 0. How the roster becomes executable
- **Source of truth:** `runtime/registry.json` (roster, dependencies, limits) plus the
  briefings in `runtime/opencode/agents/*.md`. Nothing else defines an agent.
- **Materialization:** `python scripts/sync_agent_runtime.py` generates the files an
  OpenCode runtime actually loads:
  - `.opencode/agents/<agent-id>.md` — description, `mode`, and permission rules;
  - `.opencode/opencode.json` — the skills directory and the `bug-intel` MCP server.
  The script derives every field from the registry, so an agent cannot exist in one
  place and not the other.
- **Drift control:** `python scripts/sync_agent_runtime.py --check` writes nothing and
  exits non-zero when the generated files no longer match the registry (CI runs it).
- **Dispatch:** launch an agent by id with the harness `subagent` tool
  (for example `static-agent`, `verification-agent`). OpenCode sub-agents always start
  in a fresh, isolated child session — there is no "fork the parent context" mode —
  which is exactly what the Strict Isolation rule below requires.
- **Permission encoding:** the generated files enforce two constitutional rules in
  code rather than prose: every sub-agent carries `subagent: deny` (no sub-agent can
  spawn another, AGENTS.md §2.6), and `orchestrator-agent` carries an explicit
  allow-list of exactly the registered roster followed by a blanket deny
  (AGENTS.md §1).
- **CVE intelligence:** `mcp-bug-intel-agent` reads its tools from the `bug-intel` MCP
  server declared in `.opencode/opencode.json` (`scripts/mcp_intel_server.py`).
  It must never be given device or target-network access.

## 1. Architecture Principles
- **Root-Driven Execution:** `orchestrator-agent` is always active and never spawned as a child. It holds the session context and directs all phases.
- **Strict Isolation:** Sub-agents are dispatched through the harness `subagent` tool and each runs in its own isolated child session with fresh context; never hand a sub-agent the parent session context. Raw execution logs from sub-agents are discarded after their structured summary is returned to the orchestrator.
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

## 3. Dispatch Checklist (per engagement)
1. `python scripts/sync_agent_runtime.py --check` — the loaded roster matches the registry.
2. `python scripts/orchestrator_runner.py waves --next` — take only the dispatchable set.
3. Launch at most 3 sub-agents, never two that touch the same package component,
   endpoint, or database file.
4. Collect the structured summary, then record the work:
   `orchestrator_runner.py ledger ... --record`.
5. Only `orchestrator-agent` promotes findings, and only through the Hard FP Gate.
