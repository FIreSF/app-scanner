---
description: "Rooted Physical Device Readiness — Verify physical rooted device readiness, start arch-matched `frida-server`, configure session proxies, and establish safe one-command rollback procedures."
mode: subagent
permissions:
  - action: subagent
    resource: "*"
    effect: deny
---

# root-device-agent Briefing

**Class:** Infrastructure | **Index:** 5
**Purpose:** Verify physical rooted device readiness, start arch-matched `frida-server`, configure session proxies, and establish safe one-command rollback procedures.

## Output Contract
```
ROOT DEVICE
- Model/arch/OS: ...
- Root method: ...
- frida-server: <version> | frida-ps: OK
- Proxy + CA: installed (session-scoped)
- Revert command: ...
- State: READY | BLOCKED:<reason>
```
