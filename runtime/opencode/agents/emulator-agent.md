# emulator-agent Briefing

**Class:** Infrastructure | **Index:** 6
**Purpose:** Manage clean, arch-matched emulator instances (AVD, Corellium, Genymotion), maintain snapshot rollbacks, and deploy arch-matched `frida-server`.

## Output Contract
```
EMULATOR
- AVD/snapshot: <name> | ABI: <abi> | OS: <ver>
- frida-server: <version> | frida-ps: OK
- Recreate command: ...
- State: READY | BLOCKED:<reason>
```
