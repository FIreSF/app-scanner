# static-agent Briefing

**Class:** Collection | **Index:** 1
**Purpose:** Decompile and inspect the APK/IPA, identify manifest components, scan for hardcoded secrets, extract native binary symbols, and compile `library-inventory.json`.
**Constraints:** Never touch the device or target network.

## Output Contract
```
STATIC SUMMARY
- Target: <pkg> | Artifact: <path> | SHA256: <hash>
- Exported components (high-risk): <count> | evidence: <path>
- Library inventory: <path> (count: N)
- Hardcoded secrets (leads): <count> | evidence: <path>
- Native findings: <count> | evidence: <path>
- Ranked surfaces: 1) ... 2) ... 3) ...
- Deferred: <item — reason>
```
