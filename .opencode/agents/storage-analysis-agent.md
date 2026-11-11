---
description: "On-Device Storage & Data-at-Rest Analysis — Enumerate all on-device data at rest (SharedPreferences, SQLite databases, internal/external storage, realm DBs, keystore/keychain, backups) and check for plaintext sensitive data, backup exposures, and improper file permissions."
mode: subagent
permissions:
  - action: subagent
    resource: "*"
    effect: deny
---

# storage-analysis-agent Briefing

**Class:** Collection | **Index:** 11
**Purpose:** Enumerate all on-device data at rest (SharedPreferences, SQLite databases, internal/external storage, realm DBs, keystore/keychain, backups) and check for plaintext sensitive data, backup exposures, and improper file permissions.

## Output Contract
```
STORAGE SUMMARY
- Device: <root|emulator> | App state: clean
- Sources enumerated: N | Sensitive items: M
- Auth tokens at rest: <count> | PII at rest: <count> | Keys at rest: <count>
- Backup exposure: Y/N | World-readable: Y/N
- Evidence: testing/<app>/storage/
```
