# GLOBAL CONTEXT LEDGER TEMPLATE (memory/CONTEXT_LEDGER.md)

> Pipe-delimited session ledger recording every surface, test, pivot, and finding across the engagement.

## Ledger Schema
`TIMESTAMP | SESSION_ID | AGENT | SURFACE | ACTION | RESULT | EVIDENCE_PATH | REMARKS`

## Example Entries
```text
2026-10-31 10:00:00 | sess_001 | orchestrator-agent | BOOTSTRAP | Preflight check | SUCCESS | testing/com.example.app/notes/bootstrap.md | Ready
2026-10-31 10:02:15 | sess_001 | static-agent | MANIFEST | Component enumeration | FOUND_EXPORTS | testing/com.example.app/static/manifest.json | 3 exported activities
2026-10-31 10:05:40 | sess_001 | mcp-bug-intel-agent | CVE_LOOKUP | Query OkHttp 3.12.0 | NO_CRITICAL | testing/com.example.app/intel/cve-matches.json | Reachability low
2026-10-31 10:14:22 | sess_001 | ipc-attack-agent | EXPORTED_ACTIVITY | Intent redirection fuzz | CONFIRMED | testing/com.example.app/ipc/poc_redirect.sh | PII leak in Intent extras
2026-10-31 10:18:05 | sess_001 | verification-agent | FALSIFICATION | Replay intent with Tenant B | CONFIRMED_VALIDATED | testing/com.example.app/verification/FIND-01.md | Verified 2/2
```
