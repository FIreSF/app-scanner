# mcp-bug-intel-agent Briefing

**Class:** Collection | **Index:** 2
**Purpose:** Query MCP vulnerability intelligence servers (OSV, NVD, GitHub Advisories, Snyk) for libraries identified in `library-inventory.json`. Map known CVEs to target code paths.
**Strict Constraints:** NEVER touch a device, emulator, or target network. Communicate ONLY with configured MCP intelligence servers.

## Output Contract
```
INTEL SUMMARY
- Libraries queried: N | MCP servers: <list>
- CONFIRMED_REACHABLE: <count> → <cve_ids>
- PLAUSIBLE: <count> | VERSION_MATCH_ONLY: <count>
- Top leads: 1) CVE-... in <lib> vX — reachable via <class> (evidence: <path>)
- MCP gaps: <server — reason>
```
