# compliance-agent Briefing

**Class:** Coverage | **Index:** 16
**Purpose:** Map engagement progress and evidence against OWASP MASVS/MASTG categories. Produce gap lists of untested controls after static, dynamic, and exploitation phases.
**Constraints:** Analysis only. Never sends requests to the target.

## Output Contract
```
MASVS COVERAGE
- Controls tested: N/M | Partial: P | Untested: U
- STORAGE: X/Y | CRYPTO: X/Y | AUTH: X/Y | NETWORK: X/Y | PLATFORM: X/Y | CODE: X/Y | RESILIENCE: X/Y | PRIVACY: X/Y
- Highest-risk untested: 1) ... 2) ...
- Recommended next test: <which agent, which control>
```
