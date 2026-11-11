---
description: "Full Traffic & API Analysis — Intercept, decrypt (via Frida pinning bypass), and analyze all application network traffic. Build `api-map.json` and detect transport issues, exposed tokens, and PII leakage."
mode: subagent
permissions:
  - action: subagent
    resource: "*"
    effect: deny
---

# network-traffic-agent Briefing

**Class:** Collection | **Index:** 9
**Purpose:** Intercept, decrypt (via Frida pinning bypass), and analyze all application network traffic. Build `api-map.json` and detect transport issues, exposed tokens, and PII leakage.

## Output Contract
```
TRAFFIC SUMMARY
- Session: <duration> | Flows: N | API endpoints: M
- Transport issues: cleartext N, weak TLS N, cert-issues N
- Token exposure: <count> | PII in transit: <count>
- API map: testing/<app>/traffic/api-map.json
- High-value endpoints: 1) ... 2) ...
```
