# Mobile API / backend testing (client findings, server impact) (mobile-api-backend-testing.md)
**Standard:** OWASP MASVS-NETWORK / MASVS-AUTH
**Audience:** Mobile penetration testers & mobile agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Most mobile 'app bugs' are actually backend bugs reachable from the client — test the API, not just the app.

---

## 2. Test steps
1. Map APIs from traffic (mitmproxy): endpoints, auth headers, refresh tokens, GraphQL operations.
2. Broken access control: replay another user's object IDs (IDOR), swap roles (user -> admin endpoints), mass-assignment fields (`isAdmin`, `role`) in requests.
3. Auth flaws: missing/expired token acceptance, no rate limiting on OTP/reset, token leakage in URLs/logs, verbose errors.
4. Replay captured requests with modified payloads (Burp Repeater) — every claim needs baseline vs manipulated evidence (see AGENTS.md §4).

---

## 3. False-positive notes
- Client-side-only controls (pinning, root checks) enforced nowhere on the server are defense-in-depth findings — say so explicitly.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-NETWORK / MASVS-AUTH; OWASP API Security Top 10.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
