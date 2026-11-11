---
name: Android Network Security Config
description: Use when reviewing the Android Network Security Config, cleartext traffic rules, and user-added certificate authorities.
---

# Android Network Security Config & cleartext (android-network-security-config.md)
**Standard:** OWASP MASVS-NETWORK
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Misconfigured NSC silently disables TLS protections for the whole app.

---

## 2. Test steps
1. Find `networkSecurityConfig` XML (manifest `android:networkSecurityConfig`): `cleartextTrafficPermitted=true`, `<trust-anchors>` with `src="user"`, `<pin-set>` backups, `overridePins`.
2. Dynamic: proxy without CA install — does HTTP (cleartext) traffic flow? `curl` from device / grader checks.
3. Frida: hook `TrustManagerImpl.verifyChain` / OkHttp `CertificatePinner.check` to confirm pinning actually enforced (bypass != vulnerability; absence + cleartext = finding).
4. Check per-domain configs: dev/staging domains often allow cleartext while prod does not — still reportable if shipped.

---

## 3. False-positive notes
- Absence of pinning alone is defense-in-depth, not an exploitable server bug (FALSE_POSITIVE_DB) — pair with cleartext/CA issues.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-NETWORK; MASTG network tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
