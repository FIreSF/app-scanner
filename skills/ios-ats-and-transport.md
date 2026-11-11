---
name: IOS ATS And Transport
description: Use when testing iOS App Transport Security, TLS validation, and certificate pinning on iOS builds.
---

# iOS ATS & transport security (ios-ats-and-transport.md)
**Standard:** OWASP MASVS-NETWORK
**Audience:** Mobile penetration testers & ios agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
App Transport Security exceptions silently allow cleartext or weak TLS.

---

## 2. Test steps
1. Audit `Info.plist` `NSAppTransportSecurity`: `NSAllowsArbitraryLoads`, `NSAllowsLocalNetworking`, per-domain exceptions (`NSTemporaryExceptionAllowsInsecureHTTP`, TLS version/cipher downgrades).
2. Dynamic: proxy without CA — does HTTP flow? Frida hook `URLSession:didReceiveChallenge` / `SecTrustEvaluate` to confirm pinning enforced.
3. Check `NSAllowsArbitraryLoadsInWebContent` for WebViews separately from native traffic.
4. Certificate transparency / pinning backup pins: expired backup pins can brick updates — note as resilience issue.

---

## 3. False-positive notes
- ATS exception for a local-only dev domain shipped in prod is still reportable; test-only builds are not.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-NETWORK; MASTG iOS network tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
