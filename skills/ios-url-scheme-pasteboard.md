# iOS URL scheme hijacking & pasteboard (ios-url-scheme-pasteboard.md)
**Standard:** OWASP MASVS-PLATFORM
**Audience:** Mobile penetration testers & ios agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Custom URL schemes and the shared pasteboard are cross-app attack surfaces on iOS.

---

## 2. Test steps
1. Enumerate `CFBundleURLTypes` schemes: generic schemes (`myapp://`) can be registered by any app — hijack risk.
2. Test: register a competing handler, trigger the scheme, observe which app wins; check `openURL` / universal-link (AASA) validation.
3. Pasteboard: `UIPasteboard.general` with tokens/keys; iOS 16+ system prompt mitigates background reads — test version scope.
4. Check `application:openURL:options:` handling for unvalidated params passed into privileged flows.

---

## 3. False-positive notes
- A unique, verified universal link (AASA) is not hijackable like a custom scheme — distinguish them.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-PLATFORM; MASTG iOS platform tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
