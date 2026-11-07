# Biometric & app-lock bypass (android-biometric-auth-bypass.md)
**Standard:** OWASP MASVS-AUTH
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Client-side biometric gates are spoofable unless bound to a Keystore CryptoObject.

---

## 2. Test steps
1. Disassemble the lock flow: does success depend only on a client callback/boolean, or on a `CryptoObject` that decrypts a Keystore key?
2. Frida: hook `BiometricPrompt.authenticate` / `onAuthenticationSucceeded` and force success; observe whether protected data/actions unlock.
3. Check fallback: PIN/password fallback entropy, rate limiting, lockout; `setUserAuthenticationRequired(true)` + validity window.
4. Test with invalid CryptoObject / cancelled auth -> does the app fail closed?

---

## 3. False-positive notes
- Client callback spoofable but Keystore CryptoObject in hardware TEE = known FP (backend decryption still blocked).

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-AUTH; MASTG auth tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
