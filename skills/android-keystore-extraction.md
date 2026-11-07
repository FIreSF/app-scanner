# Android Keystore key extraction & misuse (android-keystore-extraction.md)
**Standard:** OWASP MASVS-CRYPTO
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Keys that should be hardware-backed and non-extractable are often exportable or misused.

---

## 2. Test steps
1. Audit KeyStore usage: `KeyGenParameterSpec` — `setUserAuthenticationRequired`, `setInvalidatedByBiometricEnrollment`, hardware-backed (`setIsStrongBoxBacked` where required).
2. Frida: hook `KeyStore.getKey/getEntry`, `KeyPairGenerator.generateKeyPair`, `Cipher.init` to dump keys/IVs at runtime.
3. Check for symmetric keys generated in software and stored in SharedPreferences/files instead of Keystore.
4. Verify keys are non-exportable (`setKeyExportAllowed(false)` equivalent) and bound to auth where claimed.

---

## 3. False-positive notes
- A key used only for encrypting non-sensitive cache data is low impact; prove sensitive use first.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-CRYPTO; MASTG keystore tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
