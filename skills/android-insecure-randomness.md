# Insecure randomness (tokens, IVs, nonces) (android-insecure-randomness.md)
**Standard:** OWASP MASVS-CRYPTO
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Predictable randomness makes tokens, session IDs, and IVs guessable.

---

## 2. Test steps
1. Grep for `java.util.Random`, `Math.random()`, time-seeded PRNGs used for tokens/keys/IVs; confirm `java.security.SecureRandom` is the standard.
2. Check IV/nonce handling: static IV (`IvParameterSpec(new byte[16])`), reused IV across encryptions, ECB mode.
3. Dynamic (Frida): hook `SecureRandom.nextBytes` / `Cipher.init` and log IVs across runs — identical IVs = deterministic ciphertext.
4. Look for tokens generated client-side and accepted by the backend without server-side entropy.

---

## 3. False-positive notes
- MD5/SHA1 used only as a cache key is a known FP; randomness used for non-security purposes is not a bug.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-CRYPTO; MASTG crypto tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
