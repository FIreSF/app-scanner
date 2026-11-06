# MASVS-CRYPTO CHECKLIST (memory/targets/crypto.md)

1. [ ] Check for hardcoded encryption keys, AES keys, or static salt in code or native libraries.
2. [ ] Identify block cipher mode: reject AES-ECB; ensure AES-GCM or authenticated CBC with HMAC.
3. [ ] Verify initialization vectors (IVs): ensure IVs are randomly generated using `SecureRandom` and never static.
4. [ ] Audit key derivation functions: ensure PBKDF2/Argon2/bcrypt with sufficient iterations instead of plain SHA256.
5. [ ] Verify Android Keystore / iOS Keychain usage: ensure keys are hardware-backed (`KeyGenParameterSpec.Builder(..., PURPOSE_ENCRYPT | PURPOSE_DECRYPT)`).
6. [ ] Audit custom cryptographic implementations: ensure standard, peer-reviewed libraries are utilized.
