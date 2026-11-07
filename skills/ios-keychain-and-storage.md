# iOS Keychain & file storage (ios-keychain-and-storage.md)
**Standard:** OWASP MASVS-STORAGE
**Audience:** Mobile penetration testers & ios agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
iOS secrets survive in Keychain, preferences, and files long after logout if cleanup is wrong.

---

## 2. Test steps
1. Audit Keychain usage: `kSecAttrAccessible` class (e.g. `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` vs weaker), missing access groups (shared with other apps/extensions).
2. Check `NSUserDefaults` / `UserDefaults` for tokens/keys (plaintext plist), and file protection classes (`NSFileProtectionComplete` vs `...UntilFirstUserAuthentication`).
3. Dynamic: Frida `SecItemAdd/CopyMatching`, Objection `ios keychain dump` (where available); inspect app container via backup.
4. Verify logout actually deletes Keychain items and files — re-login with a second account and look for leftover data.

---

## 3. False-positive notes
- Non-sensitive preferences in UserDefaults are not a finding; prove secret/PII content in the container.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-STORAGE; MASTG iOS storage tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
