# Android backup extraction (allowBackup) (android-backup-extraction.md)
**Standard:** OWASP MASVS-STORAGE-2
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Extractable backups leak databases, shared_prefs, and files to anyone with adb/USB access.

---

## 2. Test steps
1. Manifest: `android:allowBackup="true"` (default pre-API 31 for apps targeting <31 without rules).
2. Check `backup_rules.xml` / `dataExtractionRules`: are databases, prefs, files, sharedpref excluded?
3. Dynamic: `adb backup -f backup.ab <pkg>` (needs on-device confirmation) -> convert with `dd if=backup.ab bs=1 skip=24 | openssl rst2ba -d | tar -xf -` (Android backup extractor).
4. Report only if sensitive data (credentials, keys, tokens, PII) is actually extractable.

---

## 3. False-positive notes
- `allowBackup=true` with sensitive data excluded in backup rules is a known false positive (FALSE_POSITIVE_DB).

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-STORAGE-2; MASTG backup tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
