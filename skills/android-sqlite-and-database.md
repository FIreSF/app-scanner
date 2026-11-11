---
name: Android SQLITE And Database
description: Use when auditing SQLite and database files for unencrypted sensitive data and injection through local storage.
---

# Insecure SQLite & database storage (android-sqlite-and-database.md)
**Standard:** OWASP MASVS-STORAGE
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Unencrypted local databases and injectable queries leak or corrupt app data.

---

## 2. Test steps
1. Locate `.db` files: `adb shell run-as <pkg> ls databases/` (debuggable) or via backup/provider/Frida `SQLiteDatabase.openDatabase` hooks.
2. Check for SQL built by string concatenation (`rawQuery("SELECT ..." + input)`) -> injection via UI input / provider / deep link params.
3. Check encryption: SQLCipher vs plaintext; keys in SharedPreferences (see keystore skill).
4. Dynamic: input `' OR '1'='1` / UNION payloads; Frida-hook `rawQuery/execSQL` to log constructed SQL.

---

## 3. False-positive notes
- A database readable only by root on a test device is a known FP unless an unprivileged app path exists.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-STORAGE; MASTG storage tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
