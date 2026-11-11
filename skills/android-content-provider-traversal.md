---
name: Android Content Provider Traversal
description: Use when testing exported content providers for path traversal, SQL injection, and permission bypass.
---

# Content provider path traversal & SQL injection (android-content-provider-traversal.md)
**Standard:** OWASP MASVS-STORAGE / MASVS-PLATFORM
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Providers expose structured storage to other apps; path and query handling are classic bug sources.

---

## 2. Test steps
1. Enumerate providers: `adb shell dumpsys package <pkg> | grep -A1 PROVIDERS` / manifest audit.
2. Path traversal: `FileProvider` `filepaths.xml` with `<root-path path="."/>` / `<external-path path="."/>` -> query `content://<authority>/...` to read `/data/data/<pkg>/databases/`.
3. SQL injection: query/insert/update/insert with unsanitized `selection`/`sortOrder` (`' OR '1'='1`) via `content query --uri ... --where "..."`.
4. Frida/drozer: `content query` from a test app with `grantUriPermissions` abuse.

---

## 3. False-positive notes
- A provider that requires a signature permission and validates URIs is not vulnerable even if exported.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-STORAGE / MASVS-PLATFORM; MASTG provider tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
