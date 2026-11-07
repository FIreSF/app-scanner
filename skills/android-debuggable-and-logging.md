# Debuggable apps & sensitive logging (android-debuggable-and-logging.md)
**Standard:** OWASP MASVS-RESILIENCE / MASVS-CODE
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Debuggable builds and verbose logs leak code paths and secrets to other apps / logcat readers.

---

## 2. Test steps
1. Manifest: `android:debuggable="true"` in a release APK (check with aapt/jadx). Debuggable = any app can attach as debugger.
2. Grep decompiled code for `Log.d/v/i/e` printing tokens, passwords, keys, URLs, PII; check `System.out.println` equivalents.
3. Dynamic: `adb logcat` while exercising login/share flows; look for credentials in plaintext.
4. Also check `android:usesCleartextTraffic`, test-only endpoints, and stack traces returned to UI.

---

## 3. False-positive notes
- Debug logs in a debug build are expected; report only against release artifacts.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-RESILIENCE / MASVS-CODE; MASTG logging tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
