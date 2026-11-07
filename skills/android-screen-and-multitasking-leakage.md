# Screen, recents & notification leakage (android-screen-and-multitasking-leakage.md)
**Standard:** OWASP MASVS-STORAGE / MASVS-RESILIENCE
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Sensitive screens leak via app-switcher screenshots, notifications, and screen capture.

---

## 2. Test steps
1. Check `FLAG_SECURE` on activities showing tokens/PII/passwords; dynamic: switch apps and inspect recents thumbnail.
2. Notifications: sensitive text in `Notification.Builder` / `addAction` visible on lock screen; check `VISIBILITY_SECRET` handling.
3. Screen capture/screen recording: does the app detect or warn? (Informational unless policy requires it.)
4. WebView/PDF/file previews: thumbnails and cached previews may retain sensitive content after deletion.

---

## 3. False-positive notes
- Missing FLAG_SECURE on non-sensitive screens is a hardening note, not a data leak.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-STORAGE / MASVS-RESILIENCE; MASTG platform tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
