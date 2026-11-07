# Clipboard & intent-extra data leakage (android-clipboard-and-intent-leakage.md)
**Standard:** OWASP MASVS-STORAGE / MASVS-PLATFORM
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Sensitive data copied to the clipboard or sent in intents outlives the app sandbox.

---

## 2. Test steps
1. Grep for `ClipboardManager.setPrimaryClip` with tokens/passwords/keys; check `ClipDescription` labels and whether sensitive clips are cleared after use.
2. Audit intents carrying secrets in extras (implicit intents to any handler app = leakage).
3. Dynamic: set a password/token, copy it, read clipboard from a second (attacker) app with `READ_CLIPBOARD` where allowed; inspect `adb shell dumpsys clipboard`.
4. Android 10+ restricts background clipboard access — test on the target API level and note version scope.

---

## 3. False-positive notes
- Clipboard use for non-sensitive text (share sheet text) is not a finding; prove sensitive content.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-STORAGE / MASVS-PLATFORM; MASTG clipboard tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
