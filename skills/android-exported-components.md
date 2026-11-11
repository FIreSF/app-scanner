---
name: Android Exported Components
description: Use when auditing the manifest for exported activities, services, receivers, and their permission guards.
---

# Android exported components & manifest audit (android-exported-components.md)
**Standard:** OWASP MASVS-PLATFORM
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Exported activities/services/receivers/providers are the #1 Android IPC bug class.

---

## 2. Test steps
1. `aapt dump xmltree app.apk AndroidManifest.xml` / jadx manifest review: list every component with `android:exported=true` or an intent-filter (implicitly exported pre-API 31).
2. For each exported component: is it protected by a `signature`-level permission? No permission + sensitive action = bug candidate.
3. Dynamic proof: `adb shell am start -n <pkg>/<activity>` (activity), `am startservice`, `am broadcast`, `content query --uri content://<authority>/...` (provider).
4. Check intent extras: does an exported component forward nested intents (`startActivity(getParcelableExtra(...))`) -> intent redirection (see ipc-deeplink-exploitation).

---

## 3. False-positive notes
- Permissions declared with `normal`/`dangerous` protection level do not stop other apps; only `signature` does.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-PLATFORM-1/2; MASTG tests for exported components.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
