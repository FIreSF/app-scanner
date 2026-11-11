---
name: Flutter Android Security
description: Use when testing Flutter or Dart Android apps: Dart route handling, initial-route injection, dart:io exposure, engine isolation.
---

# Flutter app security testing (flutter-android-security.md)
**Standard:** OWASP MASVS-NETWORK / MASVS-CODE
**Audience:** Mobile penetration testers & flutter agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Flutter apps inherit Android bugs but break standard Frida/MASTG tooling — test them differently.

---

## 2. Test steps
1. Identify Flutter: `libflutter.so`, `assets/flutter_assets/`, `Dart` strings in jadx; note Objection/MASTG gaps.
2. SSL pinning: standard Android Frida scripts often fail on BoringSSL — use `flutter` Frida scripts (search `ssl_crypto_x509_session_verify_cert_chain` in libflutter.so) or reFlutter-style patching on authorized test builds.
3. Storage: insecure_storage plugins (flutter_secure_storage misconfig), plaintext SharedPreferences via platform channels.
4. Platform channels: method channels are the IPC equivalent — audit channel handlers for unvalidated args from Dart/UI input.

---

## 3. False-positive notes
- Tooling failure on Flutter is not evidence of security; switch technique before concluding.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-NETWORK / MASVS-CODE; MASTG Flutter guidance.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
