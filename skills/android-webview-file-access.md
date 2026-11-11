---
name: Android Webview File Access
description: Use when testing Android WebView file access: setAllowFileAccess, universal access, file:// scheme abuse and local XSS.
---

# WebView file access & universal access (android-webview-file-access.md)
**Standard:** OWASP MASVS-PLATFORM
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
File-scheme access in WebViews turns XSS or MITM into local file theft.

---

## 2. Test steps
1. Audit WebSettings: `setAllowFileAccess(true)`, `setAllowFileAccessFromFileURLs(true)`, `setAllowUniversalAccessFromFileURLs(true)`, `setAllowContentAccess`.
2. Find `loadUrl`/`loadDataWithBaseURL` with web-controlled or deep-link-controlled input (file:// scheme abuse).
3. Dynamic: load a `file:///data/data/<pkg>/...` URL via deep link / JS bridge and observe file read; combine with network-agent MITM for stored-XSS chaining.
4. Check `onJsPrompt/onJsAlert` and `WebViewClient.shouldOverrideUrlLoading` for custom scheme handling.

---

## 3. False-positive notes
- File access enabled but no attacker-controlled URL reaches the WebView = hardening note, not a confirmed bug.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-PLATFORM; MASTG WebView tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
