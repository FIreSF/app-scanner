# TRIAGER QUALITY LESSONS & REPORTING RULES (memory/report-lessons.md)

## Core Reporting Guidelines
1. **Never Claim Speculative Impact:** Never assert "Remote Code Execution" if only reflected XSS in a sandbox WebView without bridge interfaces is observed.
2. **Every Finding Must Have Raw Reproduction Commands:**
   - Intent flaws: exact `adb shell am start ...` with extras.
   - Deep links: exact `adb shell am start -a android.intent.action.VIEW -d "scheme://path?param=..."`.
   - API issues: exact curl command or mitmproxy flow reproduction script.
   - Frida bypasses: exact `.js` script name and Frida CLI invocation.
3. **Always Include MASVS / MASTG References:**
   - Explicitly cite the MASVS category (e.g. `MASVS-STORAGE-1`, `MASVS-PLATFORM-2`).
4. **Remediation Must Be Actionable:**
   - Cite specific AndroidManifest attributes, ProGuard/R8 rules, or Android Keystore API calls.
5. **Redact Sensitive Customer Data:**
   - Always scrub auth tokens, phone numbers, and production identifiers from screenshots and dumps.
