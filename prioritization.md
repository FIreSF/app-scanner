# SIGNAL PRIORITIZATION ENGINE (prioritization.md)

This engine governs signal triage and prioritizes testing effort across discovered mobile surfaces.

## Priority Tiers (P1 to P4)

### P1 — Immediate Exploitation Candidates (Max 60 min timebox)
- Exported components with dangerous permissions or no permissions (`android:exported="true"`, custom URL schemes with command injection/auth bypass).
- Hardcoded production credentials (AWS/GCP service keys with write access, private signing keys, database connection strings).
- Insecure WebView bridges exposing native Java/ObjC methods with code execution or file read capabilities.
- Direct object reference (IDOR) or authentication token leaks in cleartext/unpinned network traffic.
- Reachable, high-CVSS CVEs in bundled third-party libraries (deserialization, RCE, memory corruption).

### P2 — High-Value Dynamic Exploration (Max 30 min timebox)
- Insecure data storage of plaintext credentials, access tokens, or sensitive user PII in SharedPreferences, SQLite databases, or SD cards.
- Weak or hardcoded cryptographic keys (AES-ECB mode, static IV, predictable RNG).
- Universal deep links redirecting to internal web views or sensitive application screens without validation.
- Missing SSL pinning on sensitive API endpoints.

### P3 — Standard Hardening & Resilience Gaps (Max 15 min timebox)
- Trivial bypass of root or jailbreak detection mechanisms via generic Frida hooks.
- Backup enablement (`android:allowBackup="true"`) without sensitive content exclusions.
- Verbose logging of session identifiers or tokens in logcat/syslog.
- Debuggable application flag enabled in release builds (`android:debuggable="true"`).

### P4 — Informational / Low Signal (Log and pivot)
- Public API keys (e.g., standard Google Maps or Firebase client keys without backend access).
- Missing obfuscation or code stripping where business logic is standard.
- Theoretical vulnerabilities without reachable code paths or exploit primitive.

## Circuit Breakers
- **Surface Timeout:** Abandon low-signal surface if no progress in 15 minutes; high-value surface capped at 60 minutes.
- **Repeated Failures:** 5 consecutive 403/429 responses trigger a 60-second backoff.
- **Loop Prevention:** 5 identical tool calls without state change trigger immediate surface pivot.
