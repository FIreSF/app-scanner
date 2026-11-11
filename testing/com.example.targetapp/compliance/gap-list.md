# MASVS Gap List

- **Target:** `com.example.targetapp`
- **Generated:** 2026-11-11T09:28:25
- **Open gaps:** 23

| Priority | Control | Status | Recommended agent | Why it matters |
|---|---|---|---|---|
| P1 | MASVS-AUTH-1 | not-tested | `network-traffic-agent` | Secure authentication and authorization protocols |
| P1 | MASVS-CODE-2 | not-tested | `static-agent` | Release build settings (no debuggable, backup hardened) |
| P1 | MASVS-CRYPTO-1 | not-tested | `crypto-analysis-agent` | No hardcoded symmetric keys as the sole encryption method |
| P1 | MASVS-NETWORK-1 | not-tested | `network-traffic-agent` | Cleartext communication used only where necessary |
| P1 | MASVS-NETWORK-2 | not-tested | `network-traffic-agent` | Remote endpoint identity verified (TLS / pinning) |
| P1 | MASVS-PLATFORM-1 | not-tested | `ipc-attack-agent` | IPC mechanisms used securely |
| P1 | MASVS-PLATFORM-2 | not-tested | `webview-agent` | WebViews configured securely |
| P1 | MASVS-STORAGE-1 | not-tested | `storage-analysis-agent` | Sensitive data (PII, credentials, keys) uses platform credential storage |
| P1 | MASVS-STORAGE-2 | not-tested | `storage-analysis-agent` | No sensitive data stored outside the app container or credential storage |
| P2 | MASVS-AUTH-2 | not-tested | `dynamic-agent` | Local authentication implemented per platform best practice |
| P2 | MASVS-AUTH-3 | not-tested | `dynamic-agent` | Sensitive operations require additional authentication |
| P2 | MASVS-CODE-1 | not-tested | `static-agent` | App signed and provisioned with a valid certificate |
| P2 | MASVS-CODE-4 | not-tested | `mcp-bug-intel-agent` | Up-to-date platform version and third-party dependencies |
| P2 | MASVS-CRYPTO-2 | not-tested | `crypto-analysis-agent` | Proven implementations of cryptographic primitives |
| P2 | MASVS-PLATFORM-3 | not-tested | `ipc-attack-agent` | User interface and deep links handled securely |
| P2 | MASVS-PRIVACY-1 | not-tested | `storage-analysis-agent` | App minimizes use of sensitive data |
| P2 | MASVS-PRIVACY-2 | not-tested | `network-traffic-agent` | Sensitive data protected against third-party access |
| P2 | MASVS-RESILIENCE-2 | not-tested | `resilience-agent` | Debugging and instrumentation prevented/detected |
| P2 | MASVS-RESILIENCE-3 | not-tested | `resilience-agent` | Tampering with code and data detected |
| P3 | MASVS-CODE-3 | not-tested | `static-agent` | Debug symbols stripped from native binaries |
| P3 | MASVS-PRIVACY-3 | not-tested | `dynamic-agent` | Sensitive data not exposed through the UI |
| P3 | MASVS-RESILIENCE-1 | not-tested | `resilience-agent` | Platform integrity validated |
| P3 | MASVS-RESILIENCE-4 | not-tested | `resilience-agent` | Reverse engineering tools and frameworks detected |

## Next actions

1. Re-dispatch the recommended agent for every P1 gap.
2. Convert `partial` rows into `tested` by writing the expected artifact into the evidence directory.
3. Re-run `python scripts/compliance_matrix.py` after each milestone.
