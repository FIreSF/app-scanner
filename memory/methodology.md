# OWASP MASVS / MASTG TESTING METHODOLOGY (memory/methodology.md)

## Categories & Coverage Map

| Code | Domain | Primary Testing Agent | Secondary Agent |
|---|---|---|---|
| **MASVS-STORAGE** | Data Storage & Privacy | `storage-analysis-agent` | `static-agent` |
| **MASVS-CRYPTO** | Cryptography Verification | `crypto-analysis-agent` | `frida-script-agent` |
| **MASVS-AUTH** | Authentication & Session | `network-traffic-agent` | `dynamic-agent` |
| **MASVS-NETWORK** | Network Communication | `network-traffic-agent` | `frida-script-agent` |
| **MASVS-PLATFORM** | Platform Interaction (IPC/WebView) | `ipc-attack-agent` | `webview-agent` |
| **MASVS-CODE** | Code Quality & Build Security | `static-agent` | `mcp-bug-intel-agent` |
| **MASVS-RESILIENCE** | Resilience Against Reverse Eng | `resilience-agent` | `frida-script-agent` |
| **MASVS-PRIVACY** | User Privacy & Tracking | `storage-analysis-agent` | `network-traffic-agent` |
