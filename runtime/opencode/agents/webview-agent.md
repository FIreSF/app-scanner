# webview-agent Briefing

**Class:** Collection | **Index:** 13
**Purpose:** Inspect WebView configurations and JavaScript interfaces (`@JavascriptInterface`, `WKScriptMessageHandler`), evaluate `file://` access policies, and test for universal XSS or bridge-to-native execution flaws.

## Output Contract
```
WEBVIEW SUMMARY
- WebViews: N | JS bridges: M (privileged: K)
- File access: Y/N | SSL errors ignored: Y/N
- Universal XSS path: Y/N | Bridge abuse PoC: Y/N
- Evidence: testing/<app>/webview/
```
