# MASVS-PLATFORM CHECKLIST (memory/targets/platform.md)

1. [ ] Exported Activities: enumerate and fuzz with unexpected intents or extras (`adb shell am start`).
2. [ ] Exported Content Providers: test for SQL injection and directory traversal via `content://` URIs.
3. [ ] Broadcast Receivers: test if sensitive broadcasts require signature permissions.
4. [ ] Intent Redirection: test if activities forward incoming untrusted intents to internal unexported components.
5. [ ] WebViews: check for `setJavaScriptEnabled(true)`, `addJavascriptInterface`, and `setAllowFileAccessFromFileURLs(true)`.
6. [ ] Deep Links: audit intent filters with `BROWSABLE` category; test parameter injection into deep link handlers.
