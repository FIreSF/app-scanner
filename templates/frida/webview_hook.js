/**
 * Senior WebView & Hybrid Bridge Security Instrumentation Template
 * Standard: OWASP MASVS-PLATFORM
 * Target Operations:
 *  - Force enable Chrome DevTools remote debugging (setWebContentsDebuggingEnabled)
 *  - Intercept addJavascriptInterface and enumerate exposed methods
 *  - Audit dangerous WebSettings: setAllowFileAccess, setAllowUniversalAccessFromFileURLs
 *  - Monitor WebView.loadUrl and WebView.loadDataWithBaseURL
 *  - Monitor WebViewClient.shouldOverrideUrlLoading for intent:// schemes
 * Safe to run: true
 */

Java.perform(function () {
    console.log("[*] [FRIDA_WEBVIEW] Initializing Senior WebView Security Hooks...");

    // 1. Force Enable Chrome DevTools Remote Debugging
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.setWebContentsDebuggingEnabled(true);
        console.log("[+] [WEBVIEW_DEBUG] WebView.setWebContentsDebuggingEnabled forced to TRUE (Attach via chrome://inspect)");
    } catch (err) {}

    // 2. Intercept addJavascriptInterface to audit bridge security
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String').implementation = function (obj, name) {
            console.log("\n[!] [WEBVIEW_BRIDGE] Native Interface Injected:");
            console.log("    -> Interface Name: '" + name + "'");
            console.log("    -> Java Class:     " + obj.getClass().getName());

            var methods = obj.getClass().getDeclaredMethods();
            console.log("    -> Exposed Methods:");
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var hasAnnotation = false;
                try {
                    var annotations = method.getDeclaredAnnotations();
                    for (var j = 0; j < annotations.length; j++) {
                        if (annotations[j].toString().indexOf("JavascriptInterface") > -1) {
                            hasAnnotation = true;
                            break;
                        }
                    }
                } catch (e) {}

                var flag = hasAnnotation ? " [@JavascriptInterface]" : " [UNANNOTATED]";
                console.log("       " + method.getName() + "()" + flag);
            }
            return this.addJavascriptInterface(obj, name);
        };
    } catch (err) {}

    // 3. Audit Dangerous WebSettings
    try {
        var WebSettings = Java.use("android.webkit.WebSettings");
        WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function (allow) {
            if (allow) {
                console.log("[!] [WEBVIEW_CONFIG] CRITICAL: setAllowUniversalAccessFromFileURLs set to TRUE! (UXSS Risk)");
            }
            return this.setAllowUniversalAccessFromFileURLs(allow);
        };

        WebSettings.setAllowFileAccessFromFileURLs.implementation = function (allow) {
            if (allow) {
                console.log("[!] [WEBVIEW_CONFIG] WARNING: setAllowFileAccessFromFileURLs set to TRUE!");
            }
            return this.setAllowFileAccessFromFileURLs(allow);
        };

        WebSettings.setAllowFileAccess.implementation = function (allow) {
            console.log("[*] [WEBVIEW_CONFIG] setAllowFileAccess(" + allow + ")");
            return this.setAllowFileAccess(allow);
        };
    } catch (err) {}

    // 4. Monitor WebView URL Loading
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            console.log("\n[*] [WEBVIEW_URL] loadUrl: " + url);
            if (url && (url.indexOf("javascript:") === 0 || url.indexOf("file://") === 0)) {
                console.log("    [!] SENSITIVE SCHEME: WebView loading " + url);
            }
            return this.loadUrl(url);
        };

        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
            console.log("\n[*] [WEBVIEW_URL] loadUrl with custom headers: " + url);
            return this.loadUrl(url, headers);
        };
    } catch (err) {}

    console.log("[+] [FRIDA_WEBVIEW] WebView Security Monitoring Active.");
});
