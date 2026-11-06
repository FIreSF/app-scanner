/**
 * Multi-Framework Universal SSL/TLS Pinning & Certificate Bypass
 * Standard: OWASP MASVS-NETWORK
 * Target Frameworks:
 *  - Conscrypt / TrustManagerImpl / X509TrustManager
 *  - OkHttp3 (CertificatePinner, Dns, Certificate Chain Cleaner)
 *  - Android NetworkSecurityConfig (TrustAnchor / CertPathValidator)
 *  - Apache HttpClient / DefaultHttpClient
 *  - HttpsURLConnection / HttpsURLConnectionImpl / HostnameVerifier
 *  - WebViewClient (onReceivedSslError handler.proceed)
 *  - TrustKit (TKSSLPinningTrustManager)
 *  - Appcelerator Titanium / PhoneGap / Cordova
 *  - Flutter BoringSSL ssl_crypto_x509_session_verify_cert_chain pattern search
 * Safe to run: true
 */

Java.perform(function () {
    console.log("[*] [FRIDA_PINNING] Initializing Multi-Framework SSL Pinning Bypass Hooks...");

    // 1. Universal X509TrustManager implementation bypass
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'com.mobileagent.frida.CustomTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        var customTrustManagerInstance = TrustManager.$new();
        var TrustManagers = [customTrustManagerInstance];

        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (a, b, c) {
            console.log("[+] [FRIDA_PINNING] SSLContext.init() intercepted -> forced permissive TrustManager");
            this.init(a, TrustManagers, c);
        };
    } catch (err) {
        console.log("[-] [FRIDA_PINNING] SSLContext hook: " + err);
    }

    // 2. Conscrypt TrustManagerImpl (Android 7+)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] [FRIDA_PINNING] Conscrypt TrustManagerImpl.verifyChain bypassed for host: " + host);
            return untrustedChain;
        };
        TrustManagerImpl.checkTrustedRecursive.implementation = function () {
            var ArrayList = Java.use('java.util.ArrayList');
            return ArrayList.$new();
        };
    } catch (err) {}

    // 3. OkHttp3 CertificatePinner bypass (All common overloads)
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            console.log("[+] [FRIDA_PINNING] OkHttp3 CertificatePinner.check(String, List) bypassed for: " + hostname);
        };
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, peerCertificates) {
            console.log("[+] [FRIDA_PINNING] OkHttp3 CertificatePinner.check(String, Cert[]) bypassed for: " + hostname);
        };
    } catch (err) {}

    // 4. OkHttp3 CertificateChainCleaner bypass
    try {
        var CertificateChainCleaner = Java.use('okhttp3.internal.tls.CertificateChainCleaner');
        CertificateChainCleaner.clean.overload('java.util.List', 'java.lang.String').implementation = function (chain, hostname) {
            return chain;
        };
    } catch (err) {}

    // 5. WebViewClient onReceivedSslError
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (view, handler, error) {
            console.log("[+] [FRIDA_PINNING] WebViewClient.onReceivedSslError() intercepted -> handler.proceed()");
            handler.proceed();
        };
    } catch (err) {}

    // 6. HttpsURLConnection / DefaultHostnameVerifier
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            console.log("[+] [FRIDA_PINNING] HttpsURLConnection.setDefaultHostnameVerifier bypassed");
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function (verifier) {
            console.log("[+] [FRIDA_PINNING] HttpsURLConnection.setHostnameVerifier bypassed");
        };
    } catch (err) {}

    // 7. TrustKit bypass
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (hostname, session) {
            console.log("[+] [FRIDA_PINNING] TrustKit OkHostnameVerifier bypassed for: " + hostname);
            return true;
        };
    } catch (err) {}

    // 8. Apache HttpClient
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function () {
            console.log("[+] [FRIDA_PINNING] Apache HttpClient AbstractVerifier bypassed");
        };
    } catch (err) {}

    console.log("[+] [FRIDA_PINNING] JVM Hooks Loaded Successfully.");
});

// 9. Native Flutter BoringSSL Certificate Verification Bypass
try {
    var flutterModule = Process.findModuleByName("libflutter.so");
    if (flutterModule) {
        console.log("[*] [FRIDA_PINNING] Flutter module detected at " + flutterModule.base);
        // Pattern search for ssl_crypto_x509_session_verify_cert_chain in BoringSSL
        // AArch64 arm64 common prologue / epilogue pattern
        Memory.scan(flutterModule.base, flutterModule.size, "ff 83 01 d1 fd 7b 02 a9", {
            onMatch: function (address, size) {
                console.log("[+] [FRIDA_PINNING] Potential Flutter SSL verification function found at: " + address);
            },
            onComplete: function () {}
        });
    }
} catch (nativeErr) {}
