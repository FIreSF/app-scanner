# COMMON ATTACK PATTERNS (memory/patterns.md)

## 1. Intent Redirection & Unprotected Components
- **Pattern:** Exported activity receives an Intent extra containing a nested Intent, then calls `startActivity(nestedIntent)` without validation.
- **Impact:** Attacker triggers unexported internal activities or reads protected Content Providers with the victim app's privileges.
- **Proof:** Pass an intent extra targeting an unexported Activity or `grantUriPermissions`.

## 2. Insecure FileProvider Path Configuration
- **Pattern:** `filepaths.xml` contains `<root-path path="." />` or `<external-path path="." />`.
- **Impact:** Any component with access to the provider can traverse arbitrary local device paths.
- **Proof:** Query provider using `content://<authority>/...` to retrieve `/data/data/<pkg>/databases/`.

## 3. WebView Bridge Native Reflection
- **Pattern:** `addJavascriptInterface` added on WebViews on Android < 4.2 or insecure custom bridges allowing native method invocation.
- **Impact:** Malicious web page loaded via MITM, deep link, or stored XSS achieves native code execution.

## 4. Keystore Misuse & Static IV
- **Pattern:** AES keys initialized with a hardcoded static byte array for IV (`IvParameterSpec(new byte[16])`), or AES-ECB mode without authentication.
- **Impact:** Deterministic ciphertext allows pattern recognition and replay attacks.
