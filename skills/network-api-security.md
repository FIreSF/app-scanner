---
name: Network API Security
description: Use when auditing mobile network traffic: TLS, certificate pinning, API endpoint mapping, token and PII exposure in transit.
---

# NETWORK TRAFFIC & MOBILE API SECURITY AUDITING (skills/network-api-security.md)
**Standard:** OWASP MASVS-NETWORK & MASVS-AUTH | API Security Testing  
**Audience:** Senior Mobile Penetration Testers & Network Traffic Agents  

---

## 1. Mobile Network Architecture & Interception Strategy
Mobile applications communicate with backend REST, GraphQL, WebSocket, and gRPC endpoints. Because client-side code executes on untrusted hardware, the network layer forms the primary boundary for authentication, authorization, and data confidentiality.

```
Mobile App (Android/iOS)
   │  [Cleartext HTTP / Weak TLS / Custom Pinning]
   ▼
Interception Proxy (mitmproxy / Burp Suite) [CA Certificate Injected]
   │  [Inspected & Manipulated Payloads]
   ▼
Backend Microservices & Cloud APIs
```

---

## 2. SSL/TLS Certificate Pinning & Interception Bypass

### 2.1 Pinning Mechanisms Overview
1. **Android Network Security Config (NSC):** XML declaration in `res/xml/network_security_config.xml` defining pin sets (`<pin-set expiration="...">`).
2. **OkHttp3 `CertificatePinner`:** In-code SHA-256 certificate public key pinning (`CertificatePinner.Builder().add(...)`).
3. **Conscrypt / TrustManagerImpl:** System-level X.509 certificate chain validation.
4. **Third-Party Libraries:** TrustKit, Appcelerator, PhoneGap, Cordova.
5. **Non-JVM Runtimes (Flutter & React Native):**
   - Flutter uses Google's BoringSSL directly compiled into `libflutter.so`, completely bypassing Java TrustManager!
   - React Native uses OkHttp on Android and NSURLSession on iOS.

### 2.2 Senior Bypass Strategies
- **JVM Layer:** Use the surgical Frida pinning template (`templates/frida/ssl_pinning_bypass.js`).
- **Flutter BoringSSL Bypass:** Hook native C functions in `libflutter.so`:
  Search memory for the SSL verification routine `ssl_crypto_x509_session_verify_cert_chain` and patch the return register (`MOV W0, #1; RET` or ARM64 equivalent).
- **Network Security Config Patching:** When re-signing is permissible, modify `network_security_config.xml` in APK decompiled tree:
```xml
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

---

## 3. Mutual TLS (mTLS) Handling & Client Certificate Extraction
When an application enforces mTLS:
- The client certificate and private key are bundled in the application (often inside `assets/` or `res/raw/` as `.p12` or `.pfx`, or protected inside Android Keystore).
- **Extraction Technique:**
  1. Audit assets for `.p12`, `.pfx`, `.crt`, `.key`.
  2. Hook `java.security.KeyStore.load` to intercept the passphrase passed when loading the PKCS#12 bundle.
  3. Import the extracted client certificate and private key into mitmproxy or Burp Suite to allow transparent proxying.

---

## 4. Mobile Authentication & Session Architecture Flaws

### 4.1 OAuth 2.0 / OIDC Implementation Pitfalls
- **PKCE (Proof Key for Code Exchange) Absence:** If an application implements the Authorization Code grant without PKCE (`code_challenge` / `code_verifier`), intercepted authorization codes can be exchanged for tokens by rogue apps on the device.
- **Custom Scheme Redirect Hijacking:** Deep link redirection URIs that lack domain ownership verification can be claimed by malicious apps to intercept access tokens.
- **Token Leakage in Query Parameters:** Sensitive session tokens or API keys passed in URL query strings leak via proxy logs, WebKit history, server access logs, and HTTP Referer headers.

### 4.2 Cross-Tenant IDOR & Broken Object Level Authorization (BOLA)
- **High-Value Target:** Mobile-specific API endpoints (e.g. `/api/v2/mobile/user/1337/profile` or `/api/v1/app/documents?account_id=...`).
- **Verification Rule:**
  - Create `Account_A` and `Account_B`.
  - Issue request with `Account_A`'s bearer token, but replace targeted IDs with `Account_B`'s entity IDs.
  - If the server responds with `200 OK` and `Account_B`'s confidential data, IDOR is confirmed.
  - Verify if write operations (`PUT`, `POST`, `DELETE`) allow unauthorized cross-account state modification.

---

## 5. GraphQL & REST Mobile API Specifics

### 5.1 GraphQL Introspection & Batching
- Check if GraphQL introspection is enabled in production (`query { __schema { types { name } } }`).
- Test for query batching attacks (submitting an array of 50+ queries in a single HTTP request to bypass rate limiting).

### 5.2 Cleartext Traffic Permitted (`usesCleartextTraffic`)
- Inspect `AndroidManifest.xml` for `android:usesCleartextTraffic="true"`.
- If cleartext HTTP is permitted and the app sends credentials or session cookies over `http://`, demonstrate credential harvesting on the local network.
