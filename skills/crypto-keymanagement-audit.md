# CRYPTOGRAPHIC IMPLEMENTATION & KEY MANAGEMENT AUDITING (skills/crypto-keymanagement-audit.md)
**Standard:** OWASP MASVS-CRYPTO | Android Keystore & iOS KeyChain / Secure Enclave  
**Audience:** Senior Mobile Penetration Testers & Cryptography Analysis Agents  

---

## 1. Executive Cryptographic Assessment Philosophy
Cryptographic vulnerabilities in mobile applications rarely stem from broken underlying primitive math (e.g. factoring RSA); they stem almost exclusively from **implementation failures, improper mode selection, static IVs, hardcoded secrets, and flawed key storage**.

---

## 2. Weak Ciphers, Modes & Nonce Misuse

### 2.1 ECB Mode (Electronic Codebook)
- **Vulnerability:** `Cipher.getInstance("AES/ECB/PKCS5Padding")` or omitting mode in `Cipher.getInstance("AES")` defaults to ECB mode on Android.
- **Impact:** Identical plaintext blocks produce identical ciphertext blocks, leaking structural patterns without knowing the key.
- **Audit Command:** Grep decompiled code for `Cipher.getInstance("AES")` or `Cipher.getInstance("AES/ECB/...")`.

### 2.2 Static or Zero IVs in CBC and GCM
- **CBC Mode (Static IV):** Reusing the same Initialization Vector (IV) enables dictionary and replay attacks, and reveals identical plaintext prefixes.
- **GCM Mode (Nonce Reuse):** Reusing an IV with the same AES-GCM key destroys authenticity and allows complete recovery of the authentication key ($H$), enabling ciphertext forgery.
- **Flag Pattern:**
  - `new IvParameterSpec(new byte[16])` (all zeros)
  - `new IvParameterSpec("1234567890123456".getBytes())` (static ASCII string)

### 2.3 Obsolete Primitives
- Inspect and flag any use of:
  - Ciphers: `DES`, `TripleDES` (`DESede`), `Blowfish`, `RC4`.
  - Hashes: `MD5`, `SHA-1` (when used for signature verification or password hashing).
  - Broken PRNGs: `java.util.Random` for cryptographic tokens, nonces, or salt generation (must use `java.security.SecureRandom`).

---

## 3. Hardware-Backed Key Storage Auditing

### 3.1 Android Keystore System
Keys generated in the Android Keystore system are stored either in the Linux kernel space or inside a hardware-isolated security module (TEE - Trusted Execution Environment, or StrongBox Keymaster):
- **Verification of Hardware Backing:**
```java
KeyInfo keyInfo = (KeyInfo) keyFactory.getKeySpec(secretKey, KeyInfo.class);
boolean isInsideSecureHardware = keyInfo.isInsideSecureHardware();
```
- **Attacker Pitfall:** Many apps generate an AES key, encrypt data, but store the AES key inside `SharedPreferences` in plaintext or encoded with Base64, completely bypassing the Keystore.

### 3.2 iOS KeyChain & Secure Enclave
- KeyChain items must specify appropriate accessibility attributes:
  - `kSecAttrAccessibleAfterFirstUnlock`: Accessible after user first unlocks device.
  - `kSecAttrAccessibleWhenUnlocked`: Accessible only while device is unlocked.
  - Vulnerability: `kSecAttrAccessibleAlways` (deprecated) allows data to be read even before device unlock.

---

## 4. Biometric Authentication Architecture: Crypto-Object vs Boolean Callback

### 4.1 The Flawed Client-Side Callback
A frequent high-severity architectural flaw:
```java
// Vulnerable: Client-side boolean verification
biometricPrompt.authenticate(promptInfo, executor, new BiometricPrompt.AuthenticationCallback() {
    @Override
    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
        // App simply branches into authenticated screen or sends cached token!
        navigateToMainScreen();
    }
});
```
- **Bypass Technique:** A simple Frida script hooking `onAuthenticationSucceeded` or overriding the callback can bypass biometric authentication in milliseconds without providing a valid fingerprint or face scan.

### 4.2 The Secure Cryptographic Binding
A secure implementation binds biometrics directly to cryptographic key usage:
- `KeyGenParameterSpec.Builder.setUserAuthenticationRequired(true)`
- The app passes `new BiometricPrompt.CryptoObject(cipher)` into `authenticate()`.
- The Android Keystore will **only** release or authorize the private/secret key upon successful biometric confirmation from the hardware TEE.
- Frida bypass of the callback will fail because the `CryptoObject` remains uninitialized and cannot decrypt the server token.

---

## 5. Hardcoded Secret Extraction & Entropy Analysis

### 5.1 Distinguishing Public Identifiers from Secrets
Senior mobile testers eliminate false positives by distinguishing public metadata from confidential secrets:

| Asset | Sensitivity | Classification | Rule |
|---|---|---|---|
| Firebase Project ID / App ID | Low / Public | INFORMATIONAL | Designed for public client discovery. |
| Google Maps API Key | Low (usually) | INFORMATIONAL | Public by design; verify if restricted by Package Name + SHA1 fingerprint. |
| AWS Access Key / Secret | Critical | REPORTABLE | Direct access to cloud infrastructure; verify permissions with AWS STS. |
| Stripe / Braintree Publishable Key | Low / Public | INFORMATIONAL | Designed to sit on client (`pk_live_...`). |
| Stripe Secret Key (`sk_live_...`) | Critical | REPORTABLE | Allows backend balance transfer / full charge manipulation. |
| Private Signing Keys (RSA/EC) | Critical | REPORTABLE | Found in assets or native binaries; allows token forgery. |

---

## 6. Dynamic Frida Cryptography Logger Hook
Use the senior crypto instrumentation template (`templates/frida/crypto_logger.js`) to:
1. Capture runtime cipher initializations and log actual raw key bytes.
2. Inspect IV parameter uniqueness across multiple encryption rounds.
3. Alert immediately upon detecting ECB mode (`mode === 1 && !params`).
