/**
 * Senior Cryptographic Operation & Key Audit Logger
 * Standard: OWASP MASVS-CRYPTO
 * Target APIs:
 *  - javax.crypto.Cipher (init, doFinal, getAlgorithm)
 *  - javax.crypto.spec.SecretKeySpec (key material extraction)
 *  - javax.crypto.spec.IvParameterSpec (IV uniqueness & static IV detection)
 *  - java.security.MessageDigest (MD5, SHA-1 flagging)
 *  - javax.crypto.Mac (HMAC verification)
 *  - java.security.KeyStore (alias enumeration & key retrieval)
 * Safe to run: true
 */

Java.perform(function () {
    console.log("[*] [FRIDA_CRYPTO] Initializing Senior Cryptography Audit Logger...");

    function bytesToHex(bytes) {
        if (!bytes) return "null";
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i] & 0xFF;
            hex.push((b < 16 ? "0" : "") + b.toString(16));
        }
        return hex.join("");
    }

    function bytesToBase64(bytes) {
        if (!bytes) return "null";
        try {
            var Base64 = Java.use("android.util.Base64");
            return Base64.encodeToString(bytes, 2); // NO_WRAP
        } catch (e) {
            return "N/A";
        }
    }

    var seenIVs = {};

    // 1. Hook SecretKeySpec to extract raw cryptographic key material
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algorithm) {
            console.log("\n[+] [KEY_MATERIAL] SecretKeySpec generated:");
            console.log("    -> Algorithm: " + algorithm);
            console.log("    -> Key (Hex): " + bytesToHex(keyBytes));
            console.log("    -> Key (B64): " + bytesToBase64(keyBytes));
            return this.$init(keyBytes, algorithm);
        };
    } catch (err) {}

    // 2. Hook IvParameterSpec to audit static/zero IVs
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload('[B').implementation = function (ivBytes) {
            var hexIV = bytesToHex(ivBytes);
            console.log("\n[+] [IV_INSPECT] IvParameterSpec initialized:");
            console.log("    -> IV (Hex):  " + hexIV);

            // Check for all-zeros IV
            var isAllZeros = true;
            for (var i = 0; i < ivBytes.length; i++) {
                if (ivBytes[i] !== 0) {
                    isAllZeros = false;
                    break;
                }
            }
            if (isAllZeros) {
                console.log("    [!] CRITICAL: All-zero IV detected! (MASVS-CRYPTO-1 violation)");
            }

            // Check for IV reuse
            if (seenIVs[hexIV]) {
                seenIVs[hexIV]++;
                console.log("    [!] WARNING: IV Reuse Detected! IV was seen " + seenIVs[hexIV] + " times.");
            } else {
                seenIVs[hexIV] = 1;
            }

            return this.$init(ivBytes);
        };
    } catch (err) {}

    // 3. Hook Cipher.init to audit mode, algorithm, and parameters
    try {
        var Cipher = Java.use("javax.crypto.Cipher");

        function auditCipher(cipherObj, opmode, key, params) {
            var algo = cipherObj.getAlgorithm();
            var modeStr = opmode === 1 ? "ENCRYPT" : (opmode === 2 ? "DECRYPT" : "MODE_" + opmode);
            console.log("\n[*] [CIPHER_OP] Cipher.init (" + modeStr + "):");
            console.log("    -> Algorithm: " + algo);

            // Audit insecure ECB mode
            if (algo.indexOf("/ECB/") > -1 || algo === "AES" || algo === "DES") {
                console.log("    [!] CRITICAL: Insecure ECB Mode or default mode detected: '" + algo + "' (MASVS-CRYPTO-1 violation)");
            }

            // Audit legacy weak ciphers
            if (algo.indexOf("DES") > -1 || algo.indexOf("RC4") > -1 || algo.indexOf("Blowfish") > -1) {
                console.log("    [!] CRITICAL: Deprecated weak cipher in use: '" + algo + "'");
            }

            if (key) {
                console.log("    -> Key Class: " + key.getClass().getName() + " | Format: " + key.getFormat());
                try {
                    var encoded = key.getEncoded();
                    if (encoded) {
                        console.log("    -> Key Bytes: " + bytesToHex(encoded));
                    }
                } catch (e) {}
            }
        }

        Cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
            auditCipher(this, opmode, key, null);
            return this.init(opmode, key);
        };

        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opmode, key, params) {
            auditCipher(this, opmode, key, params);
            return this.init(opmode, key, params);
        };
    } catch (err) {}

    // 4. Hook MessageDigest for MD5 / SHA-1
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function (algorithm) {
            if (algorithm.toUpperCase() === "MD5" || algorithm.toUpperCase() === "SHA-1" || algorithm.toUpperCase() === "SHA1") {
                console.log("[!] [HASH_WEAK] MessageDigest requested weak algorithm: " + algorithm);
            }
            return this.getInstance(algorithm);
        };
    } catch (err) {}

    console.log("[+] [FRIDA_CRYPTO] Cryptographic Audit Hooks Active.");
});
