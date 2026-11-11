---
name: Storage Data At Rest
description: Use when auditing data at rest: SharedPreferences, internal and external storage, databases, backups, clipboard.
---

# STORAGE & DATA-AT-REST SECURITY AUDITING (skills/storage-data-at-rest.md)
**Standard:** OWASP MASVS-STORAGE | Android Local Storage & iOS Data Protection  
**Audience:** Senior Mobile Penetration Testers & Storage Analysis Agents  

---

## 1. Storage Attack Surface & Data Leakage Vectors
Data stored locally on mobile devices can be accessed through physical device access, backup extraction, malware sharing the same storage card, or unauthorized inter-app sharing.

```
Application Sandbox (/data/data/<pkg>/ or iOS Container)
 ├── shared_prefs/        -> XML files (tokens, flags, credentials)
 ├── databases/           -> SQLite / Room / Realm (user messages, cache)
 ├── files/ & cache/      -> Temporary downloads, PDF exports, images
 └── External Storage     -> /sdcard/Android/data/<pkg>/ (shared media)
```

---

## 2. Insecure Data Storage in SharedPreferences & Property Lists

### 2.1 Android SharedPreferences
- Located at `/data/data/<package_name>/shared_prefs/*.xml`.
- **High-Risk Items:**
  - Plaintext authentication tokens, OAuth refresh tokens, session JWTs.
  - Plaintext passwords, PINs, or biometric bypass flags (`"is_biometric_enabled": true`).
  - Sensitive PII (Social Security Numbers, credit card numbers, email, physical addresses).
- **Audit Command via ADB:**
```bash
adb shell "su -c 'cat /data/data/com.target.app/shared_prefs/*.xml'"
```

### 2.2 iOS `NSUserDefaults` & Property Lists (`.plist`)
- Located inside `<App_Container>/Library/Preferences/<bundle_id>.plist`.
- `NSUserDefaults` is **never encrypted**. It is intended strictly for user preferences (UI theme, locale). Sensitive credentials stored here violate MASVS-STORAGE-1.

---

## 3. SQLite, Room, Realm & Unencrypted Databases

### 3.1 Plaintext Database Inspection
Many applications store local user history, messages, cached API responses, and authentication credentials inside SQLite databases:
```bash
# Locate and inspect databases
adb shell "su -c 'ls -la /data/data/com.target.app/databases/'"
adb shell "su -c 'sqlite3 /data/data/com.target.app/databases/app.db .dump'"
```

### 3.2 SQLCipher & Hardcoded Key Misuse
When SQLCipher is utilized:
- Audit where the encryption passphrase originates.
- **Common Vulnerability:** The passphrase is hardcoded in Java or native `.so` files:
  `SQLiteDatabase.openOrCreateDatabase(dbFile, "STATIC_HARDCODED_PASSPHRASE_12345", null);`
- **Dynamic Key Extraction via Frida:** Hook SQLCipher `openOrCreateDatabase` or `net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase` to dump the encryption key at runtime.

---

## 4. Android Backup Vulnerability (`android:allowBackup="true"`)

### 4.1 Exploitation Workflow
If `android:allowBackup="true"` is enabled in `AndroidManifest.xml` (the Android default if unspecified) and no restrictive `fullBackupContent` rules exist:
1. Connect device via ADB:
```bash
adb backup -f backup.ab -noapk com.target.app
```
2. Unpack the Android backup using standard tools:
```bash
# Convert Android Backup (.ab) to tar archive
( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 backup.ab ) | tar xfvz -
```
3. Inspect unpacked files for active session cookies, JWTs, and private databases.
4. **False Positive Prevention:** `allowBackup` is only reportable as a vulnerability if sensitive session tokens, private encryption keys, or sensitive PII are extracted from the resulting archive. If the app excludes sensitive directories via `backup_rules.xml` or only non-sensitive UI settings are backed up, downgrade to INFORMATIONAL.

---

## 5. System Logs, Crash Dumps & Logcat Leakage

### 5.1 Android Logcat Exposure
- Applications must never log sensitive information (tokens, authorization headers, credit card data, passwords) via `android.util.Log` (`Log.d`, `Log.i`, `Log.v`, `Log.e`).
- While Android 4.1+ restricts logcat reading from other non-root applications, logs can be read:
  - By desktop machines connected via USB debugging.
  - By third-party crash reporting SDKs (Sentry, Crashlytics, Firebase Crashlytics) if uncaught exceptions include full HTTP headers or payloads.
- **Inspection Command:**
```bash
adb logcat -d | grep -iE "token|bearer|auth|password|secret|session"
```

---

## 6. Clipboard Exposure & Background Screenshot Caching

### 6.1 Clipboard Leakage (`ClipboardManager`)
- If sensitive data (one-time passwords, credit card numbers, recovery seeds) is copied to the system clipboard, any foreground app can monitor and read clipboard contents without special permissions on Android < 10, and foreground apps on Android 10+.
- Recommended defense: `ClipDescription.FLAG_IS_SENSITIVE` on Android 13+.

### 6.2 Screen Caching & Task Switcher Snapshots
- When an application transitions to the background, the operating system takes a screenshot of the current screen to display in the task switcher.
- If the screen contains bank account numbers, medical data, or sensitive PII, this image is cached on disk.
- Recommended defense: `getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);`
