/**
 * Senior Storage & Android KeyStore Security Audit Hook
 * Standard: OWASP MASVS-STORAGE & MASVS-CRYPTO
 * Target APIs:
 *  - android.content.SharedPreferences$Editor (putString, putBoolean, commit, apply)
 *  - android.database.sqlite.SQLiteDatabase (rawQuery, execSQL, insert, update)
 *  - java.security.KeyStore (getKey, getEntry, setKeyEntry, getCertificate)
 *  - android.content.ClipboardManager (setPrimaryClip)
 * Safe to run: true
 */

Java.perform(function () {
    console.log("[*] [FRIDA_STORAGE] Initializing Senior Storage & KeyStore Audit Hooks...");

    // 1. Audit SharedPreferences Writes for Sensitive Data Leaks
    try {
        var SharedPreferencesEditor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        SharedPreferencesEditor.putString.implementation = function (key, value) {
            var keyLower = (key || "").toLowerCase();
            var valStr = value || "";
            var isSensitive = (
                keyLower.indexOf("token") > -1 ||
                keyLower.indexOf("auth") > -1 ||
                keyLower.indexOf("pass") > -1 ||
                keyLower.indexOf("secret") > -1 ||
                keyLower.indexOf("jwt") > -1 ||
                keyLower.indexOf("key") > -1
            );

            if (isSensitive) {
                console.log("\n[!] [PREFS_LEAK] Sensitive string written to SharedPreferences:");
                console.log("    -> Key:   " + key);
                console.log("    -> Value: " + valStr);
            }
            return this.putString(key, value);
        };
    } catch (err) {}

    // 2. Audit SQLite Database Operations
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        SQLiteDatabase.rawQueryWithFactory.implementation = function (cursorFactory, sql, selectionArgs, editTable, cancellationSignal) {
            if (sql && (sql.toLowerCase().indexOf("user") > -1 || sql.toLowerCase().indexOf("token") > -1 || sql.toLowerCase().indexOf("pass") > -1)) {
                console.log("\n[*] [SQL_QUERY] Database query: " + sql);
            }
            return this.rawQueryWithFactory(cursorFactory, sql, selectionArgs, editTable, cancellationSignal);
        };

        SQLiteDatabase.execSQL.overload("java.lang.String").implementation = function (sql) {
            console.log("[*] [SQL_EXEC] execSQL: " + sql);
            return this.execSQL(sql);
        };
    } catch (err) {}

    // 3. Audit Android KeyStore Operations
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getKey.overload("java.lang.String", "[C").implementation = function (alias, password) {
            console.log("\n[+] [KEYSTORE_ACCESS] KeyStore.getKey(alias='" + alias + "') invoked");
            return this.getKey(alias, password);
        };

        KeyStore.getEntry.overload("java.lang.String", "java.security.KeyStore$ProtectionParameter").implementation = function (alias, param) {
            console.log("\n[+] [KEYSTORE_ACCESS] KeyStore.getEntry(alias='" + alias + "') invoked");
            return this.getEntry(alias, param);
        };
    } catch (err) {}

    // 4. Audit Clipboard Writes
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.setPrimaryClip.implementation = function (clipData) {
            console.log("\n[!] [CLIPBOARD_WRITE] Data written to system clipboard:");
            if (clipData && clipData.getItemCount() > 0) {
                var item = clipData.getItemAt(0);
                var text = item.getText();
                console.log("    -> Content: " + (text ? text.toString() : "null"));
            }
            return this.setPrimaryClip(clipData);
        };
    } catch (err) {}

    console.log("[+] [FRIDA_STORAGE] Storage & KeyStore Hooks Active.");
});
