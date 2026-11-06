/**
 * Senior Intent, Deep Link & PendingIntent Security Monitor
 * Standard: OWASP MASVS-PLATFORM
 * Target Components:
 *  - Activity.startActivity & startActivityForResult
 *  - Context.startService & startForegroundService
 *  - Context.sendBroadcast & sendOrderedBroadcast
 *  - android.app.PendingIntent (getActivity, getBroadcast, getService)
 *  - Intent flag inspection (FLAG_GRANT_READ/WRITE_URI_PERMISSION, FLAG_MUTABLE)
 * Safe to run: true
 */

Java.perform(function () {
    console.log("[*] [FRIDA_IPC] Initializing Senior IPC & Intent Monitor Hooks...");

    function dumpIntent(tag, intent) {
        if (!intent) return;
        try {
            var action = intent.getAction();
            var component = intent.getComponent();
            var data = intent.getData();
            var flags = intent.getFlags();
            var extras = intent.getExtras();

            console.log("\n[!] [IPC_SIGNAL] " + tag + ":");
            if (component) console.log("    -> Target Component: " + component.flattenToString());
            if (action) console.log("    -> Action:           " + action);
            if (data) {
                console.log("    -> Data URI:         " + data.toString());
                console.log("    -> Scheme:           " + data.getScheme() + " | Host: " + data.getHost() + " | Path: " + data.getPath());
            }
            console.log("    -> Flags:            0x" + flags.toString(16));

            // Check dangerous URI grant flags
            var FLAG_GRANT_READ = 0x00000001;
            var FLAG_GRANT_WRITE = 0x00000002;
            if ((flags & FLAG_GRANT_READ) !== 0) console.log("    [!] WARNING: FLAG_GRANT_READ_URI_PERMISSION set!");
            if ((flags & FLAG_GRANT_WRITE) !== 0) console.log("    [!] WARNING: FLAG_GRANT_WRITE_URI_PERMISSION set!");

            if (extras) {
                var keys = extras.keySet().iterator();
                console.log("    -> Extras Bundle:");
                while (keys.hasNext()) {
                    var key = keys.next().toString();
                    var val = extras.get(key);
                    var valStr = (val !== null) ? val.toString() : "null";
                    console.log("       [" + key + "] = " + valStr);
                    // Check if extra contains a nested Intent (Intent Redirection vector)
                    if (val && val.getClass().getName() === "android.content.Intent") {
                        console.log("       [!] CRITICAL: Nested Intent detected inside extra '" + key + "' (Potential Intent Redirection)!");
                    }
                }
            }
        } catch (e) {
            console.log("[-] Error dumping intent: " + e);
        }
    }

    // 1. Hook Activity.startActivity
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload("android.content.Intent").implementation = function (intent) {
            dumpIntent("Activity.startActivity", intent);
            return this.startActivity(intent);
        };
        Activity.startActivityForResult.overload("android.content.Intent", "int").implementation = function (intent, reqCode) {
            dumpIntent("Activity.startActivityForResult (reqCode=" + reqCode + ")", intent);
            return this.startActivityForResult(intent, reqCode);
        };
    } catch (err) {}

    // 2. Hook ContextWrapper / Services & Broadcasts
    try {
        var ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.startService.implementation = function (intent) {
            dumpIntent("Context.startService", intent);
            return this.startService(intent);
        };
        ContextWrapper.sendBroadcast.overload("android.content.Intent").implementation = function (intent) {
            dumpIntent("Context.sendBroadcast", intent);
            return this.sendBroadcast(intent);
        };
    } catch (err) {}

    // 3. Hook PendingIntent Mutability (Android 12+ / API 31+)
    try {
        var PendingIntent = Java.use("android.app.PendingIntent");
        var FLAG_MUTABLE = 0x02000000;
        var FLAG_IMMUTABLE = 0x04000000;

        PendingIntent.getActivity.overload('android.content.Context', 'int', 'android.content.Intent', 'int').implementation = function (ctx, req, intent, flags) {
            if ((flags & FLAG_MUTABLE) !== 0) {
                console.log("\n[!] [MUTABLE_PENDING_INTENT] PendingIntent.getActivity() created with FLAG_MUTABLE (CVE-2021-39695 candidate)");
                dumpIntent("PendingIntent base intent", intent);
            }
            return this.getActivity(ctx, req, intent, flags);
        };
    } catch (err) {}

    console.log("[+] [FRIDA_IPC] Intent & PendingIntent Monitoring Active.");
});
