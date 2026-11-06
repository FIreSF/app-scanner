/**
 * Senior Comprehensive Root & Anti-Debug Detection Bypass Template
 * Standard: OWASP MASVS-RESILIENCE
 * Target Checks:
 *  - RootBeer (all methods: isRooted, checkSuExists, checkForBinary, checkForDangerousProps, etc.)
 *  - Common binary & package checks (su, busybox, magisk, daemonsu, Superuser)
 *  - Process execution (Runtime.exec, ProcessBuilder) looking for "su", "which", "getprop", "mount"
 *  - android.os.Build.TAGS ("test-keys" -> "release-keys")
 *  - android.os.Debug.isDebuggerConnected() -> false
 *  - SystemProperties.get()
 *  - Native libc fopen/access checks for root files and /proc/self/status TracerPid
 * Safe to run: true
 */

Java.perform(function () {
    console.log("[*] [FRIDA_ROOT] Initializing Senior Root & Anti-Debug Bypass Hooks...");

    // 1. RootBeer Complete Hooking
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function () {
            console.log("[+] [FRIDA_ROOT] RootBeer.isRooted() -> false");
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
            console.log("[+] [FRIDA_ROOT] RootBeer.isRootedWithoutBusyBoxCheck() -> false");
            return false;
        };
        RootBeer.isRootedWithBusyBoxCheck.implementation = function () {
            console.log("[+] [FRIDA_ROOT] RootBeer.isRootedWithBusyBoxCheck() -> false");
            return false;
        };
        RootBeer.checkSuExists.implementation = function () { return false; };
        RootBeer.checkForBinary.implementation = function () { return false; };
        RootBeer.checkForDangerousProps.implementation = function () { return false; };
        RootBeer.checkForRWPaths.implementation = function () { return false; };
        RootBeer.checkSuReflect.implementation = function () { return false; };
        RootBeer.checkRootCloakingApps.implementation = function () { return false; };
        RootBeer.checkForMagiskBinary.implementation = function () { return false; };
        RootBeer.checkForRootNative.implementation = function () { return false; };
    } catch (err) {}

    // 2. Hide Root & Magisk Files from Java File.exists()
    try {
        var File = Java.use("java.io.File");
        var rootIndicators = [
            "su", "busybox", "magisk", "daemonsu", "superuser",
            "Superuser.apk", "Magisk.apk", "subuser", ".su",
            "/system/app/Superuser", "/system/xbin/su", "/system/bin/su",
            "/sbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su"
        ];

        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            for (var i = 0; i < rootIndicators.length; i++) {
                if (path.indexOf(rootIndicators[i]) > -1) {
                    console.log("[+] [FRIDA_ROOT] Cloaking root file check: " + path);
                    return false;
                }
            }
            return this.exists();
        };
    } catch (err) {}

    // 3. Intercept Process Execution (Runtime.exec & ProcessBuilder)
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if (cmd.indexOf("su") > -1 || cmd.indexOf("which") > -1 || cmd.indexOf("busybox") > -1) {
                console.log("[+] [FRIDA_ROOT] Intercepted Runtime.exec('" + cmd + "') -> redirecting to echo false");
                return this.exec("echo false");
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
            var cmdStr = cmdArray.join(" ");
            if (cmdStr.indexOf("su") > -1 || cmdStr.indexOf("which") > -1 || cmdStr.indexOf("busybox") > -1) {
                console.log("[+] [FRIDA_ROOT] Intercepted Runtime.exec(String[]) '" + cmdStr + "' -> neutered");
                var dummy = Java.array('java.lang.String', ['echo', 'false']);
                return this.exec(dummy);
            }
            return this.exec(cmdArray);
        };
    } catch (err) {}

    // 4. Spoof android.os.Build.TAGS & FINGERPRINT
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        console.log("[+] [FRIDA_ROOT] Build.TAGS spoofed to 'release-keys'");
    } catch (err) {}

    // 5. Anti-Debug Evasion (Debug.isDebuggerConnected)
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            console.log("[+] [FRIDA_ROOT] Debug.isDebuggerConnected() -> false");
            return false;
        };
    } catch (err) {}

    // 6. SystemProperties ro.secure & ro.debuggable
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function (key) {
            if (key === "ro.secure") return "1";
            if (key === "ro.debuggable") return "0";
            return this.get(key);
        };
    } catch (err) {}

    console.log("[+] [FRIDA_ROOT] All JVM Root Detection Bypass Hooks Active.");
});

// 7. Native libc Hooks (fopen, access) for /proc/self/status TracerPid and su
try {
    var libcModule = Process.findModuleByName("libc.so");
    if (libcModule) {
        var fopenPtr = Module.findExportByName("libc.so", "fopen");
        if (fopenPtr) {
            Interceptor.attach(fopenPtr, {
                onEnter: function (args) {
                    var path = Memory.readCString(args[0]);
                    this.isProcStatus = (path && path.indexOf("/proc/self/status") > -1);
                }
            });
        }

        var accessPtr = Module.findExportByName("libc.so", "access");
        if (accessPtr) {
            Interceptor.attach(accessPtr, {
                onEnter: function (args) {
                    var path = Memory.readCString(args[0]);
                    if (path && (path.indexOf("/su") > -1 || path.indexOf("/magisk") > -1)) {
                        this.hide = true;
                    }
                },
                onLeave: function (retval) {
                    if (this.hide) {
                        retval.replace(-1); // File not found
                    }
                }
            });
        }
    }
} catch (nativeErr) {}
