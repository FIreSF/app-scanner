# RESILIENCE, ANTI-TAMPERING & REVERSE ENGINEERING AUDITING (skills/resilience-antitamper.md)
**Standard:** OWASP MASVS-RESILIENCE | Android & iOS Anti-Analysis  
**Audience:** Senior Mobile Penetration Testers & Resilience Agents  

---

## 1. Resilience Philosophy in Senior Penetration Testing
MASVS-RESILIENCE defines defense-in-depth controls intended to impede reverse engineering and dynamic tampering.
**Senior Golden Rule:** Bypassing root detection, jailbreak checks, or anti-Frida is a *means to an end*, not a standalone vulnerability. Client-side anti-tamper bypass is only reportable when it directly enables an attack that breaches a security boundary or violates program compliance rules.

---

## 2. Root & Jailbreak Detection Mechanisms and Bypasses

### 2.1 Common Android Root Signals
Detection frameworks (e.g. RootBeer, custom SDKs) inspect:
1. **Root Binaries & Packages:** Existence of `su`, `busybox`, `daemonsu`, `magisk`, `Superuser.apk`.
2. **Directory Permissions:** Testing write permissions on system directories (`/system`, `/system/bin`, `/vendor/bin`).
3. **Build Tags:** Checking `android.os.Build.TAGS` for `"test-keys"` instead of `"release-keys"`.
4. **Command Execution:** Spawning processes via `Runtime.getRuntime().exec("su")` or `which su`.
5. **Mount Inspection:** Reading `/proc/mounts` looking for `rw` remounts of `/system` or presence of Magisk overlayfs.
6. **Magisk Props:** Checking system properties via `getprop` (e.g., `ro.debuggable`, `ro.secure`).

### 2.2 Evasion Techniques
- Use modern Magisk Zygisk DenyList / Shamiko / KernelSU module isolation.
- Inject surgical Frida hooks (`templates/frida/root_detection_bypass.js`) to intercept:
  - `java.io.File.exists()`
  - `java.lang.Runtime.exec()`
  - `java.lang.ProcessBuilder.start()`
  - `com.scottyab.rootbeer.RootBeer.*`
  - Native libc `fopen`, `access`, `stat`.

---

## 3. Anti-Debugging & Tracer Evasion

### 3.1 Ptrace Anti-Debugging
Native libraries often invoke `ptrace(PTRACE_TRACEME, 0, 1, 0)` upon startup:
- Linux only permits one debugger/tracer to attach to a process at a time.
- If an app calls `ptrace` on itself, subsequent `gdb` or `lldb` attachment fails.
- **Bypass Hook (libc.so):**
```javascript
Interceptor.attach(Module.findExportByName("libc.so", "ptrace"), {
    onEnter: function(args) {
        var request = args[0].toInt32();
        if (request === 0) { // PTRACE_TRACEME
            console.log("[+] [RESILIENCE] Neutralized ptrace(PTRACE_TRACEME)");
            this.bypass = true;
        }
    },
    onLeave: function(retval) {
        if (this.bypass) {
            retval.replace(0);
        }
    }
});
```

### 3.2 `/proc/self/status` TracerPid Monitoring
Applications spawn watchdog threads reading `/proc/self/status` looking for `TracerPid != 0`:
- **Bypass Hook:** Intercept `fopen` or `read` on `/proc/self/status` and replace the `TracerPid` line with `TracerPid: 0`.

---

## 4. Anti-Frida Detection Techniques

### 4.1 Frida Detection Vectors
Advanced anti-tamper SDKs detect Frida through:
1. **TCP Port Probing:** Scanning local port `27042` (default `frida-server` port).
2. **Named Pipe Scanning:** Scanning `/proc/self/fd/` for pipes containing `frida` or `linjector`.
3. **Memory Map Inspection:** Reading `/proc/self/maps` looking for loaded libraries (`frida-agent.so`, `frida-gadget.so`) or anonymous executable memory regions (`rwx`).
4. **Thread Name Enumeration:** Enumerating active pthreads for `gmain`, `gdbus`, `gum-js-loop`.
5. **D-Bus Protocol Probing:** Sending D-Bus AUTH requests to open ports.

### 4.2 Frida Stealth Countermeasures
- Rename `frida-server` binary to a benign system process name (e.g., `syslogd`).
- Run `frida-server` on a non-standard port or Unix domain socket:
  `./frida-server -l 127.0.0.1:49152 &`
- Intercept native string comparisons (`strstr`) in memory scanning routines to hide strings matching `"frida"`, `"gadget"`, or `"gum"`.

---

## 5. Code Obfuscation & Dynamic Integrity Verification

### 5.1 Obfuscation Evaluation
- Inspect decompiled DEX: Are class, method, and variable names renamed (ProGuard / R8 / DexGuard)?
- Are sensitive string constants encrypted or dynamically decrypted via string unflattening routines?
- Native code: Are control-flow flattening, instruction substitution, and symbol stripping applied?

### 5.2 Signature & Package Integrity Checks
- Many apps verify their own signing certificate at runtime using `PackageManager.getPackageInfo(..., PackageManager.GET_SIGNATURES)`.
- **Bypass:** Hook `PackageManager.getPackageInfo` to return the original production SHA-256 certificate byte array even when running a modified re-signed APK.
