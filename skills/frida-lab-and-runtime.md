# FRIDA LAB SETUP & RUNTIME BYPASS PLAYBOOK (skills/frida-lab-and-runtime.md)
**Standard:** OWASP MASVS-RESILIENCE / MASVS-NETWORK | Android dynamic analysis
**Audience:** frida-script-agent, dynamic-agent, root-device-agent, emulator-agent

Distilled from 10 public Medium mobile-pentest writeups (2023–2026); see `writeups/processed/`.
Use only on owned or explicitly authorized devices/emulators and target apps.

---

## 1. Lab setup order (never skip steps)

1. **ABI + version check first**
   - `adb shell getprop ro.product.cpu.abi` (and `ro.system.product.cpu.abilist`)
   - `frida --version`; download the **matching** `frida-server-<ver>-android-<abi>.xz`
   - Pin `frida` + `frida-tools` + `objection` together; record versions (`pip3 show`).
2. **Push server:** `adb push frida-server /data/local/tmp/` → `chmod 755` → run `su -c` / background.
3. **Health-check:** `frida-ps -Uai` — distinguishes server/connectivity failure from app failure.
4. **Proxy + CA:** Burp/mitmproxy listener on host IPv4:8080; export CA (`.cer`, DER); install on
   device (Settings → Install Certificate; verify under Trusted Credentials).
   Set Wi-Fi/manual proxy or `settings put global http_proxy <host>:8080`; verify HTTPS in the
   **browser** before testing the app. Reset proxy (`:0`) when done.
5. **Snapshots:** golden AVD image + isolated network; log tool versions for reproducibility.

## 2. SSL pinning bypass

- `objection --gadget <package> explore` → `android sslpinning disable` (try first).
- If it fails: **do not report custom pinning yet** — re-check proxy CA, package name, stale session.
- Custom per-app hook: reverse the pinning implementation in jadx, then hook
  `TrustManagerImpl.verifyChain`, `validatePin`, OkHttp `CertificatePinner`, `RealCall.execute`,
  `URL.openConnection`. Confirm pinned HTTPS appears in proxy history.
- Android 7+ `networkSecurityConfig` may ignore user CAs — CA install alone is **not** a bypass.

## 3. Root / Frida detection bypass

- Map detection in decompiled code first (files, processes, ports, `su`/Magisk, build props,
  bootloader/ROM checks). No hook without a mapped Java-layer check = dead end, not a clean app.
- Hook detection functions (`RootBeer.isRooted`, `File.exists`, `Runtime.exec`) with the
  log-args → call-original → modify-return shape. Spawn (`-f`) so startup checks are caught.
- Failover: stack-trace trace + enumerate classes matching `root|detect|tamper|jailbreak`.
- Emulator root indicators alone are **not** a finding (see `memory/FALSE_POSITIVE_DB.md`).

## 4. Hook hygiene

- Spawn (`frida -U -f <pkg> -l script.js --no-pause`) by default for startup/root/pin checks;
  attaching after launch misses early code.
- Filter high-frequency hooks (`String.equals`, `Cipher.init/doFinal`) by length/pattern or
  hex-to-UTF-8 gating; keep scripts modular, logged, and versioned.
- Never copy example class names from writeups blindly — jadx/apktool recon first.
- Aggressive native hooks cause crashes/anti-Frida triggers: test isolated, one hook at a time.

## 5. Crypto / storage / auth runtime signals

- Hook `Cipher.init/doFinal` to dump AES keys/data; `Java.choose` / `enumerateLoadedClasses`
  to find hidden methods; `String.equals` for hardcoded credential compares (filtered).
- Log OkHttp `newCall` URL/body to expose sensitive API params/tokens in memory.
- Every runtime claim needs evidence: exact Frida CLI + script name, baseline vs manipulated
  output, and independent verification before REPORTABLE (see `AGENTS.md` §3–4).
