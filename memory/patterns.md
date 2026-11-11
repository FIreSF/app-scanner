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

## 5. Frida Lab & Runtime Pitfalls (Medium writeup batch, 2025–2026)
Distilled from 10 public Medium mobile-pentest writeups (see `writeups/processed/`).

- **Pattern:** frida-server ABI/version mismatch (`getprop ro.product.cpu.abi` / `ro.system.product.cpu.abilist` not checked before download; host frida != server version).
- **Impact:** frida-server never starts; tester misreports "Frida setup failed" or misses dynamic bugs entirely.
- **Proof / prevention:** check ABI + `frida --version` first; pin `frida` + `frida-tools` + `objection` together (Objection tracks latest Frida; drift breaks Objection); health-check `frida-ps -Uai` before hooking.

- **Pattern:** User CA installed, then "no HTTPS interception" reported without trying a Frida pinning hook; or CA install claimed as a pinning bypass.
- **Impact:** False negative (missed API/transport bugs) or false positive (claimed bypass with no traffic).
- **Proof:** Android 7+ `networkSecurityConfig` often ignores user CAs; verify interception in a browser first, then hook pinning APIs (`TrustManagerImpl.verifyChain`, `validatePin`, OkHttp `CertificatePinner`), then confirm pinned HTTPS in Burp/mitmproxy history.

- **Pattern:** `objection android sslpinning disable` fails, reported as "custom pinning".
- **Impact:** False positive — failure is usually missing proxy CA, wrong package name, or stale session.
- **Proof:** re-check prerequisites (device, arch-matching server, package, proxy CA, app restart) before concluding custom pinning.

- **Pattern:** Attaching Frida after launch (`-n`) to catch startup root/pin checks; hook floods on `String.equals` / `Cipher.doFinal`.
- **Impact:** Missed early checks (false negative) or output flood hiding real signals.
- **Proof:** spawn (`frida -U -f <pkg> -l script.js --no-pause`) by default; filter high-frequency hooks by length/pattern or hex-to-UTF-8 gating; hook shape = log args -> call original -> modify return.

- **Pattern:** Blindly copying example class names from writeups (`RootChecker`, `TransactionManager`) without static recon.
- **Impact:** Hooks silently no-op; dynamic bugs missed.
- **Proof:** jadx/apktool first to find real FQCNs; if one bypass fails, stack-trace trace it and enumerate classes matching `root|detect|tamper|jailbreak` instead of guessing.

## 6. Flutter Exported Proxy + Route Extra Injection (XP Investimentos br.com.xp.carteira, 2026-11)
- **Pattern:** Exported proxy activity (`DeepLinkActivity`) does explicit `new Intent(this, MainActivity.class)` + `setData(uri)` + `putExtras(all)` with NO allow-list, and `MainActivity extends FlutterFragmentActivity` with exported `getInitialRoute()` returning extra `route` verbatim. Custom scheme `appxpinvestimentos://` 30+ hosts, no permission, `flutter_deeplinking_enabled=false` does NOT block the extra path.
- **Impact:** Any installed app controls the Dart initial route / deep-link-of-choice (Medium deception primitive). Escalates to auth bypass or WebView exposure ONLY if Dart honors valid routes / `?url=` without whitelist — requires seeded account to prove.
- **Proof:** `am start -a VIEW -d "appxpinvestimentos://flutter" --es route "/IPC" <pkg>` + `am start -n <pkg>/.MainActivity --es route "/x"` on clean state 3x; require dumpsys `has extras` + logcat paired START. Unknown-route fallback does NOT falsify the finding; record as native-only CONFIRMED.
- **FP trap:** Do NOT report as intent redirection (destination hard-coded) or WebView XSS without Dart `libapp.so` proof.
- **Reuse (proven):** Same shell found again in `br.com.xpinc.clear.app.android` v5.9.0 (scheme `appclear://`, same hosts) in minutes — check `exported=true` MainActivity + DeepLinkActivity → `putExtras` → `getInitialRoute`. Expect it across the XP family (`br.com.xp.carteira`, `br.com.xpinc.clear.app.android`, `br.com.xpinc.xpempresas`). Obfuscated jadx name hides it (`IconCompatParcelizer`, not `read()`): match by structure `new Intent(this, MainActivity.class)` + `setData` + `putExtras` + `startActivity`, not by method name. Proof set that convinces triagers = 4 shots: annotated red-box picture (02) + real jadx screenshot (05) + manifest/how-we-found (03) + logcat paired START (04) (+ app UI 01). Do not add more.
