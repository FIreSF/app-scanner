# MASVS-RESILIENCE CHECKLIST (memory/targets/resilience.md)

1. [ ] Root / Jailbreak Detection: verify presence of detection routines (RootBeer, `which su`, Magisk path checks, test-keys).
2. [ ] Anti-Debugging: check for `ptrace(PTRACE_TRACEME)` or `android.os.Debug.isDebuggerConnected()`.
3. [ ] Anti-Frida / Hooking Detection: check for listening port 27042, `/proc/self/maps` scanning for `frida-agent.so`.
4. [ ] Binary Integrity: check if the app calculates APK signature hashes or checksums at runtime.
5. [ ] Bypass Resilience: assess whether hooks in `frida-script-agent` neutralize protections trivially or require native patching.
