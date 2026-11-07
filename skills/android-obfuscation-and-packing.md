# Obfuscation, packing & string encryption (android-obfuscation-and-packing.md)
**Standard:** OWASP MASVS-RESILIENCE / MASVS-CODE
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Obfuscation/packing raises the bar but is bypassed at runtime — test the runtime, not the packaging.

---

## 2. Test steps
1. Inventory: ProGuard/R8 status, DexGuard/other packers, encrypted strings/assets, native `.so` obfuscation (check `lib/` with radare2).
2. Runtime defeats: Frida `enumerateLoadedClasses`, string-decryption hooks (`decrypt`/`decode` functions), dump decrypted DEX in memory (Frida DEX dump).
3. Check whether secrets survive in decrypted runtime memory even when static strings are encrypted.
4. Packers that block Frida: hook anti-Frida checks first (see frida-lab-and-runtime), then dump.

---

## 3. False-positive notes
- Obfuscation present but runtime secrets readable = finding is the secret exposure, not 'weak obfuscation'.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-RESILIENCE / MASVS-CODE; MASTG resilience tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
