# MASVS-CODE CHECKLIST (memory/targets/code.md)

1. [ ] Third-Party Library Inventory: map dependencies in `library-inventory.json` and query MCP vulnerability feeds.
2. [ ] Debuggable Flag: verify `android:debuggable="false"` in release builds.
3. [ ] Memory Corruption in Native Libraries: audit JNI methods and C/C++ native libs (`.so`/`.dylib`) for unsafe string manipulation (`strcpy`, `sprintf`).
4. [ ] Hardcoded Secrets: scan source tree for high-entropy strings, AWS/GCP tokens, private keys.
5. [ ] Obfuscation: verify R8/ProGuard/DexGuard class and symbol name mangling.
