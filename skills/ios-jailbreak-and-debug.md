---
name: IOS Jailbreak And Debug
description: Use when testing iOS jailbreak detection, anti-debug, and instrumentation defences.
---

# iOS jailbreak & anti-debug checks (ios-jailbreak-and-debug.md)
**Standard:** OWASP MASVS-RESILIENCE
**Audience:** Mobile penetration testers & ios agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
Missing or bypassable jailbreak/anti-debug checks let attackers instrument the app freely.

---

## 2. Test steps
1. Audit for jailbreak indicators: `/bin/bash`, `/usr/sbin/sshd`, Cydia, `fork()` success, suspicious URL schemes (`cydia://`), dyld injection checks.
2. Anti-debug: `ptrace(PT_DENY_ATTACH)`, `sysctl` P_TRACED checks — verify they actually run before sensitive flows (not dead code).
3. Dynamic: Frida bypass hooks for each check; confirm the app proceeds to sensitive functionality post-bypass (impact proof, not just bypass).
4. Note: jailbreak detection is defense-in-depth — report as such unless tied to a concrete bypass of a security control.

---

## 3. False-positive notes
- Bypassable jailbreak check with no sensitive functionality behind it = hardening note.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-RESILIENCE; MASTG iOS resilience tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
