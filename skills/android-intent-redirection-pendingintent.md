---
name: Android Intent Redirection Pendingintent
description: Use when testing intent redirection, PendingIntent mutability, and pending-intent hijacking to reach internal components.
---

# Intent redirection & PendingIntent mutability (android-intent-redirection-pendingintent.md)
**Standard:** OWASP MASVS-PLATFORM
**Audience:** Mobile penetration testers & android agents
**Sources:** OWASP MASTG/MASVS, MobSF checks, Objection/frida-scripts techniques (see `writeups/`)

---

## 1. Threat model
PendingIntent/intent-forwarding flaws let attackers act with the victim app's identity.

---

## 2. Test steps
1. Find `PendingIntent.getActivity/getService/getBroadcast` with `FLAG_MUTABLE` (API 31+ requires explicit mutability; mutable + intent fill-in = hijack).
2. Find exported components that call `startActivity/startService/sendBroadcast` on an Intent taken from extras without validation.
3. Dynamic: send a crafted intent via adb/drozer with a nested intent extra targeting an unexported component; observe whether it launches.
4. Frida: hook `Activity.startActivity` / `PendingIntent.send` and log intents in transit.

---

## 3. False-positive notes
- An exported LAUNCHER activity with MAIN action is expected (see FALSE_POSITIVE_DB); redirection through it is not.

---

## 4. Evidence standard
Every claim needs: target package/version + artifact SHA-256, baseline vs manipulated proof with
unique markers, exact reproduction commands (adb/Frida/curl), and independent verification before
REPORTABLE (see `AGENTS.md` §3–4). Cite MASVS-PLATFORM; OWASP MASTG intent-redirection tests.

---

## 5. Remediation guidance
- Fix the root cause at the platform/API level (not just client-side checks).
- Re-test with the same steps above and record the after-state in `notes/tested-variants.md`.
