---
name: Master Bugbounty Rules
description: Master rules of engagement for mobile bug-bounty and pentest runs: authorization, scope, evidence standards, and reporting.
---

# MASTER MOBILE BUG BOUNTY & PENETRATION TESTING RULES OF ENGAGEMENT
**Document:** `skills/master-bugbounty-rules.md`  
**Version:** 2.0.0 | **Standard:** OWASP MASVS v2.0 / MASTG / Bug Bounty Safe Harbor  
**Target Audience:** Senior Mobile Penetration Testers (10+ Years Experience) & Autonomous Orchestrators  

---

## 1. Core Principles & Non-Negotiables

### 1.1 Scope Absolute & Target Authorization
- **Strict Scope Boundaries:** Test **only** the application package name, bundle identifier, native binaries, and API endpoints explicitly specified in the engagement scope or bug bounty policy.
- **Out-of-Scope Isolation:** Never inspect, hook, or send traffic to third-party endpoints (e.g., analytics SDKs, ad networks, CDNs, external payment gateways) unless specifically listed in scope.
- **Device Ownership:** Dynamic testing must occur strictly on user-owned physical devices (rooted via Magisk/KernelSU with documented revert paths) or dedicated isolated emulators (AVD, Corellium, Genymotion).
- **Environment Containment:** Testing artifacts, Frida scripts, memory dumps, SQLite databases, and decompiled code must remain exclusively in the localized session directory `testing/<app-package>/`. Never leak target artifacts to external AI services or cloud repositories.

### 1.2 Data Integrity, Privacy & Synthetic Account Rules
- **No Real User PII Exfiltration:** Never access, view, extract, or tamper with data belonging to other users, employees, or customers.
- **Cross-Account / Multi-Tenant Isolation:**
  - For authorization flaws, IDOR, cross-tenant leaks, or privilege escalation, register **at least two distinct test accounts** owned by the operator (e.g., `User_A` and `User_B`).
  - Demonstrate unauthorized access strictly by accessing `User_B`'s seeded resources using `User_A`'s authenticated session.
  - Never execute cross-account modifications against unknown or production user IDs.
- **Non-Destructive Testing:**
  - Strictly prohibit denial-of-service (DoS), rate-limit exhaustion flooding, thread exhaustion, or massive battery-draining loops on user devices or backend services.
  - Never permanently delete, overwrite, or corrupt server-side records. If state manipulation is required to prove a vulnerability, test in a sandbox/staging environment or create synthetic entities with an explicit rollback mechanism.

---

## 2. Senior Mobile Pentesting Methodology (The 8-Phase Hunt)

```
[Phase 0: Intake & Scope Lock]
      │
      ▼
[Phase 1: Static Architecture & Attack Surface Mapping]
      │
      ▼
[Phase 2: Dependency Intel & Known CVE Reachability]
      │
      ▼
[Phase 3: Targeted Instrumentation & Bypass Engineering]
      │
      ▼
[Phase 4: Runtime Dynamic Exploration & Deep Protocol Analysis]
      │
      ▼
[Phase 5: High-Confidence Lead Weaponization & Safe PoC]
      │
      ▼
[Phase 6: Adversarial Verification & Hard False-Positive Filter]
      │
      ▼
[Phase 7: MASVS Coverage & Compliance Gap Auditing]
      │
      ▼
[Phase 8: High-Signal Triager-Ready Reporting]
```

### Phase 1: Static Architecture & Attack Surface Mapping
- **Signature & Manifest Triage:** Verify APK/AAB/IPA integrity, signature scheme (v1/v2/v3), debuggable flags, backup allowances (`android:allowBackup`), cleartext traffic permissions, and custom permissions.
- **Component Enumeration:** Inspect every exported and non-exported Activity, Service, BroadcastReceiver, and ContentProvider. Flag exposed `intent-filter` configurations, deep links (`http`, `https`, and custom schemes), and pending intent creation.
- **Native Surface Review:** Unpack ELF (`.so`) and Mach-O binaries. Audit exported JNI functions (`Java_com_...`), symbol tables, insecure string operations, hardcoded crypto keys, and dynamic library loading (`System.loadLibrary`).

### Phase 2: Dependency Intel & Reachability Analysis
- **Software Bill of Materials (SBOM):** Extract exact Maven/Gradle/CocoaPods coordinates and version strings.
- **Vulnerability Reachability (Not Version Matching):**
  - A known CVE in a third-party library is merely a *lead*.
  - A senior pentester traces code execution paths from application logic to the vulnerable library function. If the vulnerable method or class is never instantiated or reachable from app input, downgrade to INFORMATIONAL or discard.

### Phase 3: Targeted Instrumentation Engineering
- **Surgical Hooks Over Generic Blunderbusses:**
  - Develop modular Frida hooks targeting specific classes, security controls, and crypto routines rather than injecting bloated universal scripts that crash native threads.
  - Implement resilience evasion: Root/Jailbreak detection bypass, SSL/TLS certificate pinning bypass, anti-debugging (`ptrace`, `TracerPid`) neutralization.
  - Ensure every hook emits deterministic execution markers (e.g., `[+] [FRIDA_VERIFIED_<ID>]`) to validate successful instrumentation.

### Phase 4: Runtime Dynamic Exploration
- **Cryptographic Auditing:** Trace cipher initialization, key derivation (PBKDF2, scrypt), IV uniqueness (preventing nonce reuse in AES-GCM), and Android Keystore / iOS Keychain hardware-backed backing.
- **Data-at-Rest Inspection:** Inspect `/data/data/<pkg>/` on Android and sandbox Containers on iOS. Scrutinize SharedPreferences, SQLite databases, Realm, cache directories, WebKit local storage, logcat outputs, and clipboard interactions.
- **Inter-Process Communication (IPC):** Fuzz exported components using structured intents, verify input validation on deep link parameters, test for Intent Redirection (nested intents), and test ContentProviders for directory traversal (`../`) and SQL injection.
- **WebView & Hybrid Bridges:** Inspect JavaScript interfaces (`@JavascriptInterface`), `setAllowUniversalAccessFromFileURLs`, `setAllowFileAccess`, remote debugging enablement, and URL scheme hijacking.

### Phase 5: High-Confidence Lead Weaponization
- **Safe Exploitation:** Chain vulnerabilities safely (e.g., deep link -> intent redirection -> private component launch -> token leak).
- **Proof-of-Concept Standard:** Every PoC must be reproducible via single commands (`adb shell am start ...`, `curl`, or standalone python/frida scripts).

### Phase 6: Adversarial Verification & Hard False-Positive Gate
- **Independent Replay:** Re-run the PoC on a clean application state (after `pm clear` or fresh installation) at least 2 times.
- **Falsification Testing:** Actively attempt to disprove the vulnerability by testing negative conditions, unauthenticated contexts, and alternate user roles.
- **The 7-Question FP Gate:** Run every candidate finding through the gate defined in Section 3.

### Phase 7: MASVS Coverage Auditing
- Systematically cross-reference findings and tested surfaces against OWASP MASVS v2.0 categories:
  - `MASVS-STORAGE`: Secure data storage and sensitive data leakage.
  - `MASVS-CRYPTO`: Robust cryptographic algorithms and key management.
  - `MASVS-AUTH`: Authentication and session management architectures.
  - `MASVS-NETWORK`: Secure network communications and TLS validation.
  - `MASVS-PLATFORM`: Secure platform interaction (IPC, deep links, WebViews, permissions).
  - `MASVS-CODE`: Code quality, compiler security settings, and third-party dependencies.
  - `MASVS-RESILIENCE`: Defense-in-depth anti-tampering and reverse engineering protections.

### Phase 8: Triager-Ready Reporting
- Produce concise, high-signal vulnerability advisories formatted specifically for platform triagers (HackerOne, Bugcrowd, Intigriti, or internal AppSec teams).

---

## 3. The 7-Question Hard False-Positive (FP) Gate

Before any finding is promoted to `REPORTABLE`, all seven questions must be answered affirmatively:

| # | Criterion | Verification Question | Downgrade Trigger |
|---|---|---|---|
| **Q1** | **Real Impact** | Does this vulnerability cause tangible, demonstrable unauthorized access, privilege escalation, or security state compromise? | Pure theoretical weakness without security boundary violation. |
| **Q2** | **Deterministic Exploit** | Is there a reliable, step-by-step attack path reproducible from outside the app sandbox? | Flaky behavior requiring impossible race conditions or physical root access by an external attacker. |
| **Q3** | **Meaningful Leverage** | Does this flaw chain into Account Takeover (ATO), arbitrary data extraction, RCE, or business logic bypass? | Security headers missing without exploitable consequence, informational manifest flags without reachable attack vector. |
| **Q4** | **PoC Reproducibility** | Is the proof-of-concept completely reproducible with exact commands/scripts provided in evidence? | Missing reproduction steps or failure to replicate on clean test state. |
| **Q5** | **Cross-Context Rule** | Was the behavior validated across distinct accounts/roles to eliminate intended self-access? | Finding based on inspecting the current user's own data or normal account operations. |
| **Q6** | **FP Database Clearance** | Has the signature hash been verified against `memory/FALSE_POSITIVE_DB.md`? | Known false positive signature match (e.g., standard Google Maps API key, public Firebase config). |
| **Q7** | **Independent Replay** | Has the finding survived adversarial falsification and independent 2× replay? | Inability to replicate impact on clean install or under strict verification. |

---

## 4. Triage Excellence & Bug Bounty Value Maximization

### 4.1 What Gets Paid (High / Critical Value)
- **Account Takeover via Deep Link / OAuth Hijacking:** Interception of authorization codes or access tokens via improperly validated custom URI schemes or Intent redirection.
- **Remote Code Execution (RCE):** Exploitation of unpatched native libraries, unsafe dynamic code loading from untrusted storage, or WebView JS interfaces on Android < 4.2 / misconfigured WebViews.
- **Cross-Tenant IDOR via Mobile Endpoints:** Mobile-specific API endpoints that bypass backend authorization checks present in web applications.
- **Sensitive Data Exfiltration via Exported ContentProviders:** Path traversal in `openFile()` allowing arbitrary reading of app-private databases or SharedPreferences.
- **Arbitrary Intent Redirection to Unexported Components:** Exploiting exported Trampoline Activities to forward attacker-controlled Intents to unexported internal screens or debug components.

### 4.2 What Gets Closed as Informational / N/A (Avoid Submitting)
- Hardcoded public API keys without backend billing or data access (e.g., Firebase Project ID, Google Maps API key, Bugsnag/Sentry keys).
- `android:allowBackup="true"` without demonstrating extraction of sensitive session tokens or keys on an unencrypted backup.
- SSL Pinning bypass demonstrated on a rooted device where the attacker owns the device (this is a client-side defense-in-depth control, not a standalone server-side vulnerability).
- Root / Jailbreak detection bypass alone without secondary impact.
- Lack of obfuscation or binary protections unless explicitly specified in program bounties.
- Exported activities that merely render public informational screens without parameters or state change.

---

## 5. Artifact Directory & Evidence Structure

Every assessment must maintain a structured audit trail in `testing/<app-package>/`:
```
testing/<app-package>/
├── notes/
│   ├── CONTEXT_LEDGER.md      # Action history and spawn logs
│   ├── MINDMAP.md             # Attack surface decomposition
│   └── tested-variants.md     # Exploitation permutations ledger
├── static/
│   ├── manifest-analysis.json # Exported components & permissions
│   ├── library-inventory.json # Third-party dependency list
│   └── secrets-leads.json     # Extracted keys and credential leads
├── intel/
│   └── cve-matches.json       # Evaluated CVE reachability reports
├── frida/
│   ├── README.md              # Script-to-evidence execution map
│   └── *.js                   # Surgical instrumentation scripts
├── dynamic/
│   ├── network/               # Decrypted HTTP/mTLS flows (.pcap, .mitm)
│   ├── storage/               # Extracted DBs, prefs, and keychain dumps
│   └── ipc/                   # Intent fuzzer logs and intent dumps
├── exploitation/
│   ├── poc_<finding_id>.py    # Executable proof of concept
│   └── raw_evidence/          # Screenshots, terminal logs, diff outputs
└── reports/
    └── <finding_id>.md        # Triager-ready vulnerability report
```
