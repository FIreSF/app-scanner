# ADVERSARIAL FALSIFICATION & FALSE-POSITIVE ELIMINATION (skills/adversarial-falsification.md)
**Standard:** Bug Bounty Quality Assurance | The 7-Question Hard FP Gate  
**Audience:** Senior Mobile Penetration Testers & Verification Agents  

---

## 1. The Adversarial Verification Mindset
A junior tester discovers a potential weakness and immediately drafts a report. A senior mobile penetration tester with 10+ years of experience immediately **switches roles into an aggressive defense attorney or platform triager** and attempts to disprove the finding.

A finding is considered unproven until:
1. It survives active attempts to falsify it.
2. It is confirmed across independent, clean application states.
3. It clearly breaches an authorization, authentication, or isolation boundary.

---

## 2. The 5-Step Falsification Protocol

```
[Candidate Finding (CONFIRMED)]
               │
               ▼
   [Step 1: The Clean Slate Test (2x)]
               │
               ▼
   [Step 2: The Multi-Account Isolation Test]
               │
               ▼
   [Step 3: Negative Context / Self-Access Falsification]
               │
               ▼
   [Step 4: Reachability & Dependency Realism]
               │
               ▼
   [Step 5: The Triager Value & Exploitability Filter]
               │
               ▼
      [PROMOTED TO VALIDATED]
```

### Step 1: The Clean Slate Test (2x Reproduction)
- **Problem:** Many dynamic "vulnerabilities" occur due to contaminated runtime state: cached tokens, remnants of prior hooked sessions, or lingering root modifications.
- **Protocol:**
  1. Terminate the app: `adb shell am force-stop <pkg>`.
  2. Clear app state completely: `adb shell pm clear <pkg>`.
  3. Replay the exact raw exploit commands / intents / network payloads from scratch.
  4. Repeat twice on two distinct clean states.
  5. If the exploit fails to replicate either time, the finding is invalid.

### Step 2: The Multi-Account Isolation Test (IDOR / BOLA)
- **Problem:** Testers frequently test with Account A, query an object ID, get 200 OK, and report IDOR without realizing that Object ID belongs to Account A or is publicly readable.
- **Protocol:**
  1. Provision `Account_A` and `Account_B`.
  2. Create a private resource $R_B$ strictly within `Account_B`'s session.
  3. Authenticate as `Account_A`. Request $R_B$.
  4. Perform Response-Diff analysis: compare $R_B$ requested by `Account_B` (authorized) vs $R_B$ requested by `Account_A` (unauthorized).
  5. If `Account_A` receives the identical sensitive payload, IDOR is validated. If `Account_A` receives a sanitized or public subset, it is not an IDOR.

### Step 3: Negative Context / Self-Access Falsification
- **Problem:** Testing whether an app allows modifying its own SharedPreferences or reading its own internal files. On mobile, an app has full read/write access to its own sandbox!
- **Rule:** A finding that requires the attacker to already be executing inside the victim app's own sandbox or running as root on the victim's physical device is generally **Self-Exploitation** (Informational / Out-of-Scope).
- **Test:** Can this vulnerability be triggered by an external, non-privileged app on the device, or by a remote attacker across the network? If no, evaluate whether the threat model supports local privilege boundaries.

### Step 4: Reachability & Dependency Realism (CVE Falsification)
- **Problem:** Static scanners flag `libpng 1.6.30 - CVE-2018-XXXX (Memory Corruption)`.
- **Falsification Test:**
  1. Does the APK compile this native library?
  2. Is the symbol called anywhere in DEX or native code?
  3. Can an attacker pass untrusted image bytes to this specific decoder path from an exported component, deep link, or network payload?
  4. If the code path is completely uncalled or dead code stripped by ProGuard, mark as `DEAD_CODE_FALSE_POSITIVE` and downgrade.

### Step 5: Triager Value & Impact Filter
- Run the 7-Question Hard FP Gate:
  1. Real Impact?
  2. Deterministic Exploit?
  3. Leverageable into High/Crit?
  4. Fully Reproducible?
  5. Cross-Context Verified?
  6. FP Database Checked?
  7. Survived Verification Agent?

---

## 3. High-Value vs. Low-Value Finding Classification

| Finding Candidate | Typical Junior Submission | Senior 10+ Year Reclassification |
|---|---|---|
| Hardcoded Google Maps API Key in AndroidManifest | High: "Hardcoded API Key" | **INFORMATIONAL**: Public key, restricted by package name & SHA-1 fingerprint. |
| Exported Activity with Intent Filter | Medium: "Exported Activity Vulnerability" | **INFORMATIONAL**: Public activity (e.g. Login screen) with no sensitive parameters or state change. |
| Exported Trampoline Activity Forwarding Intent Extra | Medium: "Exported Component" | **HIGH / CRITICAL**: Arbitrary Intent Redirection allowing launch of unexported internal components and private file leakage. |
| Lack of Certificate Pinning | Medium: "Missing SSL Pinning" | **INFORMATIONAL / LOW**: Defense-in-depth client control; not an independent server vulnerability. |
| Deep Link Triggering Unauthenticated Password Reset | Low: "Deep link exposed" | **CRITICAL**: Remote 1-Click Account Takeover via Deep Link CSRF. |
| Cleartext Database on Rooted Device | High: "Unencrypted Database" | **LOW / INFORMATIONAL**: Root user can inspect all sandboxes. Only valid if `allowBackup=true` allows non-root extraction or provider leaks it. |
