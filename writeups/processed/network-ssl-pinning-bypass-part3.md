---
title: Frida — The Android Penetration Testing Tool (Part 3: SSL Pinning Bypass)
vuln_class: network
source: medium
tags: [android, frida, ssl-pinning, mitm, burp]
---

# Frida — The Android Penetration Testing Tool (Part 3: SSL Pinning Bypass)

- **Author:** Kishor Rankhamb
- **Date:** 2025-12-16
- **Source:** [https://medium.com/@kishor.rankhamb28/frida-the-android-penetration-testing-tool-part-3-ssl-pinning-bypass-4baedc5115cf](https://medium.com/@kishor.rankhamb28/frida-the-android-penetration-testing-tool-part-3-ssl-pinning-bypass-4baedc5115cf)
- **Platform:** Android (emulator / rooted device)
- **Vuln class:** network

## Bugs / vulnerability classes

SSL/certificate pinning (hardcoded cert/key) blocking traffic interception; transparent proxy trust issues. Goal: enable interception to expose API/insecure-transport bugs.

## Techniques (tools & commands)

pip install frida-tools; frida-server on device; Burp/mitmproxy listener on PC IPv4:8080; export CA as .cer (DER); install on device (Settings > Install Certificate, verify under Trusted Credentials); Wi-Fi proxy manual PC:8080; adb reboot; launch app via Frida, observe Burp history/Repeater. Custom hook needed if pinning ignores user CA.

## Lessons for the agent

- Verify system-CA trust + proxy binding after adb reboot before assuming pinning; no traffic does not equal pinning.
- CA export must match the active proxy listener, not a stale cert.
- Install order matters: Android 7+ apps may ignore user CAs (networkSecurityConfig) — test pinning APIs before claiming bypassable pinning.

## Provenance

Summarised from the public Medium article above (educational / authorised-testing use only).
Full text remains at the source URL; this file is the normalised learning record consumed by
`writeup_index.py` for similar-case expansion.
