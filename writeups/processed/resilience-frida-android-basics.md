---
title: Frida — The Android Penetration Testing Tool (Part 1: Basics)
vuln_class: resilience
source: medium
tags: [android, frida, dynamic-analysis, setup]
---

# Frida — The Android Penetration Testing Tool (Part 1: Basics)

- **Author:** Kishor Rankhamb
- **Date:** 2025-11-23
- **Source:** [https://medium.com/@kishor.rankhamb28/frida-android-penetration-testing-tool-24fdfe45d142](https://medium.com/@kishor.rankhamb28/frida-android-penetration-testing-tool-24fdfe45d142)
- **Platform:** Android (emulator / rooted device)
- **Vuln class:** resilience

## Bugs / vulnerability classes

SSL pinning bypass, anti-debugging bypass, obfuscated-code analysis, credential capture via login hooking, AES/RSA key dumping, memory manipulation.

## Techniques (tools & commands)

pip install frida-tools; adb devices; getprop ro.product.cpu.abi; download ABI-matching frida-server (arm/arm64/x86); adb push to /data/local/tmp, chmod 755, run in background; frida-ps -Uai health-check; frida -U <app> (spawn/attach). Components: frida-cli, frida-server (rooted), frida-gadget (embedded, non-rooted, limited), frida-trace, frida-js.

## Lessons for the agent

- Always match frida-server variant/version to device ABI (ro.product.cpu.abi) and host tools — arch mismatch is the #1 setup failure.
- Use frida-ps -Uai as health-check before hooking; distinguishes server/connectivity issues from app issues.
- 'No root needed' is partial: server mode still needs root/emulator; gadget mode has restrictions.

## Provenance

Summarised from the public Medium article above (educational / authorised-testing use only).
Full text remains at the source URL; this file is the normalised learning record consumed by
`writeup_index.py` for similar-case expansion.
