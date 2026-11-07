---
title: Dynamic Analysis and Runtime Manipulation in Mobile Pentesting
vuln_class: resilience
source: medium
tags: [android, frida, dynamic-analysis, root-detection, ssl-pinning]
---

# Dynamic Analysis and Runtime Manipulation in Mobile Pentesting

- **Author:** Izaz Haque (@izaz.haque246)
- **Date:** 2025-03-21
- **Source:** [https://medium.com/@izaz.haque246/dynamic-analysis-and-runtime-manipulation-in-mobile-pentesting-b9e991344bb9](https://medium.com/@izaz.haque246/dynamic-analysis-and-runtime-manipulation-in-mobile-pentesting-b9e991344bb9)
- **Platform:** Android (emulator / rooted device)
- **Vuln class:** resilience

## Bugs / vulnerability classes

Root detection/anti-tampering, SSL pinning, broken auth (forced PIN), hardcoded/hidden flags/debug logic, sensitive API params/tokens in memory, anti-Frida/anti-debug, insecure network traffic exposure.

## Techniques (tools & commands)

pip install frida frida-tools; adb root/push/chmod frida-server; frida-ps -U; frida -U -l hello.js / -f <package>; Java.perform/Java.use(...).implementation=; objection --gadget explore -> android sslpinning disable; radare2/JADX/Apktool/Ghidra; Python frida API (get_usb_device().attach/create_script); Memory.allocUtf8String/readUtf8String/hexdump.

## Lessons for the agent

- Reusable hook shape: hook method -> log args -> call original -> modify return; same shape for root/pin/Frida checks + API interception.
- Combine static (JADX/Apktool) to find real class/method names first — example namespaces are illustrative; blind copying yields false negatives.
- Aggressive hooks on high-frequency/native code cause crashes and anti-Frida triggers — test isolated, keep scripts modular/logged.

## Provenance

Summarised from the public Medium article above (educational / authorised-testing use only).
Full text remains at the source URL; this file is the normalised learning record consumed by
`writeup_index.py` for similar-case expansion.
