---
title: Setup an Android Pen Testing Lab with Frida-Tools, Objection, Frida Server, and Bypass SSL Pinning
vuln_class: network
source: medium
tags: [android, frida, objection, ssl-pinning, lab-setup]
---

# Setup an Android Pen Testing Lab with Frida-Tools, Objection, Frida Server, and Bypass SSL Pinning

- **Author:** Amjad Ali (with Sahil Choudhary)
- **Date:** 2023-07-02
- **Source:** [https://amjadali110.medium.com/setup-an-android-pen-testing-lab-with-frida-tools-objection-frida-server-and-bypass-ssl-pinning-17897f6abaf3](https://amjadali110.medium.com/setup-an-android-pen-testing-lab-with-frida-tools-objection-frida-server-and-bypass-ssl-pinning-17897f6abaf3)
- **Platform:** Android (emulator / rooted device)
- **Vuln class:** network

## Bugs / vulnerability classes

Certificate/SSL pinning bypass, insecure HTTPS interception, insecure traffic analysis.

## Techniques (tools & commands)

pip install frida-tools objection; adb shell getprop ro.product.cpu.abi; frida-server-16.1.1-android-x86 to /data/local/tmp; Burp proxy listener + CA install (cacert.der -> .cer); objection -g <package> explore, then android sslpinning disable; frida-ps -Uai.

## Lessons for the agent

- Detect ABI first (getprop) before selecting frida-server; arch mismatch = top false positive for 'setup failed'.
- Verify Burp CA trust separately from pinning bypass; user-CA install does not mean pinning is disabled.
- Emulator proxy must be host-IP reachable; test interception in the browser before testing app traffic.

## Provenance

Summarised from the public Medium article above (educational / authorised-testing use only).
Full text remains at the source URL; this file is the normalised learning record consumed by
`writeup_index.py` for similar-case expansion.
