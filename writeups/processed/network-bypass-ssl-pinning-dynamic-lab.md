---
title: Android Application Pentesting — Bypass SSL Pinning
vuln_class: network
source: medium
tags: [android, ssl-pinning, dynamic-analysis, burp, objection]
---

# Android Application Pentesting — Bypass SSL Pinning

- **Author:** Manoj Deshmukh
- **Date:** 2025-03-25
- **Source:** [https://manojdeshmukh45.medium.com/android-application-pentesting-bypass-ssl-pinning-8d643cb3967b](https://manojdeshmukh45.medium.com/android-application-pentesting-bypass-ssl-pinning-8d643cb3967b)
- **Platform:** Android (emulator / rooted device)
- **Vuln class:** network

## Bugs / vulnerability classes

SSL/certificate pinning blocking traffic interception; setup for dynamic analysis of insecure transport (static vs dynamic framing).

## Techniques (tools & commands)

Android Studio Pixel emulator; rootAVD -> Magisk -> adb shell su; Burp proxy *:8080, emulator Wi-Fi proxy http://burp, install cacert.crt; pip install frida/objection; adb push frida-server (version-matched, e.g. 16.6.1-android-x86_64), chmod, run; adb install <apk>; frida -U -f <package> -l ssl.js; verify bypass in Burp HTTP logs.

## Lessons for the agent

- Lab order matters: root -> CA install -> verify HTTPS in browser -> then script. Skipping verification creates false 'bypass worked' when no HTTPS traffic exists.
- Version/arch lock: check adb device ABI before downloading the server; mismatch is the top failure.
- CA install alone is not a pinning bypass: open app actions and look for pinned HTTPS appearing in Burp.

## Provenance

Summarised from the public Medium article above (educational / authorised-testing use only).
Full text remains at the source URL; this file is the normalised learning record consumed by
`writeup_index.py` for similar-case expansion.
