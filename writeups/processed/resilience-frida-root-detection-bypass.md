---
title: Frida — The Android Penetration Testing Tool (Part 2: Frida & Root Detection Bypass)
vuln_class: resilience
source: medium
tags: [android, frida, root-detection, anti-analysis]
---

# Frida — The Android Penetration Testing Tool (Part 2: Frida & Root Detection Bypass)

- **Author:** Kishor Rankhamb
- **Date:** 2025-12-01
- **Source:** [https://medium.com/@kishor.rankhamb28/frida-the-android-penetration-testing-tool-part-2-frida-root-detection-bypass-abdab66e08c1](https://medium.com/@kishor.rankhamb28/frida-the-android-penetration-testing-tool-part-2-frida-root-detection-bypass-abdab66e08c1)
- **Platform:** Android (emulator / rooted device)
- **Vuln class:** resilience

## Bugs / vulnerability classes

Frida detection (process/library/port/file checks) and root detection (su binary, Magisk/root apps, build props, bootloader/ROM) used to block hooking/interception — anti-analysis controls, not vulnerabilities themselves.

## Techniques (tools & commands)

Reverse APK in JADX-GUI (deobfuscation), locate detection logic (Frida file/process/port checks; root file/prop checks), write custom per-app Frida hook targeting detection functions, spawn: frida -U -l <script.js> <package>.

## Lessons for the agent

- Map root+Frida checks in decompiled code before attempting Frida — absence of a hook is a dead end, not a clean app.
- If JADX output is unreadable (obfuscation), switch static tools before writing hooks.
- Passing after bypass proves detection was client-side only; do not report the app as secure because it ran.

## Provenance

Summarised from the public Medium article above (educational / authorised-testing use only).
Full text remains at the source URL; this file is the normalised learning record consumed by
`writeup_index.py` for similar-case expansion.
