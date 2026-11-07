---
title: Setting up your Android mobile-app pentesting lab — a fast, reliable guide
vuln_class: network
source: medium
tags: [android, lab-setup, masvs, jadx, apktool]
---

# Setting up your Android mobile-app pentesting lab — a fast, reliable guide

- **Author:** coy0te
- **Date:** 2025-11-11
- **Source:** [https://coy0te.medium.com/setting-up-your-android-mobile-app-pentesting-lab-a-fast-reliable-guide-f2627f4fa132](https://coy0te.medium.com/setting-up-your-android-mobile-app-pentesting-lab-a-fast-reliable-guide-f2627f4fa132)
- **Platform:** Android (emulator / rooted device)
- **Vuln class:** network

## Bugs / vulnerability classes

MASVS coverage surface: insecure network config/pinning, exported components and secrets (jadx/apktool/MobSF), root/emulator detection, SafetyNet/Play Integrity, WebView/native hooking surface.

## Techniques (tools & commands)

Android Studio SDK platform-tools; adb devices/shell getprop/settings put global http_proxy/root/remount/push/reboot; openssl x509 cert convert; adb shell pm list/path + pull; apktool d; jadx-gui; frida-trace; frida-server to /data/local/tmp chmod 755 su -c; objection --gadget <app> explore; Frida Gadget embedded in rebuilt APK for non-root devices.

## Lessons for the agent

- Hybrid lab: start on snapshotable AVD for speed, escalate to rooted device for hardware APIs/anti-emulation — emulator detection is expected, not a lab bug.
- User CA is often ignored by strict networkSecurityConfig; do not report 'no HTTPS interception' until a Frida pinning hook is tried.
- Snapshot/golden image + isolated network + version logging makes evidence reproducible and cuts false positives.

## Provenance

Summarised from the public Medium article above (educational / authorised-testing use only).
Full text remains at the source URL; this file is the normalised learning record consumed by
`writeup_index.py` for similar-case expansion.
