# resilience-agent Briefing

**Class:** Collection | **Index:** 14
**Purpose:** Evaluate MASVS-R controls: root/jailbreak detection, anti-debug hooks, anti-Frida measures, code integrity checks, and obfuscation levels. Test effectiveness and bypassability.

## Output Contract
```
RESILIENCE SUMMARY
- Root detection: <present|absent> | effective: Y/N | bypass: Y/N
- Jailbreak detection: <present|absent> | effective: Y/N | bypass: Y/N
- Anti-debug / anti-Frida: <present|absent> | bypass: Y/N
- Integrity checks: <count> | bypass: Y/N
- Obfuscation: <none|light|moderate|heavy>
- Consequence of bypasses: <list>
```
