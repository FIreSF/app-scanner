#!/usr/bin/env python3
"""
Scenario -> agent/skill resolver.

Given a surface description (free text such as "webview bridge ssl pinning"),
return the agents that own it, the methodology skills they must load, the tools
they need and the MASVS category the work feeds.

The resolver is deliberately explicit: when nothing matches it says so instead
of silently pretending the request was static analysis.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REGISTRY_PATH = os.path.join(ROOT_DIR, "runtime", "registry.json")

SCENARIO_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "static": {
        "agents": ["static-agent"],
        "skills": ["skills/master-bugbounty-rules.md", "skills/adversarial-falsification.md"],
        "tools": ["apktool", "jadx", "strings", "ghidra"],
        "description": "Decompilation, manifest analysis, native binary review, and library inventory.",
        "masvs_category": "MASVS-CODE",
    },
    "cve": {
        "agents": ["mcp-bug-intel-agent", "frida-script-agent"],
        "skills": ["skills/adversarial-falsification.md"],
        "tools": ["mcp:osv", "mcp:nvd", "mcp:github-advisories", "python"],
        "description": "Lookup known CVEs for third-party libraries and probe reachability.",
        "masvs_category": "MASVS-CODE",
    },
    "frida": {
        "agents": ["frida-script-agent", "dynamic-agent"],
        "skills": ["skills/master-bugbounty-rules.md", "skills/frida-lab-and-runtime.md"],
        "tools": ["frida", "frida-tools", "objection", "python"],
        "description": "Generate targeted, read-only-by-default instrumentation scripts.",
        "masvs_category": "MASVS-RESILIENCE",
    },
    "dynamic": {
        "agents": ["dynamic-agent"],
        "skills": ["skills/master-bugbounty-rules.md", "skills/adversarial-falsification.md", "skills/flutter-android-security.md"],
        "tools": ["frida", "objection", "adb", "mitmproxy"],
        "description": "Runtime exploration, class enumeration, method tracing, hidden business logic.",
        "masvs_category": "MASVS-PLATFORM",
    },
    "root-device": {
        "agents": ["root-device-agent"],
        "skills": ["skills/master-bugbounty-rules.md"],
        "tools": ["adb", "fastboot", "magisk", "frida-server"],
        "description": "Rooted physical device readiness, frida-server, proxy and CA setup with revert path.",
        "masvs_category": "MASVS-RESILIENCE",
    },
    "emulator": {
        "agents": ["emulator-agent"],
        "skills": ["skills/master-bugbounty-rules.md"],
        "tools": ["avdmanager", "emulator", "genymotion", "corellium", "adb", "frida-server"],
        "description": "Clean, arch-matched emulator instances, snapshots and rollbacks.",
        "masvs_category": "MASVS-RESILIENCE",
    },
    "exploitation": {
        "agents": ["exploitation-agent"],
        "skills": [
            "skills/master-bugbounty-rules.md",
            "skills/adversarial-falsification.md",
            "skills/ipc-deeplink-exploitation.md",
        ],
        "tools": ["frida", "adb", "python", "mitmproxy"],
        "description": "Weaponize a single HIGH-CONFIDENCE lead into a safe, reproducible PoC.",
        "masvs_category": "ALL",
    },
    "reporting": {
        "agents": ["reporting-agent"],
        "skills": ["skills/master-bugbounty-rules.md"],
        "tools": ["markdown", "pandoc"],
        "description": "Triager-ready report assembly from VALIDATED findings only (user gated).",
        "masvs_category": "ALL",
    },
    "traffic": {
        "agents": ["network-traffic-agent"],
        "skills": ["skills/network-api-security.md", "skills/master-bugbounty-rules.md", "skills/android-network-security-config.md", "skills/ios-ats-and-transport.md", "skills/mobile-api-backend-testing.md"],
        "tools": ["mitmproxy", "frida", "tcpdump"],
        "description": "Traffic decryption, API mapping, token leakage, and cleartext inspection.",
        "masvs_category": "MASVS-NETWORK",
    },
    "crypto": {
        "agents": ["crypto-analysis-agent"],
        "skills": ["skills/crypto-keymanagement-audit.md", "skills/android-insecure-randomness.md", "skills/android-keystore-extraction.md", "skills/android-biometric-auth-bypass.md"],
        "tools": ["jadx", "ghidra", "python-cryptography"],
        "description": "Weak ciphers, static IVs, hardcoded keys, and custom cryptographic routines.",
        "masvs_category": "MASVS-CRYPTO",
    },
    "storage": {
        "agents": ["storage-analysis-agent"],
        "skills": ["skills/storage-data-at-rest.md", "skills/android-backup-extraction.md", "skills/android-clipboard-and-intent-leakage.md", "skills/android-sqlite-and-database.md", "skills/ios-keychain-and-storage.md", "skills/android-screen-and-multitasking-leakage.md"],
        "tools": ["adb", "sqlite3", "strings", "python"],
        "description": "Inspection of SharedPreferences, SQLite, Realm, cache, and backup security.",
        "masvs_category": "MASVS-STORAGE",
    },
    "ipc": {
        "agents": ["ipc-attack-agent", "dynamic-agent"],
        "skills": ["skills/ipc-deeplink-exploitation.md", "skills/master-bugbounty-rules.md", "skills/android-exported-components.md", "skills/android-content-provider-traversal.md"],
        "tools": ["adb", "frida", "drozer"],
        "description": "Test exported activities, services, broadcast receivers, and content providers.",
        "masvs_category": "MASVS-PLATFORM",
    },
    "intent": {
        "agents": ["ipc-attack-agent"],
        "skills": ["skills/ipc-deeplink-exploitation.md", "skills/android-intent-redirection-pendingintent.md", "skills/ios-url-scheme-pasteboard.md"],
        "tools": ["adb", "frida"],
        "description": "Deep link fuzzing, pending intent hijacking, and intent redirection.",
        "masvs_category": "MASVS-PLATFORM",
    },
    "webview": {
        "agents": ["webview-agent", "dynamic-agent"],
        "skills": ["skills/webview-security-testing.md", "skills/master-bugbounty-rules.md", "skills/android-webview-file-access.md"],
        "tools": ["frida", "chrome-devtools-mcp", "adb"],
        "description": "JavaScript bridges, file:// scheme abuse, and universal XSS in WebViews.",
        "masvs_category": "MASVS-PLATFORM",
    },
    "resilience": {
        "agents": ["resilience-agent", "frida-script-agent"],
        "skills": ["skills/resilience-antitamper.md", "skills/android-debuggable-and-logging.md", "skills/ios-jailbreak-and-debug.md", "skills/android-obfuscation-and-packing.md"],
        "tools": ["frida", "objection", "magisk"],
        "description": "Root/jailbreak detection, anti-Frida, anti-debug, and code integrity.",
        "masvs_category": "MASVS-RESILIENCE",
    },
    "verification": {
        "agents": ["verification-agent"],
        "skills": ["skills/adversarial-falsification.md", "skills/master-bugbounty-rules.md"],
        "tools": ["frida", "adb", "mitmproxy", "python"],
        "description": "Adversarial falsification, 2x reproduction, and alternate context checks.",
        "masvs_category": "ALL",
    },
    "compliance": {
        "agents": ["compliance-agent"],
        "skills": ["skills/adversarial-falsification.md", "memory/methodology.md"],
        "tools": ["python"],
        "description": "MASVS/MASTG coverage matrix, gap analysis and re-test recommendations.",
        "masvs_category": "ALL",
    },
}

# Extra vocabulary that should resolve to a scenario key.
ALIASES: Dict[str, List[str]] = {
    "static": ["decompile", "decompilation", "manifest", "apk", "ipa", "jadx", "apktool", "secrets", "sbom", "library"],
    "cve": ["intel", "osv", "nvd", "advisory", "advisories", "dependency", "dependencies", "vulnerable", "reachability"],
    "frida": ["hook", "hooks", "instrumentation", "script", "bypass", "objection"],
    "dynamic": ["runtime", "trace", "tracing", "class-dump", "enumeration"],
    "root-device": ["root", "rooted", "magisk", "device", "physical", "frida-server"],
    "emulator": ["avd", "snapshot", "genymotion", "corellium", "simulator"],
    "exploitation": ["exploit", "poc", "weaponize", "payload"],
    "reporting": ["report", "writeup", "advisory", "triager"],
    "traffic": ["network", "mitm", "mitmproxy", "tls", "ssl", "pinning", "http", "api", "traffic", "cleartext"],
    "crypto": ["cipher", "aes", "rsa", "keystore", "keychain", "iv", "encryption", "hash", "random"],
    "storage": ["prefs", "sharedpreferences", "sqlite", "database", "realm", "backup", "clipboard", "at-rest", "data-at-rest"],
    "ipc": ["exported", "activity", "service", "provider", "broadcast", "contentprovider", "binder", "xpc"],
    "intent": ["deeplink", "deep-link", "url-scheme", "scheme", "pending-intent", "redirection"],
    "webview": ["bridge", "javascriptinterface", "xss", "javascript", "wkwebview", "hybrid", "cordova"],
    "resilience": ["antitamper", "anti-tamper", "jailbreak", "anti-debug", "obfuscation", "integrity", "safetynet", "play-integrity"],
    "verification": ["verify", "falsify", "false-positive", "false_positive", "replay"],
    "compliance": ["masvs", "mastg", "coverage", "gap", "audit"],
}

MULTIWORD_ALIASES = {
    "deep link": "intent",
    "ssl pinning": "traffic",
    "certificate pinning": "traffic",
    "data at rest": "storage",
    "content provider": "ipc",
    "javascript interface": "webview",
    "false positive": "verification",
    "root device": "root-device",
}


def _tokenize(query: str) -> List[str]:
    return [token for token in re.split(r"[^a-z0-9_-]+", query.lower()) if token]


def _score(query: str, tokens: Iterable[str], key: str) -> int:
    token_set = set(tokens)
    score = 0
    if key in token_set:
        score += 10
    if key in query:
        score += 4
    for alias in ALIASES.get(key, []):
        if alias in token_set:
            score += 8
        elif len(alias) > 3 and alias in query:
            score += 3
    return score


def resolve_scenario(scenario_query: str) -> Dict[str, Any]:
    """Resolve free-text surface keywords to one or more scenario mappings.

    The returned dict always contains a ``matched`` boolean.  When nothing
    matches, a ``default`` entry (static analysis) is returned and ``matched``
    is False so callers can warn instead of silently misrouting work.
    """
    query = (scenario_query or "").lower().strip()
    if not query:
        return {
            "matched": False,
            "query": scenario_query,
            "results": {},
            "unmatched_tokens": [],
        }

    tokens = _tokenize(query)
    scores: Dict[str, int] = {}
    for key in SCENARIO_MAPPINGS:
        score = _score(query, tokens, key)
        if score:
            scores[key] = score

    # Multi-word aliases ("ssl pinning" -> traffic) add a strong signal.
    for phrase, key in MULTIWORD_ALIASES.items():
        if phrase in query:
            scores[key] = scores.get(key, 0) + 9

    results: Dict[str, Any] = {}
    for key in sorted(scores, key=lambda k: (-scores[k], list(SCENARIO_MAPPINGS).index(k))):
        results[key] = dict(SCENARIO_MAPPINGS[key])

    consumed = set()
    for key in results:
        consumed.add(key)
        consumed.update(ALIASES.get(key, []))
    unmatched = [token for token in tokens if token not in consumed and len(token) > 2]

    if not results:
        return {
            "matched": False,
            "query": scenario_query,
            "results": {"default": dict(SCENARIO_MAPPINGS["static"])},
            "unmatched_tokens": tokens,
        }

    return {
        "matched": True,
        "query": scenario_query,
        "results": results,
        "unmatched_tokens": unmatched,
    }


def validate_mappings(registry_path: str = REGISTRY_PATH, root_dir: str = ROOT_DIR) -> List[str]:
    """Cross-check every mapping against the registry and the filesystem."""
    errors: List[str] = []
    try:
        with open(registry_path, "r", encoding="utf-8") as handle:
            registry = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read registry: {exc}"]

    known_agents = set((registry.get("agents") or {}).keys())
    for key, mapping in SCENARIO_MAPPINGS.items():
        for agent in mapping["agents"]:
            if agent not in known_agents:
                errors.append(f"scenario '{key}' references unknown agent '{agent}'")
        for skill in mapping["skills"]:
            if not os.path.isfile(os.path.join(root_dir, skill)):
                errors.append(f"scenario '{key}' references missing skill '{skill}'")
        if not mapping["tools"]:
            errors.append(f"scenario '{key}' has no tools")
        if not mapping["description"]:
            errors.append(f"scenario '{key}' has no description")
    return errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Scenario -> agent/skill resolver")
    parser.add_argument("--scenario", help="Scenario or surface keywords (e.g. 'webview ipc crypto')")
    parser.add_argument("--json", action="store_true", help="Output result as JSON")
    parser.add_argument("--list", action="store_true", help="List all scenarios")
    parser.add_argument("--validate", action="store_true", help="Validate mappings against the registry")
    args = parser.parse_args(argv)

    if args.validate:
        errors = validate_mappings()
        if errors:
            for error in errors:
                print(f"[-] {error}")
            return 1
        print(f"[+] {len(SCENARIO_MAPPINGS)} scenario mappings validated against the registry")
        return 0

    if args.list:
        if args.json:
            print(json.dumps(SCENARIO_MAPPINGS, indent=2))
        else:
            for key, mapping in SCENARIO_MAPPINGS.items():
                print(f"{key:<14}{mapping['masvs_category']:<16}{', '.join(mapping['agents'])}")
        return 0

    if not args.scenario:
        parser.print_help()
        return 2

    resolution = resolve_scenario(args.scenario)

    if args.json:
        print(json.dumps(resolution, indent=2))
        return 0 if resolution["matched"] else 1

    if not resolution["matched"]:
        print(f"[!] No scenario matched '{args.scenario}'. Falling back to static analysis.")
        if resolution["unmatched_tokens"]:
            print(f"    Unrecognised keywords: {', '.join(resolution['unmatched_tokens'])}")

    print(f"[*] Resolved skills for scenario: '{args.scenario}'")
    for key, result in resolution["results"].items():
        print(f"\n  [{key.upper()}] - {result['description']}")
        print(f"    - Category:     {result['masvs_category']}")
        print(f"    - Agents:       {', '.join(result['agents'])}")
        print(f"    - Tools:        {', '.join(result['tools'])}")
        print(f"    - Skills:       {', '.join(result['skills']) if result['skills'] else 'None'}")
    if resolution["unmatched_tokens"]:
        print(f"\n  [!] Unrecognised keywords: {', '.join(resolution['unmatched_tokens'])}")
    return 0 if resolution["matched"] else 1


if __name__ == "__main__":
    sys.exit(main())
