#!/usr/bin/env python3
"""
MASVS v2.0 coverage matrix and gap list generator.

`compliance-agent` is analysis-only; this script is the tool it runs.  It maps
every MASVS control to the agent responsible for testing it and to the evidence
directory that proves the test happened, then classifies each control as
`tested`, `partial` or `not-tested`.

Coverage is derived from **evidence files**, never from a policy statement
(spec §5.16: "Never claim coverage from a policy doc rather than evidence").
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# control_id, group, short title, primary agent, evidence sub-directory,
# expected artifact globs, risk priority (1 = highest).
MASVS_CONTROLS: List[Dict[str, Any]] = [
    # MASVS-STORAGE
    {
        "id": "MASVS-STORAGE-1",
        "group": "STORAGE",
        "title": "Sensitive data (PII, credentials, keys) uses platform credential storage",
        "agent": "storage-analysis-agent",
        "evidence_dir": "storage",
        "artifacts": ["*findings*.md", "*storage*.json", "*prefs*", "*keystore*"],
        "priority": 1,
    },
    {
        "id": "MASVS-STORAGE-2",
        "group": "STORAGE",
        "title": "No sensitive data stored outside the app container or credential storage",
        "agent": "storage-analysis-agent",
        "evidence_dir": "storage",
        "artifacts": ["*external*", "*backup*", "*findings*.md"],
        "priority": 1,
    },
    # MASVS-CRYPTO
    {
        "id": "MASVS-CRYPTO-1",
        "group": "CRYPTO",
        "title": "No hardcoded symmetric keys as the sole encryption method",
        "agent": "crypto-analysis-agent",
        "evidence_dir": "crypto",
        "artifacts": ["*findings*.md", "*keys*.json"],
        "priority": 1,
    },
    {
        "id": "MASVS-CRYPTO-2",
        "group": "CRYPTO",
        "title": "Proven implementations of cryptographic primitives",
        "agent": "crypto-analysis-agent",
        "evidence_dir": "crypto",
        "artifacts": ["*findings*.md", "*cipher*.json"],
        "priority": 2,
    },
    # MASVS-AUTH
    {
        "id": "MASVS-AUTH-1",
        "group": "AUTH",
        "title": "Secure authentication and authorization protocols",
        "agent": "network-traffic-agent",
        "evidence_dir": "traffic",
        "artifacts": ["*auth*.md", "*api-map.json", "*.har"],
        "priority": 1,
    },
    {
        "id": "MASVS-AUTH-2",
        "group": "AUTH",
        "title": "Local authentication implemented per platform best practice",
        "agent": "dynamic-agent",
        "evidence_dir": "dynamic",
        "artifacts": ["*auth*.md", "*biometric*", "*findings*.md"],
        "priority": 2,
    },
    {
        "id": "MASVS-AUTH-3",
        "group": "AUTH",
        "title": "Sensitive operations require additional authentication",
        "agent": "dynamic-agent",
        "evidence_dir": "dynamic",
        "artifacts": ["*step-up*", "*reauth*", "*findings*.md"],
        "priority": 2,
    },
    # MASVS-NETWORK
    {
        "id": "MASVS-NETWORK-1",
        "group": "NETWORK",
        "title": "Cleartext communication used only where necessary",
        "agent": "network-traffic-agent",
        "evidence_dir": "traffic",
        "artifacts": ["*transport*.md", "*api-map.json", "*.har"],
        "priority": 1,
    },
    {
        "id": "MASVS-NETWORK-2",
        "group": "NETWORK",
        "title": "Remote endpoint identity verified (TLS / pinning)",
        "agent": "network-traffic-agent",
        "evidence_dir": "traffic",
        "artifacts": ["*transport*.md", "*pinning*", "*.har"],
        "priority": 1,
    },
    # MASVS-PLATFORM
    {
        "id": "MASVS-PLATFORM-1",
        "group": "PLATFORM",
        "title": "IPC mechanisms used securely",
        "agent": "ipc-attack-agent",
        "evidence_dir": "ipc",
        "artifacts": ["*findings*.md", "*components*.json", "*intent*"],
        "priority": 1,
    },
    {
        "id": "MASVS-PLATFORM-2",
        "group": "PLATFORM",
        "title": "WebViews configured securely",
        "agent": "webview-agent",
        "evidence_dir": "webview",
        "artifacts": ["*findings*.md", "*bridge*", "*webview*.json"],
        "priority": 1,
    },
    {
        "id": "MASVS-PLATFORM-3",
        "group": "PLATFORM",
        "title": "User interface and deep links handled securely",
        "agent": "ipc-attack-agent",
        "evidence_dir": "ipc",
        "artifacts": ["*deeplink*", "*findings*.md"],
        "priority": 2,
    },
    # MASVS-CODE
    {
        "id": "MASVS-CODE-1",
        "group": "CODE",
        "title": "App signed and provisioned with a valid certificate",
        "agent": "static-agent",
        "evidence_dir": "static",
        "artifacts": ["*signature*", "*manifest*", "*static-summary*"],
        "priority": 2,
    },
    {
        "id": "MASVS-CODE-2",
        "group": "CODE",
        "title": "Release build settings (no debuggable, backup hardened)",
        "agent": "static-agent",
        "evidence_dir": "static",
        "artifacts": ["*manifest*", "*static-summary*"],
        "priority": 1,
    },
    {
        "id": "MASVS-CODE-3",
        "group": "CODE",
        "title": "Debug symbols stripped from native binaries",
        "agent": "static-agent",
        "evidence_dir": "static",
        "artifacts": ["*native*", "*static-summary*"],
        "priority": 3,
    },
    {
        "id": "MASVS-CODE-4",
        "group": "CODE",
        "title": "Up-to-date platform version and third-party dependencies",
        "agent": "mcp-bug-intel-agent",
        "evidence_dir": "intel",
        "artifacts": ["cve-matches.json", "*intel*"],
        "priority": 2,
    },
    # MASVS-RESILIENCE
    {
        "id": "MASVS-RESILIENCE-1",
        "group": "RESILIENCE",
        "title": "Platform integrity validated",
        "agent": "resilience-agent",
        "evidence_dir": "resilience",
        "artifacts": ["*findings*.md", "*integrity*"],
        "priority": 3,
    },
    {
        "id": "MASVS-RESILIENCE-2",
        "group": "RESILIENCE",
        "title": "Debugging and instrumentation prevented/detected",
        "agent": "resilience-agent",
        "evidence_dir": "resilience",
        "artifacts": ["*anti-debug*", "*findings*.md"],
        "priority": 2,
    },
    {
        "id": "MASVS-RESILIENCE-3",
        "group": "RESILIENCE",
        "title": "Tampering with code and data detected",
        "agent": "resilience-agent",
        "evidence_dir": "resilience",
        "artifacts": ["*tamper*", "*findings*.md"],
        "priority": 2,
    },
    {
        "id": "MASVS-RESILIENCE-4",
        "group": "RESILIENCE",
        "title": "Reverse engineering tools and frameworks detected",
        "agent": "resilience-agent",
        "evidence_dir": "resilience",
        "artifacts": ["*frida*", "*findings*.md"],
        "priority": 3,
    },
    # MASVS-PRIVACY
    {
        "id": "MASVS-PRIVACY-1",
        "group": "PRIVACY",
        "title": "App minimizes use of sensitive data",
        "agent": "storage-analysis-agent",
        "evidence_dir": "storage",
        "artifacts": ["*pii*", "*privacy*", "*findings*.md"],
        "priority": 2,
    },
    {
        "id": "MASVS-PRIVACY-2",
        "group": "PRIVACY",
        "title": "Sensitive data protected against third-party access",
        "agent": "network-traffic-agent",
        "evidence_dir": "traffic",
        "artifacts": ["*pii*", "*transport*.md"],
        "priority": 2,
    },
    {
        "id": "MASVS-PRIVACY-3",
        "group": "PRIVACY",
        "title": "Sensitive data not exposed through the UI",
        "agent": "dynamic-agent",
        "evidence_dir": "dynamic",
        "artifacts": ["*screenshot*", "*ui*", "*findings*.md"],
        "priority": 3,
    },
]

GROUP_ORDER = ["STORAGE", "CRYPTO", "AUTH", "NETWORK", "PLATFORM", "CODE", "RESILIENCE", "PRIVACY"]

IGNORED_EVIDENCE_FILES = {"readme.md", ".gitkeep", ".keep"}


def _evidence_files(workspace: str, subdir: str) -> List[str]:
    directory = os.path.join(workspace, subdir)
    if not os.path.isdir(directory):
        return []
    files: List[str] = []
    for root, _dirs, names in os.walk(directory):
        for name in names:
            if name.lower() in IGNORED_EVIDENCE_FILES:
                continue
            files.append(os.path.relpath(os.path.join(root, name), workspace).replace("\\", "/"))
    return files


def _matches(files: Iterable[str], patterns: Iterable[str]) -> List[str]:
    matched: List[str] = []
    for path in files:
        basename = os.path.basename(path).lower()
        for pattern in patterns:
            if fnmatch.fnmatch(basename, pattern.lower()):
                matched.append(path)
                break
    return matched


def build_matrix(workspace: str) -> Dict[str, Any]:
    """Classify every MASVS control from the evidence tree."""
    workspace = os.path.abspath(workspace)
    cache: Dict[str, List[str]] = {}
    rows: List[Dict[str, Any]] = []

    for control in MASVS_CONTROLS:
        subdir = control["evidence_dir"]
        if subdir not in cache:
            cache[subdir] = _evidence_files(workspace, subdir)
        files = cache[subdir]
        matched = _matches(files, control["artifacts"])

        if matched:
            status = "tested"
            evidence = ", ".join(matched[:3])
        elif files:
            status = "partial"
            evidence = ", ".join(files[:3])
        else:
            status = "not-tested"
            evidence = ""

        rows.append(
            {
                "id": control["id"],
                "group": control["group"],
                "title": control["title"],
                "agent": control["agent"],
                "evidence_dir": subdir,
                "status": status,
                "evidence": evidence,
                "priority": control["priority"],
            }
        )

    summary: Dict[str, Dict[str, int]] = {}
    for group in GROUP_ORDER:
        group_rows = [row for row in rows if row["group"] == group]
        summary[group] = {
            "total": len(group_rows),
            "tested": sum(1 for row in group_rows if row["status"] == "tested"),
            "partial": sum(1 for row in group_rows if row["status"] == "partial"),
            "not_tested": sum(1 for row in group_rows if row["status"] == "not-tested"),
        }

    gaps = sorted(
        (row for row in rows if row["status"] != "tested"),
        key=lambda row: (row["priority"], row["id"]),
    )

    return {
        "workspace": workspace,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "controls": rows,
        "summary": summary,
        "totals": {
            "total": len(rows),
            "tested": sum(1 for row in rows if row["status"] == "tested"),
            "partial": sum(1 for row in rows if row["status"] == "partial"),
            "not_tested": sum(1 for row in rows if row["status"] == "not-tested"),
        },
        "gaps": gaps,
    }


def render_coverage_markdown(matrix: Dict[str, Any], target: Optional[str] = None) -> str:
    totals = matrix["totals"]
    lines = [
        "# MASVS v2.0 Coverage Matrix",
        "",
        f"- **Target:** `{target or os.path.basename(matrix['workspace'])}`",
        f"- **Evidence root:** `{matrix['workspace']}`",
        f"- **Generated:** {matrix['generated_at']}",
        f"- **Controls:** {totals['tested']}/{totals['total']} tested · "
        f"{totals['partial']} partial · {totals['not_tested']} not tested",
        "",
        "## Summary by group",
        "",
        "| Group | Tested | Partial | Not tested | Total |",
        "|---|---|---|---|---|",
    ]
    for group in GROUP_ORDER:
        stats = matrix["summary"][group]
        lines.append(
            f"| MASVS-{group} | {stats['tested']} | {stats['partial']} | {stats['not_tested']} | {stats['total']} |"
        )

    lines += ["", "## Controls", "", "| Control | Status | Owner agent | Evidence |", "|---|---|---|---|"]
    for row in matrix["controls"]:
        evidence = f"`{row['evidence']}`" if row["evidence"] else "—"
        lines.append(f"| {row['id']} | {row['status']} | `{row['agent']}` | {evidence} |")

    return "\n".join(lines) + "\n"


def render_gap_list_markdown(matrix: Dict[str, Any], target: Optional[str] = None) -> str:
    lines = [
        "# MASVS Gap List",
        "",
        f"- **Target:** `{target or os.path.basename(matrix['workspace'])}`",
        f"- **Generated:** {matrix['generated_at']}",
        f"- **Open gaps:** {len(matrix['gaps'])}",
        "",
        "| Priority | Control | Status | Recommended agent | Why it matters |",
        "|---|---|---|---|---|",
    ]
    for row in matrix["gaps"]:
        lines.append(
            f"| P{row['priority']} | {row['id']} | {row['status']} | `{row['agent']}` | {row['title']} |"
        )
    if not matrix["gaps"]:
        lines.append("| — | — | — | — | No open gaps: every control has matching evidence |")
    lines += [
        "",
        "## Next actions",
        "",
        "1. Re-dispatch the recommended agent for every P1 gap.",
        "2. Convert `partial` rows into `tested` by writing the expected artifact into the evidence directory.",
        "3. Re-run `python scripts/compliance_matrix.py` after each milestone.",
    ]
    return "\n".join(lines) + "\n"


def write_reports(matrix: Dict[str, Any], target: Optional[str] = None) -> Dict[str, str]:
    compliance_dir = os.path.join(matrix["workspace"], "compliance")
    os.makedirs(compliance_dir, exist_ok=True)
    coverage_path = os.path.join(compliance_dir, "masvs-coverage.md")
    gap_path = os.path.join(compliance_dir, "gap-list.md")
    with open(coverage_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_coverage_markdown(matrix, target))
    with open(gap_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_gap_list_markdown(matrix, target))
    return {"coverage": coverage_path, "gaps": gap_path}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="MASVS v2.0 coverage matrix and gap list")
    parser.add_argument("--workspace", required=True, help="Engagement workspace (testing/<app-package>)")
    parser.add_argument("--target", default=None, help="Target package name (for the report header)")
    parser.add_argument("--json", action="store_true", help="Print the matrix as JSON")
    parser.add_argument("--no-write", action="store_true", help="Do not write compliance/*.md")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.workspace):
        print(f"[-] Workspace not found: {args.workspace}", file=sys.stderr)
        return 1

    matrix = build_matrix(args.workspace)

    if not args.no_write:
        paths = write_reports(matrix, args.target)
        matrix["report_paths"] = paths

    if args.json:
        print(json.dumps(matrix, indent=2))
        return 0

    totals = matrix["totals"]
    print(f"[*] MASVS coverage: {totals['tested']}/{totals['total']} tested | "
          f"{totals['partial']} partial | {totals['not_tested']} not tested")
    for group in GROUP_ORDER:
        stats = matrix["summary"][group]
        print(f"    {group:<11}: {stats['tested']}/{stats['total']} "
              f"(partial {stats['partial']}, untested {stats['not_tested']})")
    if matrix["gaps"]:
        print("[*] Highest-risk gaps:")
        for row in matrix["gaps"][:5]:
            print(f"    P{row['priority']} {row['id']} -> {row['agent']} ({row['status']})")
    if not args.no_write:
        print(f"[+] Coverage matrix: {matrix['report_paths']['coverage']}")
        print(f"[+] Gap list:        {matrix['report_paths']['gaps']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
