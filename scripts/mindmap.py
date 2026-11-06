#!/usr/bin/env python3
"""
Attack-surface mindmap builder for an engagement workspace.

The specification requires `notes/MINDMAP.md` for every target (spec §7) and
asks for it to be updated during wrap-up (spec §6 Phase 9).  The bootstrap
skeleton is deliberately generic; this module turns real workspace artifacts
into a current map:

* one Mermaid node per MASVS group with evidence counts,
* one child node per finding (severity, lifecycle state, category),
* a ranked surface table and a finding index,
* the artifact hash / session identity from `evidence/artifact.json`.

The builder is read-only unless `write_mindmap()` (or the CLI without
`--no-write`/`--check`) is used.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:  # executed as a module
    from scripts import findings as findings_mod
except ImportError:  # executed as a plain script
    import findings as findings_mod  # type: ignore[no-redef]

GROUP_ORDER: Tuple[str, ...] = (
    "STORAGE",
    "CRYPTO",
    "AUTH",
    "NETWORK",
    "PLATFORM",
    "CODE",
    "RESILIENCE",
    "PRIVACY",
    "OTHER",
)

# Evidence directories mapped to the MASVS group(s) they support.
SURFACES: Tuple[Dict[str, Any], ...] = (
    {"dir": "static", "label": "Static analysis", "agent": "static-agent", "groups": ("CODE",)},
    {"dir": "intel", "label": "CVE / dependency intel", "agent": "mcp-bug-intel-agent", "groups": ("CODE",)},
    {"dir": "frida", "label": "Frida instrumentation", "agent": "frida-script-agent", "groups": ("OTHER",)},
    {"dir": "dynamic", "label": "Dynamic exploration", "agent": "dynamic-agent", "groups": ("AUTH", "PLATFORM", "PRIVACY")},
    {"dir": "traffic", "label": "Traffic and API analysis", "agent": "network-traffic-agent", "groups": ("AUTH", "NETWORK", "PRIVACY")},
    {"dir": "crypto", "label": "Cryptography", "agent": "crypto-analysis-agent", "groups": ("CRYPTO",)},
    {"dir": "storage", "label": "Storage and data at rest", "agent": "storage-analysis-agent", "groups": ("STORAGE", "PRIVACY")},
    {"dir": "ipc", "label": "IPC and deep links", "agent": "ipc-attack-agent", "groups": ("PLATFORM",)},
    {"dir": "webview", "label": "WebView and bridges", "agent": "webview-agent", "groups": ("PLATFORM",)},
    {"dir": "resilience", "label": "Resilience and anti-tamper", "agent": "resilience-agent", "groups": ("RESILIENCE",)},
    {"dir": "exploitation", "label": "Exploitation / PoC", "agent": "exploitation-agent", "groups": ("OTHER",)},
    {"dir": "verification", "label": "Adversarial verification", "agent": "verification-agent", "groups": ("OTHER",)},
    {"dir": "compliance", "label": "MASVS coverage", "agent": "compliance-agent", "groups": ("OTHER",)},
)

IGNORED_EVIDENCE_FILES = {"readme.md", ".gitkeep", ".keep"}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
STATE_ORDER = {
    "REPORTABLE": 0,
    "VALIDATED": 1,
    "CONFIRMED": 2,
    "HIGH_CONFIDENCE": 3,
    "LEAD": 4,
    "OBSERVATION": 5,
    "INFORMATIONAL": 6,
}


def _evidence_files(workspace: str, subdir: str) -> List[str]:
    directory = os.path.join(workspace, subdir)
    if not os.path.isdir(directory):
        return []
    files: List[str] = []
    for current, _dirs, names in os.walk(directory):
        for name in names:
            if name.lower() in IGNORED_EVIDENCE_FILES:
                continue
            files.append(os.path.relpath(os.path.join(current, name), workspace).replace("\\", "/"))
    return sorted(files)


def _group_for_category(category: str) -> str:
    upper = (category or "").upper()
    for group in GROUP_ORDER:
        if group in upper:
            return group
    return "OTHER"


def _normalize_state(value: Any) -> str:
    try:
        return findings_mod.normalize_state(str(value or "OBSERVATION"))
    except ValueError:
        return str(value or "OBSERVATION").upper()


def _read_artifact_metadata(workspace: str) -> Dict[str, Any]:
    path = os.path.join(workspace, "evidence", "artifact.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def collect_findings(workspace: str) -> List[Dict[str, Any]]:
    """Load finding JSON objects from `findings/` (recursively)."""
    directory = os.path.join(workspace, "findings")
    if not os.path.isdir(directory):
        return []

    collected: List[Dict[str, Any]] = []
    for current, _dirs, names in os.walk(directory):
        for name in sorted(names):
            if not name.lower().endswith(".json"):
                continue
            path = os.path.join(current, name)
            try:
                with open(path, "r", encoding="utf-8-sig") as handle:
                    data = json.load(handle)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict) or not str(data.get("title") or "").strip():
                continue
            category = str(data.get("masvs_category") or data.get("category") or "MASVS-CODE")
            collected.append(
                {
                    "finding_id": str(data.get("finding_id") or os.path.splitext(name)[0]),
                    "title": str(data.get("title")).strip(),
                    "severity": str(data.get("severity") or "Informational"),
                    "state": _normalize_state(data.get("state")),
                    "category": category,
                    "group": _group_for_category(category),
                    "path": os.path.relpath(path, workspace).replace("\\", "/"),
                }
            )

    collected.sort(
        key=lambda row: (
            STATE_ORDER.get(row["state"], 99),
            SEVERITY_ORDER.get(row["severity"], 99),
            row["title"].lower(),
        )
    )
    return collected


def build_mindmap(workspace: str, target: Optional[str] = None) -> Dict[str, Any]:
    """Return the structured mindmap for a workspace (never writes)."""
    workspace = os.path.abspath(workspace)
    metadata = _read_artifact_metadata(workspace)
    resolved_target = target or str(metadata.get("target") or os.path.basename(workspace))

    surfaces: List[Dict[str, Any]] = []
    files_by_group: Dict[str, set] = {group: set() for group in GROUP_ORDER}
    for surface in SURFACES:
        files = _evidence_files(workspace, surface["dir"])
        for group in surface["groups"]:
            files_by_group[group].update(files)
        surfaces.append(
            {
                "dir": surface["dir"],
                "label": surface["label"],
                "agent": surface["agent"],
                "groups": list(surface["groups"]),
                "evidence_count": len(files),
                "evidence": files[:5],
            }
        )

    findings = collect_findings(workspace)
    for finding in findings:
        finding["_sort"] = (
            SEVERITY_ORDER.get(finding["severity"], 99),
            STATE_ORDER.get(finding["state"], 99),
        )

    groups: List[Dict[str, Any]] = []
    for group in GROUP_ORDER:
        group_findings = [row for row in findings if row["group"] == group]
        if not files_by_group[group] and not group_findings:
            continue
        highest = min(
            (row["severity"] for row in group_findings),
            key=lambda value: SEVERITY_ORDER.get(value, 99),
            default="—",
        )
        groups.append(
            {
                "group": group,
                "evidence_count": len(files_by_group[group]),
                "findings_count": len(group_findings),
                "highest_severity": highest,
                "agents": sorted({row["agent"] for row in surfaces if group in row["groups"]}),
            }
        )

    groups.sort(
        key=lambda row: (
            -row["findings_count"],
            SEVERITY_ORDER.get(row["highest_severity"], 99),
            -row["evidence_count"],
            GROUP_ORDER.index(row["group"]),
        )
    )

    state_counts: Dict[str, int] = {}
    for row in findings:
        state_counts[row["state"]] = state_counts.get(row["state"], 0) + 1

    return {
        "target": resolved_target,
        "workspace": workspace,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "artifact": {
            "artifact_sha256": metadata.get("artifact_sha256"),
            "artifact_path": metadata.get("artifact_path"),
            "session_id": metadata.get("session_id"),
            "platform": metadata.get("platform"),
            "mode": metadata.get("mode"),
        },
        "surfaces": surfaces,
        "groups": groups,
        "findings": [
            {key: value for key, value in row.items() if key != "_sort"} for row in findings
        ],
        "totals": {
            "surfaces_with_evidence": sum(1 for row in surfaces if row["evidence_count"]),
            "evidence_files": sum(row["evidence_count"] for row in surfaces),
            "findings": len(findings),
            "state_counts": state_counts,
        },
    }


def _escape(label: str, limit: int = 64) -> str:
    text = " ".join(str(label).replace('"', "'").split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _table(value: Any) -> str:
    return " ".join(str(value).replace("|", "\\|").split())


def _node_id(prefix: str, value: str) -> str:
    cleaned = "".join(char if char.isalnum() else "_" for char in value)
    return f"{prefix}_{cleaned}"


def render_markdown(data: Dict[str, Any]) -> str:
    """Render a human-readable markdown page with a Mermaid graph."""
    target = data["target"]
    artifact = data.get("artifact") or {}
    totals = data["totals"]

    lines: List[str] = [
        f"# Attack Surface Mindmap: {target}",
        "",
        "> Generated by `python scripts/mindmap.py`. Re-run after each milestone.",
        "",
        f"- **Workspace:** `{data['workspace']}`",
        f"- **Generated:** {data['generated_at']}",
        f"- **Platform:** {artifact.get('platform') or 'unknown'}",
        f"- **Artifact SHA-256:** `{artifact.get('artifact_sha256') or 'not provided'}`",
        f"- **Session:** `{artifact.get('session_id') or 'not started'}`",
        f"- **Findings:** {totals['findings']} "
        f"({', '.join(f'{key}={value}' for key, value in sorted(totals['state_counts'].items())) or 'none'})",
        "",
        "## Map",
        "",
        "```mermaid",
        "graph TD",
        f"  Root[\"{_escape(target)}\"]",
    ]

    if data["groups"]:
        for index, group in enumerate(data["groups"]):
            group_id = f"G{index}"
            label = (
                f"{group['group']} | evidence {group['evidence_count']} | "
                f"findings {group['findings_count']}"
            )
            lines.append(f"  Root --> {group_id}[\"{_escape(label)}\"]")
            group_findings = [row for row in data["findings"] if row["group"] == group["group"]]
            for finding in group_findings:
                finding_id = f"F{index}_{_node_id('x', finding['finding_id'])}"
                finding_label = f"[{finding['severity']}/{finding['state']}] {finding['title']}"
                lines.append(f"  {group_id} --> {finding_id}[\"{_escape(finding_label, 72)}\"]")
    else:
        lines.append(f"  Root --> Empty[\"No evidence or findings yet\"]")

    lines += ["```", "", "## Ranked surfaces", ""]
    if data["groups"]:
        lines += [
            "| MASVS group | Evidence files | Findings | Highest severity | Owner agents |",
            "|---|---|---|---|---|",
        ]
        for group in data["groups"]:
            lines.append(
                f"| {group['group']} | {group['evidence_count']} | {group['findings_count']} | "
                f"{group['highest_severity']} | {', '.join(group['agents']) or '—'} |"
            )
    else:
        lines.append("_No evidence directories are populated yet._")

    lines += ["", "## Findings", ""]
    if data["findings"]:
        lines += [
            "| Severity | State | Title | Category | File |",
            "|---|---|---|---|---|",
        ]
        for row in data["findings"]:
            lines.append(
                f"| {_table(row['severity'])} | {_table(row['state'])} | {_table(row['title'])} | "
                f"{_table(row['category'])} | `{row['path']}` |"
            )
    else:
        lines.append("_No finding JSON files under `findings/` yet._")

    lines += [
        "",
        "## Next actions",
        "",
        "1. Re-dispatch the owner agent for every group with findings but no verification evidence.",
        "2. Add finding JSON files under `findings/`; re-run this builder to refresh the map.",
        "3. Run `python scripts/orchestrator_runner.py coverage --target <package>` before reporting.",
        "",
    ]
    return "\n".join(lines)


def write_mindmap(data: Dict[str, Any], path: Optional[str] = None) -> str:
    target_path = path or os.path.join(data["workspace"], "notes", "MINDMAP.md")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_markdown(data))
    return target_path


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8-sig") as handle:
        return handle.read()


def comparable_markdown(markdown: str) -> str:
    """Strip the volatile generation timestamp before staleness comparison."""
    return "\n".join(
        line for line in markdown.splitlines() if not line.startswith("- **Generated:**")
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build the workspace attack-surface mindmap")
    parser.add_argument("--workspace", required=True, help="Engagement workspace (testing/<app-package>)")
    parser.add_argument("--target", default=None, help="Target package (defaults to artifact metadata)")
    parser.add_argument("--json", action="store_true", help="Print the structured map as JSON")
    parser.add_argument("--no-write", action="store_true", help="Do not rewrite notes/MINDMAP.md")
    parser.add_argument("--check", action="store_true", help="Fail if notes/MINDMAP.md is stale")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.workspace):
        print(f"[-] Workspace not found: {args.workspace}", file=sys.stderr)
        return 1

    data = build_mindmap(args.workspace, args.target)
    path = os.path.join(data["workspace"], "notes", "MINDMAP.md")

    if args.check:
        if not os.path.isfile(path):
            print("[-] notes/MINDMAP.md is missing; run: python scripts/mindmap.py --workspace <ws>")
            return 1
        if comparable_markdown(read_text(path)) != comparable_markdown(render_markdown(data)):
            print("[-] notes/MINDMAP.md is out of date; run: python scripts/mindmap.py --workspace <ws>")
            return 1
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print("[+] notes/MINDMAP.md is up to date")
        return 0

    if not args.no_write:
        write_mindmap(data, path)

    if args.json:
        data["path"] = path
        print(json.dumps(data, indent=2))
    else:
        totals = data["totals"]
        print(f"[*] Mindmap: {data['target']} -> {path}")
        print(
            f"    Evidence files: {totals['evidence_files']} | "
            f"Findings: {totals['findings']} | Populated surfaces: {totals['surfaces_with_evidence']}"
        )
        if not args.no_write:
            print("[+] Mindmap written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
