#!/usr/bin/env python3
"""
Final report assembly gate (spec §6 Phase 8, spec §8 evidence standard).

`reporting-agent` may only work from findings that survived the lifecycle and
the Hard FP Gate.  The specification also requires an explicit user gate before
a formal report is written.  This module implements both rules:

* it reads finding JSON files from `<workspace>/findings/`,
* recomputes the Hard FP Gate instead of trusting the `state` field,
* includes only evidence-supported `VALIDATED` / `REPORTABLE` findings,
* never writes a report unless `--approve` is passed,
* embeds the current MASVS coverage summary (when available).

A dry run is the default; the CLI exit code still reports structural errors.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:  # executed as a module
    from scripts import compliance_matrix as coverage_mod
    from scripts import findings as findings_mod
except ImportError:  # executed as a plain script
    import compliance_matrix as coverage_mod  # type: ignore[no-redef]
    import findings as findings_mod  # type: ignore[no-redef]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
REPORTABLE_STATES = {"VALIDATED", "REPORTABLE"}


def _load_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _artifact_metadata(workspace: str) -> Dict[str, Any]:
    return _load_json(os.path.join(workspace, "evidence", "artifact.json")) or {}


def collect_findings(workspace: str) -> List[Dict[str, Any]]:
    """Return every parseable finding file plus its gate evaluation."""
    directory = os.path.join(workspace, "findings")
    if not os.path.isdir(directory):
        return []

    rows: List[Dict[str, Any]] = []
    for current, _dirs, names in os.walk(directory):
        for name in sorted(names):
            if not name.lower().endswith(".json"):
                continue
            path = os.path.join(current, name)
            finding = _load_json(path)
            if not finding or not str(finding.get("title") or "").strip():
                continue
            try:
                declared = findings_mod.normalize_state(finding.get("state"))
            except ValueError:
                continue
            gate = findings_mod.evaluate_gate(finding)
            effective = gate["final_state"]
            declared_order = findings_mod.state_order(declared)
            effective_order = findings_mod.state_order(effective)
            rows.append(
                {
                    "finding_id": str(finding.get("finding_id") or os.path.splitext(name)[0]),
                    "title": str(finding.get("title")).strip(),
                    "severity": str(finding.get("severity") or "Informational"),
                    "state": declared,
                    "effective_state": effective,
                    "state_ahead_of_evidence": declared_order > effective_order,
                    "category": str(
                        finding.get("masvs_category") or finding.get("category") or "MASVS-CODE"
                    ),
                    "signature_hash": gate["signature_hash"],
                    "gate": gate,
                    "finding": finding,
                    "path": os.path.relpath(path, workspace).replace("\\", "/"),
                }
            )

    rows.sort(
        key=lambda row: (
            SEVERITY_ORDER.get(row["severity"], 99),
            -findings_mod.state_order(row["state"]),
            row["title"].lower(),
        )
    )
    return rows


def _coverage_summary(workspace: str) -> Dict[str, Any]:
    try:
        matrix = coverage_mod.build_matrix(workspace)
    except Exception as exc:  # pragma: no cover - reporting must not crash
        return {"error": str(exc)}
    return {
        "totals": matrix["totals"],
        "summary": matrix["summary"],
        "gaps": matrix["gaps"][:10],
    }


def build_report(
    workspace: str,
    target: Optional[str] = None,
    approve: bool = False,
) -> Dict[str, Any]:
    """Assemble (and optionally write) the gated final report."""
    workspace = os.path.abspath(workspace)
    metadata = _artifact_metadata(workspace)
    resolved_target = target or str(metadata.get("target") or os.path.basename(workspace))

    candidates = collect_findings(workspace)
    included: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []

    for row in candidates:
        gate = row["gate"]
        if row["state"] not in REPORTABLE_STATES:
            reason = f"state {row['state']} is below VALIDATED"
        elif row["effective_state"] not in REPORTABLE_STATES:
            reason = (
                f"evidence supports only {row['effective_state']}; "
                f"blocking gate checks: {', '.join(gate['blocking_checks']) or 'none'}"
            )
        elif row["state_ahead_of_evidence"]:
            reason = (
                f"declared state {row['state']} exceeds evidence-supported "
                f"state {row['effective_state']}"
            )
        else:
            included.append(row)
            continue
        excluded.append(
            {
                "finding_id": row["finding_id"],
                "title": row["title"],
                "state": row["state"],
                "effective_state": row["effective_state"],
                "reason": reason,
                "path": row["path"],
            }
        )

    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for row in included:
        severity_counts[row["severity"]] = severity_counts.get(row["severity"], 0) + 1

    data: Dict[str, Any] = {
        "target": resolved_target,
        "workspace": workspace,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "approved": bool(approve),
        "approval_required": not approve,
        "artifact": {
            "artifact_path": metadata.get("artifact_path"),
            "artifact_sha256": metadata.get("artifact_sha256"),
            "session_id": metadata.get("session_id"),
            "platform": metadata.get("platform"),
            "scope_lock": "CONFIRMED" if metadata else "UNRECORDED",
        },
        "included": included,
        "excluded": excluded,
        "totals": {
            "candidates": len(candidates),
            "included": len(included),
            "excluded": len(excluded),
            "severity": severity_counts,
            "integrity_issues": sum(1 for row in candidates if row["state_ahead_of_evidence"]),
        },
        "coverage": _coverage_summary(workspace),
        "written_to": None,
    }
    data["markdown"] = render_report(data)

    if approve:
        report_dir = os.path.join(workspace, "reports")
        os.makedirs(report_dir, exist_ok=True)
        path = os.path.join(report_dir, "final-report.md")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(data["markdown"])
        data["written_to"] = path

    return data


def _table(value: Any) -> str:
    return " ".join(str(value).replace("|", "\\|").split())


def _evidence_list(finding: Dict[str, Any]) -> str:
    keys = ("poc_path", "verification_path", "evidence_path")
    values = [str(finding[key]) for key in keys if finding.get(key)]
    if finding.get("poc_command"):
        values.append(f"command: {finding['poc_command']}")
    return "; ".join(values) if values else "not recorded"


def render_report(data: Dict[str, Any]) -> str:
    """Render the final report following the OWASP WSTG reporting structure,
    adapted for mobile assessments with an OWASP MASVS coverage section.

    Structure (OWASP WSTG document/5-Reporting, adapted):
      1. Introduction (version control, scope, limitations, timeline, disclaimer)
      2. Executive summary
      3. Findings (3.1 summary table, 3.2 details per finding incl. likelihood,
         impact, risk, description, remediation, artifacts)
      4. MASVS v2.0 coverage
      Appendices + References
    """
    artifact = data.get("artifact") or {}
    totals = data["totals"]
    coverage = data.get("coverage") or {}
    generated = data["generated_at"]
    lines: List[str] = [
        "# Mobile Application Security Assessment",
        "",
        f"- **Target:** `{data['target']}`",
        f"- **Platform:** {artifact.get('platform') or 'unknown'}",
        f"- **Artifact:** `{artifact.get('artifact_path') or 'not provided'}`",
        f"- **Artifact SHA-256:** `{artifact.get('artifact_sha256') or 'not provided'}`",
        f"- **Session:** `{artifact.get('session_id') or 'not started'}`",
        f"- **Scope lock:** {artifact.get('scope_lock') or 'UNRECORDED'}",
        f"- **Generated:** {generated}",
        f"- **User gate:** {'APPROVED' if data['approved'] else 'NOT APPROVED (dry run)'}",
        "",
        "## 1. Introduction",
        "",
        "### 1.1 Version Control",
        "",
        "| Version | Description | Date | Author |",
        "|:-------:|-------------|------|--------|",
        f"| 1.0 | Initial report (App Scanner `report_builder`) | {generated} | reporting-agent |",
        "",
        "### 1.2 Scope",
        "",
        "Authorized mobile application penetration testing of the target named above, on owned or "
        "explicitly authorized devices/emulators, using owned test accounts only. Testing is limited to "
        "the applications and accounts recorded in the scope lock.",
        "",
        "### 1.3 Limitations",
        "",
        "- Point-in-time assessment: the application and backend may change after testing.",
        "- Out-of-scope areas, broken functionality, lack of credentials, and device tooling gaps "
        "may limit coverage (see MASVS gaps below).",
        "- Findings are reported only when evidence, reproduction, and independent verification support them.",
        "",
        "### 1.4 Timeline",
        "",
        f"- Session: `{artifact.get('session_id') or 'not started'}`",
        f"- Report generated: {generated}",
        "",
        "### 1.5 Disclaimer",
        "",
        "*This test is a point-in-time assessment; the environment may have changed since testing. "
        "There is no guarantee every possible issue was identified. This report is a guiding document, "
        "not a warranty that it fully represents the risks to the system.*",
        "",
        "## 2. Executive Summary",
        "",
        f"{totals['included']} validated finding(s) are included; "
        f"{totals['excluded']} finding file(s) were excluded by the reporting gate.",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity} | {totals['severity'].get(severity, 0)} |")

    if totals["integrity_issues"]:
        lines += [
            "",
            f"> **Integrity warning:** {totals['integrity_issues']} finding file(s) declare a "
            "lifecycle state higher than their evidence supports. They are excluded.",
        ]

    lines += [
        "",
        "## 3. Findings",
        "",
        "### 3.1 Findings Summary",
        "",
        "| Ref. ID | Title | Risk Level |",
        "|:------------:|--------|------------|",
    ]
    for index, row in enumerate(data["included"], start=1):
        lines.append(f"| {index} | {_table(row['title'])} | {row['severity']} |")

    lines += ["", "### 3.2 Findings Details", ""]
    if not data["included"]:
        lines.append("_No finding passed the reporting gate._")
    for index, row in enumerate(data["included"], start=1):
        finding = row["finding"]
        likelihood = (
            finding.get("likelihood")
            or finding.get("exploitability")
            or f"Reproduced {finding.get('reproduced_count', 'not recorded')} time(s); "
            f"chain/leverage: {finding.get('chain') or finding.get('leverage') or 'not recorded'}"
        )
        lines += [
            f"#### {index}. {row['title']}",
            "",
            f"- **Reference ID:** {index}",
            f"- **Finding ID:** `{row['finding_id']}`",
            f"- **Risk Level:** {row['severity']}",
            f"- **State:** {row['state']} (evidence-supported: {row['effective_state']})",
            f"- **Category (MASVS):** {row['category']}",
            f"- **Likelihood / Exploitability:** {likelihood}",
            f"- **Impact:** {finding.get('impact') or 'not recorded'}",
            f"- **Description:** {finding.get('description') or row['title']}",
            f"- **Remediation:** {finding.get('remediation') or 'not recorded — apply MASVS control guidance for this category and re-verify with verification-agent.'}",
            f"- **Signature:** `{row['signature_hash']}`",
            f"- **Reproductions:** {finding.get('reproduced_count', 'not recorded')}",
            f"- **Verification verdict:** {finding.get('verification_verdict') or 'not recorded'}",
            f"- **Evidence / Artifacts:** {_evidence_list(finding)}",
            f"- **Finding file:** `{row['path']}`",
            "",
        ]

    lines += ["## 4. MASVS v2.0 coverage", ""]
    if coverage.get("error"):
        lines.append(f"Coverage unavailable: {coverage['error']}")
    elif coverage:
        cov_totals = coverage["totals"]
        lines += [
            f"- **Controls tested:** {cov_totals['tested']}/{cov_totals['total']}",
            f"- **Partial:** {cov_totals['partial']} | **Not tested:** {cov_totals['not_tested']}",
            "",
            "| Group | Tested | Partial | Not tested |",
            "|---|---|---|---|",
        ]
        for group, stats in coverage["summary"].items():
            lines.append(
                f"| MASVS-{group} | {stats['tested']} | {stats['partial']} | {stats['not_tested']} |"
            )
        if coverage["gaps"]:
            lines += ["", "Highest-priority open gaps:"]
            for gap in coverage["gaps"][:5]:
                lines.append(f"- P{gap['priority']} {gap['id']} -> `{gap['agent']}`")
    else:
        lines.append("_No coverage matrix could be derived from the workspace._")

    if data["excluded"]:
        lines += [
            "",
            "## Excluded by the reporting gate",
            "",
            "| Finding | Declared state | Evidence state | Reason |",
            "|---|---|---|---|",
        ]
        for row in data["excluded"]:
            lines.append(
                f"| {_table(row['title'])} | {row['state']} | {row['effective_state']} | "
                f"{_table(row['reason'])} |"
            )
        lines.append("")

    lines += [
        "## Appendix A. Methodology",
        "",
        "Testing follows the OWASP MASVS / MASTG methodology (see `memory/methodology.md`). "
        "Findings are promoted only through the lifecycle state machine and the 7-question Hard FP Gate, "
        "with independent verification by `verification-agent`.",
        "",
        "## Appendix B. Severity scale",
        "",
        "| Severity | Meaning |",
        "|---|---|",
        "| Critical | Direct compromise / data breach likely |",
        "| High | Significant impact, practical exploitation |",
        "| Medium | Limited impact or harder exploitation |",
        "| Low | Minor impact, defense-in-depth issue |",
        "| Informational | Hardening / best-practice note |",
        "",
        "## Appendix C. Evidence handling",
        "",
        "- Raw evidence remains under the engagement workspace; this report references it.",
        "- Redact cookies, tokens and PII before sharing the report outside the engagement.",
        "- Device-bound claims are included only when a verification verdict and evidence path exist.",
        "",
        "## Reporting gate",
        "",
        "This document was generated only from findings whose lifecycle state and Hard FP Gate "
        "evidence agree. The user gate is explicit: without `--approve` this file is a preview.",
        "",
        "## References",
        "",
        "- OWASP WSTG — Reporting Structure: https://github.com/OWASP/wstg/blob/master/document/5-Reporting/01-Reporting_Structure.md",
        "- OWASP MASVS: https://github.com/OWASP/masvs",
        "- OWASP MASTG: https://github.com/OWASP/mastg",
        "- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org",
        "",
    ]
    return "\n".join(lines)

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Assemble the gated final report")
    parser.add_argument("--workspace", required=True, help="Engagement workspace (testing/<app-package>)")
    parser.add_argument("--target", default=None, help="Target package (defaults to artifact metadata)")
    parser.add_argument(
        "--approve",
        action="store_true",
        help="Explicit user gate: write reports/final-report.md",
    )
    parser.add_argument("--json", action="store_true", help="Print the report data as JSON")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.workspace):
        print(f"[-] Workspace not found: {args.workspace}", file=sys.stderr)
        return 1

    report = build_report(args.workspace, args.target, approve=args.approve)

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    totals = report["totals"]
    print(f"[*] Report preview: {report['target']}")
    print(
        f"    Included: {totals['included']} | Excluded: {totals['excluded']} | "
        f"Candidates: {totals['candidates']}"
    )
    for severity in SEVERITY_ORDER:
        count = totals["severity"].get(severity, 0)
        if count:
            print(f"    {severity}: {count}")
    if totals["integrity_issues"]:
        print(
            f"[!] {totals['integrity_issues']} finding(s) declared a state above their evidence "
            "and were excluded"
        )
    if not args.approve:
        print("[*] Dry run: pass --approve to write reports/final-report.md")
    else:
        print(f"[+] Report written: {report['written_to']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
