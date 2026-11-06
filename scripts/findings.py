#!/usr/bin/env python3
"""
Finding lifecycle, Hard False-Positive Gate and FP signature database.

This module is the single implementation of the rules documented in
`AGENTS.md` §3 and the spec §9:

    OBSERVATION -> LEAD -> HIGH-CONFIDENCE -> CONFIRMED -> VALIDATED -> REPORTABLE

Design rules
------------
* The gate never *promotes* a finding by itself.  It answers "may this finding
  be promoted to REPORTABLE?" and reports the highest state the evidence
  supports.  Promotion is an explicit `transition` with guard checks.
* A finding can never reach REPORTABLE without `user_approved`, because the
  reporting gate is an explicit user action (spec §6 Phase 8).
* The FP database is parsed as structured rows and matched by *exact*
  signature hash — never by substring.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FP_DB_PATH = os.path.join(ROOT_DIR, "memory", "FALSE_POSITIVE_DB.md")

# Ordered lifecycle.  INFORMATIONAL is a terminal side state for rejected leads.
STATES: Tuple[str, ...] = (
    "OBSERVATION",
    "LEAD",
    "HIGH_CONFIDENCE",
    "CONFIRMED",
    "VALIDATED",
    "REPORTABLE",
    "INFORMATIONAL",
)

STATE_ALIASES = {
    "HIGH-CONFIDENCE": "HIGH_CONFIDENCE",
    "HIGH CONFIDENCE": "HIGH_CONFIDENCE",
    "INFO": "INFORMATIONAL",
}

CONFIDENCE_RANGE = {
    "OBSERVATION": "0%",
    "LEAD": "10-30%",
    "HIGH_CONFIDENCE": "30-60%",
    "CONFIRMED": "60-85%",
    "VALIDATED": "85-95%",
    "REPORTABLE": "95-100%",
    "INFORMATIONAL": "0%",
}

# Allowed forward transitions plus the universal downgrade to INFORMATIONAL.
ALLOWED_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    "OBSERVATION": ("LEAD", "INFORMATIONAL"),
    "LEAD": ("HIGH_CONFIDENCE", "INFORMATIONAL"),
    "HIGH_CONFIDENCE": ("CONFIRMED", "INFORMATIONAL"),
    "CONFIRMED": ("VALIDATED", "INFORMATIONAL"),
    "VALIDATED": ("REPORTABLE", "INFORMATIONAL"),
    "REPORTABLE": ("INFORMATIONAL",),
    "INFORMATIONAL": (),
}

PLACEHOLDER_VALUES = {
    "",
    "n/a",
    "na",
    "none",
    "null",
    "tbd",
    "todo",
    "unknown",
    "placeholder",
    "fixme",
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def normalize_state(state: Optional[str]) -> str:
    if not state:
        return "OBSERVATION"
    cleaned = str(state).strip().upper().replace(" ", "_").replace("-", "_")
    cleaned = STATE_ALIASES.get(cleaned, cleaned)
    if cleaned not in STATES:
        raise ValueError(f"Unknown finding state '{state}'. Valid states: {', '.join(STATES)}")
    return cleaned


def state_order(state: str) -> int:
    return STATES.index(normalize_state(state))


def signature_hash(category: str, identifier: str, signal: str) -> str:
    """SHA256(category:identifier:signal)[:8] as defined in the FP DB header."""
    raw = f"{category}:{identifier}:{signal}".strip()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in PLACEHOLDER_VALUES
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return bool(value)


def _resolve_path(path: str, root_dir: str) -> Optional[str]:
    if not path:
        return None
    candidates = [path]
    if not os.path.isabs(path):
        candidates.append(os.path.join(root_dir, path))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return None


# --------------------------------------------------------------------------- #
# False-positive signature database
# --------------------------------------------------------------------------- #
FP_ROW_RE = re.compile(
    r"^\|\s*`?([0-9a-fA-F]{8})`?\s*\|\s*([^|]*)\|\s*([^|]*)\|\s*([^|]*)\|\s*$"
)
FP_SECTION_HEADING = "## Signature Hash Format"


class FalsePositiveDB:
    """Structured access to `memory/FALSE_POSITIVE_DB.md`."""

    def __init__(self, path: str = FP_DB_PATH):
        self.path = path
        self._entries: Optional[List[Dict[str, str]]] = None

    def entries(self, refresh: bool = False) -> List[Dict[str, str]]:
        if self._entries is not None and not refresh:
            return list(self._entries)
        rows: List[Dict[str, str]] = []
        if os.path.isfile(self.path):
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    match = FP_ROW_RE.match(line.rstrip("\r\n"))
                    if not match:
                        continue
                    rows.append(
                        {
                            "signature_hash": match.group(1).lower(),
                            "category": match.group(2).strip(),
                            "description": match.group(3).strip(),
                            "reason": match.group(4).strip(),
                        }
                    )
        self._entries = rows
        return list(rows)

    def lookup(self, sig: str) -> Optional[Dict[str, str]]:
        sig = (sig or "").strip().lower().lstrip("`").rstrip("`")
        if not sig:
            return None
        for entry in self.entries():
            if entry["signature_hash"] == sig:
                return entry
        return None

    def contains(self, sig: str) -> bool:
        return self.lookup(sig) is not None

    def add(
        self,
        sig: str,
        category: str,
        description: str,
        reason: str,
        dry_run: bool = False,
    ) -> bool:
        """Append a row to the markdown table. Returns False when already present."""
        sig = (sig or "").strip().lower().lstrip("`").rstrip("`")
        if not re.fullmatch(r"[0-9a-f]{8}", sig):
            raise ValueError("Signature hash must be exactly 8 hexadecimal characters")
        if self.contains(sig):
            return False
        for label, value in (("category", category), ("description", description), ("reason", reason)):
            if not _has_value(value):
                raise ValueError(f"FP entry field '{label}' must not be empty")
        row = f"| `{sig}` | {category} | {description} | {reason} |\n"
        if dry_run:
            return True

        if not os.path.isfile(self.path):
            raise FileNotFoundError(f"False-positive database not found at {self.path}")

        with open(self.path, "r", encoding="utf-8") as handle:
            content = handle.read()

        if FP_SECTION_HEADING in content:
            head, tail = content.split(FP_SECTION_HEADING, 1)
            head = head.rstrip("\n") + "\n" + row + "\n"
            content = head + FP_SECTION_HEADING + tail
        else:
            content = content.rstrip("\n") + "\n" + row

        with open(self.path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        self._entries = None
        return True


# --------------------------------------------------------------------------- #
# Hard False-Positive Gate
# --------------------------------------------------------------------------- #
CHECK_LABELS = {
    "1_real_impact": "Real impact (specific unauthorized data access, privilege escalation or state tampering)",
    "2_exploitable": "Exploitable (deterministic PoC path/command present)",
    "3_leverageable": "Leverageable (chains into ATO / RCE / cross-tenant / admin bypass)",
    "4_raw_poc_reproducible": "Raw PoC reproduced at least twice on clean state",
    "5_cross_context": "Cross-context verified (>= 2 accounts/roles/tenants)",
    "6_fp_db_cleared": "Signature hash absent from memory/FALSE_POSITIVE_DB.md",
    "7_verification_agent_verdict": "verification-agent verdict is CONFIRMED_VALIDATED",
}


def evaluate_gate(
    finding: Dict[str, Any],
    fp_db: Optional[FalsePositiveDB] = None,
    root_dir: str = ROOT_DIR,
) -> Dict[str, Any]:
    """Evaluate the 7-question Hard FP Gate for a finding.

    Returns a dict with per-check booleans, human-readable details, the
    signature hash, whether the reporting gate is open, and the highest state
    the evidence supports.  It never mutates the finding or the database.
    """
    db = fp_db or FalsePositiveDB()
    title = str(finding.get("title") or "").strip()
    category = str(finding.get("masvs_category") or finding.get("category") or "MASVS-CODE").strip()
    identifier = str(finding.get("identifier") or title)
    impact = str(finding.get("impact") or "")
    sig = str(finding.get("signature_hash") or signature_hash(category, identifier, impact))

    fp_entry = db.lookup(sig)

    poc_path = finding.get("poc_path") or ""
    poc_command = finding.get("poc_command") or ""
    resolved_poc = _resolve_path(poc_path, root_dir)
    verification_path = finding.get("verification_path") or ""
    resolved_verification = _resolve_path(verification_path, root_dir) if verification_path else None

    cross_contexts = finding.get("cross_contexts") or []
    if isinstance(cross_contexts, str):
        cross_contexts = [cross_contexts]

    try:
        reproduced = int(finding.get("reproduced_count") or 0)
    except (TypeError, ValueError):
        reproduced = 0

    severity = str(finding.get("severity") or "").strip()
    impact_has_value = _has_value(impact)
    exploit_evidence = bool(resolved_poc or (poc_command and str(poc_command).strip()))

    details: Dict[str, str] = {}
    checks: Dict[str, bool] = {}

    checks["1_real_impact"] = impact_has_value and severity in {"Critical", "High", "Medium", "Low"}
    details["1_real_impact"] = (
        f"severity={severity or 'unset'}, impact={'set' if impact_has_value else 'missing/placeholder'}"
    )

    checks["2_exploitable"] = exploit_evidence
    if resolved_poc:
        details["2_exploitable"] = f"PoC file found: {resolved_poc}"
    elif poc_command:
        details["2_exploitable"] = "PoC command present (no file to verify)"
    elif poc_path:
        details["2_exploitable"] = f"PoC path does not exist: {poc_path}"
    else:
        details["2_exploitable"] = "No poc_path or poc_command supplied"

    chain = finding.get("chain") or finding.get("leverage") or ""
    checks["3_leverageable"] = _has_value(chain) or severity in {"Critical", "High"}
    details["3_leverageable"] = (
        f"chain={chain or 'not stated'}, severity={severity or 'unset'} "
        "(Medium/Low requires an explicit chain to REPORTABLE-level impact)"
    )

    checks["4_raw_poc_reproducible"] = reproduced >= 2
    details["4_raw_poc_reproducible"] = f"reproduced_count={reproduced} (need >= 2)"

    checks["5_cross_context"] = bool(finding.get("cross_context_verified")) or len(cross_contexts) >= 2
    details["5_cross_context"] = (
        f"cross_context_verified={bool(finding.get('cross_context_verified'))}, "
        f"contexts={len(cross_contexts)}"
    )

    checks["6_fp_db_cleared"] = fp_entry is None
    details["6_fp_db_cleared"] = (
        "known false positive: " + str(fp_entry.get("description"))
        if fp_entry
        else "no matching signature in FP database"
    )

    verdict = str(finding.get("verification_verdict") or "").strip().upper()
    verification_ok = verdict == "CONFIRMED_VALIDATED"
    if verification_ok and verification_path and not resolved_verification:
        verification_ok = False
        details["7_verification_agent_verdict"] = (
            f"verdict={verdict or 'missing'} but verification evidence missing: {verification_path}"
        )
    else:
        details["7_verification_agent_verdict"] = f"verdict={verdict or 'missing'}"

    checks["7_verification_agent_verdict"] = verification_ok

    blocking = [key for key, passed in checks.items() if not passed]
    approved = not blocking
    user_approved = bool(finding.get("user_approved"))

    highest = highest_supported_state(finding, fp_entry)
    if approved and user_approved:
        final_state = "REPORTABLE"
    else:
        final_state = highest

    return {
        "finding_title": title or "(untitled)",
        "signature_hash": sig,
        "checks": checks,
        "check_labels": dict(CHECK_LABELS),
        "details": details,
        "blocking_checks": blocking,
        "in_fp_db": fp_entry is not None,
        "fp_entry": fp_entry,
        "verdict": "APPROVED" if approved else "DOWNGRADED",
        "reporting_gate_open": bool(approved and user_approved),
        "highest_supported_state": highest,
        "final_state": final_state,
        "confidence": CONFIDENCE_RANGE.get(final_state, "0%"),
    }


def highest_supported_state(
    finding: Dict[str, Any],
    fp_entry: Optional[Dict[str, str]] = None,
) -> str:
    """Highest lifecycle state justified by the finding's evidence."""
    if fp_entry is not None:
        return "INFORMATIONAL"

    impact = _has_value(finding.get("impact"))
    try:
        reproduced = int(finding.get("reproduced_count") or 0)
    except (TypeError, ValueError):
        reproduced = 0

    if not impact:
        return "OBSERVATION"
    if reproduced < 2:
        return "OBSERVATION"
    if not finding.get("effect_demonstrated"):
        return "LEAD"

    has_poc = _has_value(finding.get("poc_path")) or _has_value(finding.get("poc_command"))
    if not has_poc:
        return "HIGH_CONFIDENCE"

    verdict = str(finding.get("verification_verdict") or "").strip().upper()
    cross_context = bool(finding.get("cross_context_verified")) or len(finding.get("cross_contexts") or []) >= 2
    if verdict != "CONFIRMED_VALIDATED" or not cross_context:
        return "CONFIRMED"

    severity = str(finding.get("severity") or "")
    leverageable = _has_value(finding.get("chain") or finding.get("leverage")) or severity in {"Critical", "High"}
    if leverageable and finding.get("user_approved"):
        return "REPORTABLE"
    return "VALIDATED"


# --------------------------------------------------------------------------- #
# State machine
# --------------------------------------------------------------------------- #
def check_transition(
    finding: Dict[str, Any],
    target_state: str,
    fp_db: Optional[FalsePositiveDB] = None,
) -> Dict[str, Any]:
    """Validate a lifecycle transition, returning reasons for a refusal."""
    current = normalize_state(finding.get("state"))
    target = normalize_state(target_state)
    reasons: List[str] = []

    if target not in ALLOWED_TRANSITIONS.get(current, ()):
        reasons.append(f"Illegal transition {current} -> {target}")

    try:
        reproduced = int(finding.get("reproduced_count") or 0)
    except (TypeError, ValueError):
        reproduced = 0

    if target == "LEAD" and reproduced < 2:
        reasons.append("LEAD requires the observation to be reproduced twice on a clean state")
    if target == "HIGH_CONFIDENCE" and not finding.get("effect_demonstrated"):
        reasons.append("HIGH_CONFIDENCE requires a demonstrated server-side or device-side effect")
    if target == "CONFIRMED":
        if not _has_value(finding.get("impact")):
            reasons.append("CONFIRMED requires a defined impact statement")
        if not (_has_value(finding.get("poc_path")) or _has_value(finding.get("poc_command"))):
            reasons.append("CONFIRMED requires a raw PoC path or command")
    if target == "VALIDATED":
        if str(finding.get("verification_verdict") or "").upper() != "CONFIRMED_VALIDATED":
            reasons.append("VALIDATED requires verification_verdict = CONFIRMED_VALIDATED")
    if target == "REPORTABLE":
        gate = evaluate_gate(finding, fp_db)
        reasons.extend(f"Gate check failed: {key}" for key in gate["blocking_checks"])
        if not finding.get("user_approved"):
            reasons.append("REPORTABLE requires explicit user approval of the reporting gate")

    return {
        "from": current,
        "to": target,
        "allowed": not reasons,
        "reasons": reasons,
    }


def apply_transition(
    finding: Dict[str, Any],
    target_state: str,
    fp_db: Optional[FalsePositiveDB] = None,
) -> Dict[str, Any]:
    """Return a copy of the finding with the transition applied when legal."""
    result = check_transition(finding, target_state, fp_db)
    if result["allowed"]:
        updated = dict(finding)
        updated["state"] = result["to"]
        updated["confidence"] = CONFIDENCE_RANGE.get(result["to"], "0%")
        result["finding"] = updated
    return result


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _load_finding(path: str) -> Dict[str, Any]:
    # utf-8-sig tolerates the BOM that Windows editors/PowerShell add.
    with open(path, "r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Finding file must contain a JSON object")
    return data


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Finding lifecycle, Hard FP Gate and FP signature DB")
    sub = parser.add_subparsers(dest="command")

    hash_parser = sub.add_parser("hash", help="Compute a finding signature hash")
    hash_parser.add_argument("--category", required=True)
    hash_parser.add_argument("--identifier", required=True)
    hash_parser.add_argument("--signal", default="")
    hash_parser.add_argument("--json", action="store_true")

    gate_parser = sub.add_parser("gate", help="Evaluate a finding JSON file against the Hard FP Gate")
    gate_parser.add_argument("--file", required=True)
    gate_parser.add_argument("--json", action="store_true")

    transition_parser = sub.add_parser("transition", help="Validate/apply a lifecycle transition")
    transition_parser.add_argument("--file", required=True)
    transition_parser.add_argument("--to", required=True)
    transition_parser.add_argument("--apply", action="store_true", help="Write the updated state back to the file")
    transition_parser.add_argument("--json", action="store_true")

    fp_parser = sub.add_parser("fp-db", help="Inspect or extend the false-positive signature database")
    fp_sub = fp_parser.add_subparsers(dest="fp_command")
    fp_list = fp_sub.add_parser("list", help="List known signatures")
    fp_list.add_argument("--json", action="store_true")
    fp_check = fp_sub.add_parser("check", help="Look up one signature hash")
    fp_check.add_argument("--hash", required=True)
    fp_check.add_argument("--json", action="store_true")
    fp_add = fp_sub.add_parser("add", help="Add a signature to the database")
    fp_add.add_argument("--hash", required=True)
    fp_add.add_argument("--category", required=True)
    fp_add.add_argument("--description", required=True)
    fp_add.add_argument("--reason", required=True)
    fp_add.add_argument("--dry-run", action="store_true")
    fp_add.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    db = FalsePositiveDB()

    if args.command == "hash":
        digest = signature_hash(args.category, args.identifier, args.signal)
        if args.json:
            print(json.dumps({"signature_hash": digest}, indent=2))
        else:
            print(digest)
        return 0

    if args.command == "gate":
        finding = _load_finding(args.file)
        result = evaluate_gate(finding, db)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[*] Finding: {result['finding_title']}")
            print(f"[*] Signature: {result['signature_hash']} | In FP DB: {result['in_fp_db']}")
            for key, passed in result["checks"].items():
                mark = "PASS" if passed else "FAIL"
                print(f"    [{mark}] {key}: {result['details'][key]}")
            print(f"[*] Verdict: {result['verdict']} | Highest supported state: {result['highest_supported_state']}")
            print(f"[*] Reporting gate: {'OPEN' if result['reporting_gate_open'] else 'CLOSED'}")
        return 0 if not result["blocking_checks"] else 1

    if args.command == "transition":
        finding = _load_finding(args.file)
        result = check_transition(finding, args.to, db)
        applied = False
        if args.apply and result["allowed"]:
            updated = dict(finding)
            updated["state"] = result["to"]
            with open(args.file, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(updated, handle, indent=2)
                handle.write("\n")
            applied = True
        if args.json:
            result["applied"] = applied
            result["file"] = args.file
            print(json.dumps(result, indent=2))
        else:
            print(f"[*] {result['from']} -> {result['to']}: {'ALLOWED' if result['allowed'] else 'REFUSED'}")
            for reason in result["reasons"]:
                print(f"    [-] {reason}")
            if applied:
                print(f"[+] State written to {args.file}")
        return 0 if result["allowed"] else 1

    if args.command == "fp-db":
        if args.fp_command == "list":
            entries = db.entries()
            if args.json:
                print(json.dumps(entries, indent=2))
                return 0 if entries else 1
            if not entries:
                print("[-] No signatures parsed from the FP database")
                return 1
            print(f"{'HASH':<10}{'CATEGORY':<14}DESCRIPTION")
            for entry in entries:
                print(f"{entry['signature_hash']:<10}{entry['category']:<14}{entry['description']}")
            return 0
        if args.fp_command == "check":
            entry = db.lookup(args.hash)
            if args.json:
                print(json.dumps({"hash": args.hash, "known": bool(entry), "entry": entry}, indent=2))
            elif entry:
                print(json.dumps(entry, indent=2))
            else:
                print(f"[+] {args.hash} is not a known false positive")
            return 0 if entry else 1
        if args.fp_command == "add":
            added = db.add(args.hash, args.category, args.description, args.reason, dry_run=args.dry_run)
            if args.json:
                print(
                    json.dumps(
                        {
                            "hash": args.hash,
                            "added": bool(added),
                            "dry_run": bool(args.dry_run),
                            "already_present": not added,
                        },
                        indent=2,
                    )
                )
                return 0
            if added:
                action = "would be added (dry run)" if args.dry_run else "added"
                print(f"[+] Signature {args.hash} {action}")
                return 0
            print(f"[*] Signature {args.hash} already present")
            return 0
        fp_parser.print_help()
        return 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
