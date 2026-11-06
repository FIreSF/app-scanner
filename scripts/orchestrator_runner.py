#!/usr/bin/env python3
"""
Mobile Pentesting Orchestrator CLI.

Implements the executable parts of `orchestrator-agent`'s contract:

* full canonical reference validation (`link-check`)
* dependency-aware phase/wave planning with the concurrency ceiling (`plan`, `waves`)
* scope-locked session bootstrap (`bootstrap`)
* finding state machine + Hard FP Gate (`gate`, `test-gate`, `transition`)
* false-positive signature database management (`fp-db`)
* MASVS coverage / gap analysis (`coverage`)
* context ledger and tested-variant recording (`ledger`)
* session summary from the learning engine (`summary`)
* environment diagnostics (`doctor`)

Every command is read-only unless it explicitly says otherwise (`--persist`,
`--apply`, `--write`, `ledger`).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:  # executed as a module (tests, `python -m scripts.orchestrator_runner`)
    from scripts import findings as findings_mod
    from scripts import mindmap as mindmap_mod
    from scripts import registry as registry_mod
    from scripts import report_builder as report_mod
    from scripts import runtime_preflight as preflight_mod
except ImportError:  # executed as a plain script (`python scripts/orchestrator_runner.py`)
    import findings as findings_mod  # type: ignore[no-redef]
    import mindmap as mindmap_mod  # type: ignore[no-redef]
    import registry as registry_mod  # type: ignore[no-redef]
    import report_builder as report_mod  # type: ignore[no-redef]
    import runtime_preflight as preflight_mod  # type: ignore[no-redef]

try:
    from learning_engine import LearningEngine
except ImportError:  # pragma: no cover - engine is optional for read-only commands
    LearningEngine = None  # type: ignore[assignment]


class Orchestrator:
    """Thin coordination layer used by the CLI and by tests."""

    def __init__(
        self,
        target_package: str = "com.example.targetapp",
        workspace: Optional[str] = None,
        engine: Optional[Any] = None,
    ):
        self.target = target_package
        self.registry = registry_mod.load_registry()
        self.workspace = os.path.abspath(
            workspace or os.path.join(ROOT_DIR, "testing", target_package)
        )
        if engine is not None:
            self.engine = engine
        elif LearningEngine is not None:
            self.engine = LearningEngine()
        else:
            self.engine = None
        self.session_id = self._discover_session_id()

    # ------------------------------------------------------------------ #
    # Session handling
    # ------------------------------------------------------------------ #
    def _discover_session_id(self) -> str:
        """Reuse the session id recorded by preflight, else create a stable one."""
        metadata = os.path.join(self.workspace, "evidence", "artifact.json")
        if os.path.isfile(metadata):
            try:
                with open(metadata, "r", encoding="utf-8") as handle:
                    session_id = json.load(handle).get("session_id")
                if session_id:
                    return str(session_id)
            except (OSError, json.JSONDecodeError):
                pass
        return f"hunt_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def ensure_engine_session(self) -> Optional[str]:
        """Make sure the current session exists in the learning engine."""
        if self.engine is None:
            return None
        if self.engine.get_session(self.session_id):
            return self.session_id
        result = self.engine.before_recon(self.target, [], session_id=self.session_id)
        return result["session_id"]

    # ------------------------------------------------------------------ #
    # Validation / planning
    # ------------------------------------------------------------------ #
    def link_check(self) -> Dict[str, Any]:
        result = registry_mod.link_check()
        return result.to_dict()

    def validate_registry(self) -> Dict[str, Any]:
        return registry_mod.validate_registry(self.registry).to_dict()

    def plan(self) -> Dict[str, Any]:
        tools = preflight_mod.check_tools()
        return {
            "target": self.target,
            "workspace": self.workspace,
            "session_id": self.session_id,
            "concurrency_limit": registry_mod.concurrency_limit(self.registry),
            "phases": [
                {"id": phase_id, "title": title, "agents": members}
                for phase_id, title, members in registry_mod.PHASES
            ],
            "tools": tools,
            "agent_count": len(registry_mod.sub_agent_ids(self.registry)),
        }

    def waves(
        self,
        completed: Optional[Sequence[str]] = None,
        running: Optional[Sequence[str]] = None,
        phases: Optional[Sequence[str]] = None,
        include_on_demand: bool = False,
    ) -> Dict[str, Any]:
        return {
            "concurrency_limit": registry_mod.concurrency_limit(self.registry),
            "waves": registry_mod.dependency_waves(self.registry),
            "next": registry_mod.next_dispatchable(
                self.registry,
                completed or [],
                running or [],
                phases=phases,
                include_on_demand=include_on_demand,
            ),
        }

    def mindmap(self) -> Dict[str, Any]:
        """Build (and refresh) the workspace attack-surface mindmap."""
        data = mindmap_mod.build_mindmap(self.workspace, self.target)
        data["path"] = mindmap_mod.write_mindmap(data)
        return data

    def report(self, approve: bool = False) -> Dict[str, Any]:
        """Assemble the final report; writing requires an explicit user gate."""
        return report_mod.build_report(self.workspace, self.target, approve=approve)

    # ------------------------------------------------------------------ #
    # Findings
    # ------------------------------------------------------------------ #
    def evaluate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        return findings_mod.evaluate_gate(finding, findings_mod.FalsePositiveDB())

    def persist_finding(self, finding: Dict[str, Any], gate: Dict[str, Any]) -> Optional[str]:
        """Persist a finding to the learning engine (explicit --persist only)."""
        if self.engine is None:
            return None
        session_id = self.ensure_engine_session()
        payload = dict(finding)
        payload.update(
            {
                "session_id": session_id,
                "target_package": self.target,
                "signature_hash": gate["signature_hash"],
                "state": gate["final_state"],
                "verified": bool(gate["reporting_gate_open"]),
                "masvs_category": finding.get("masvs_category") or finding.get("category") or "MASVS-CODE",
            }
        )
        return self.engine.after_finding(payload)

    # ------------------------------------------------------------------ #
    # Ledger
    # ------------------------------------------------------------------ #
    def append_ledger(
        self,
        agent: str,
        surface: str,
        action: str,
        result: str,
        evidence: str = "",
        remarks: str = "",
    ) -> str:
        notes_dir = os.path.join(self.workspace, "notes")
        os.makedirs(notes_dir, exist_ok=True)
        ledger_path = os.path.join(notes_dir, "CONTEXT_LEDGER.md")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = (
            f"{timestamp} | {self.session_id} | {agent} | {surface} | {action} | "
            f"{result} | {evidence or '-'} | {remarks or '-'}\n"
        )
        if not os.path.isfile(ledger_path):
            with open(ledger_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(f"# CONTEXT LEDGER: {self.target}\n\n")
                handle.write(
                    "TIMESTAMP | SESSION_ID | AGENT | SURFACE | ACTION | RESULT | EVIDENCE_PATH | REMARKS\n"
                )
        with open(ledger_path, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
        return ledger_path

    def append_variant(
        self,
        surface: str,
        variant: str,
        result: str,
        skill_used: str = "",
        evidence_path: str = "",
        device_state: str = "",
        reason: str = "",
        next_variants: str = "",
    ) -> str:
        """Append a row to `notes/tested-variants.md` (spec §7 per-surface ledger)."""
        notes_dir = os.path.join(self.workspace, "notes")
        os.makedirs(notes_dir, exist_ok=True)
        path = os.path.join(notes_dir, "tested-variants.md")

        def cell(value: str) -> str:
            return " ".join(str(value or "").replace("|", "\\|").split()) or "-"

        row = (
            f"| {cell(surface)} | {cell(skill_used)} | {cell(variant)} | {cell(evidence_path)} | "
            f"{cell(device_state)} | {cell(result)} | {cell(reason)} | {cell(next_variants)} |\n"
        )
        if not os.path.isfile(path):
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(f"# TESTED VARIANTS: {self.target}\n\n")
                handle.write(
                    "SURFACE | SKILL SET | VARIANT | EVIDENCE | ACCOUNT/DEVICE STATE | "
                    "RESULT | REASON | NEXT UNTESTED VARIANTS\n"
                )
                handle.write("|---|---|---|---|---|---|---|---|\n")
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
        placeholder = "| (none yet) | | | | | | | |\n"
        content = content.replace(placeholder, "")
        if not content.endswith("\n"):
            content += "\n"
        content += row
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        return path

    def record_variant(
        self,
        surface: str,
        variant: str,
        result: str,
        skill_used: Optional[str] = None,
        evidence_path: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional[int]:
        if self.engine is None:
            return None
        session_id = self.ensure_engine_session()
        return self.engine.during_testing(
            session_id, surface, variant, result, skill_used, evidence_path, notes
        )

    # ------------------------------------------------------------------ #
    # Summary
    # ------------------------------------------------------------------ #
    def summary(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        if self.engine is None:
            return {"error": "learning engine unavailable"}
        return self.engine.before_summary(session_id or self.session_id)

    def print_plan(self) -> None:
        plan = self.plan()
        print("=" * 59)
        print(f" MULTI-AGENT EXECUTION PLAN FOR: {plan['target']}")
        print(f" Workspace: {plan['workspace']}")
        print(f" Session ID: {plan['session_id']}")
        print(f" Concurrency limit: {plan['concurrency_limit']} sub-agents max")
        print("=" * 59)
        for phase in plan["phases"]:
            members = ", ".join(phase["agents"]) if phase["agents"] else "orchestrator-agent only"
            print(f"\n[PHASE {phase['id']}] {phase['title']}")
            print(f"  - {members}")
        print("\n[*] Tooling:")
        for tool, status in plan["tools"].items():
            print(f"    - {tool:<12}: {status}")


# --------------------------------------------------------------------------- #
# CLI plumbing
# --------------------------------------------------------------------------- #
def _common_parent() -> argparse.ArgumentParser:
    """Options accepted both before and after the subcommand (SUPPRESS defaults)."""
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--target", default=argparse.SUPPRESS, help="Target package or bundle id")
    parent.add_argument("--workspace", default=argparse.SUPPRESS, help="Engagement workspace")
    parent.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    return parent


def build_parser() -> argparse.ArgumentParser:
    common = _common_parent()
    parser = argparse.ArgumentParser(
        description="Mobile Pentesting Orchestrator CLI",
        epilog="Global options (--target, --workspace, --json) may be placed before or after the command.",
    )
    parser.add_argument("--target", default="com.example.targetapp", help="Target package or bundle id")
    parser.add_argument("--workspace", default=None, help="Engagement workspace")
    parser.add_argument("--json", action="store_true", help="JSON output")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("link-check", parents=[common], help="Validate every canonical reference")
    sub.add_parser("validate-registry", parents=[common], help="Validate the registry only")
    sub.add_parser("plan", parents=[common], help="Show phases, tooling and session")
    doctor_parser = sub.add_parser(
        "doctor", parents=[common], help="Environment and data-integrity diagnostics"
    )
    doctor_parser.add_argument("--strict", action="store_true", help="Fail on database integrity warnings")

    bootstrap = sub.add_parser("bootstrap", parents=[common], help="Scope-locked workspace bootstrap")
    bootstrap.add_argument("--artifact", default=None, help="Path to APK/IPA")
    bootstrap.add_argument("--expect-sha256", default=None, help="Pinned artifact SHA-256")
    bootstrap.add_argument("--platform", default="auto", choices=["auto", "android", "ios"])
    bootstrap.add_argument("--mode", default="hunt", choices=["hunt", "audit", "triage"])
    bootstrap.add_argument("--scenario", default="mobile static analysis")
    bootstrap.add_argument("--require-tools", default="")
    bootstrap.add_argument("--allow-external-workspace", action="store_true")
    bootstrap.add_argument("--no-session", action="store_true", help="Skip opening a learning-engine session")
    bootstrap.add_argument("--strict", action="store_true")

    waves = sub.add_parser("waves", parents=[common], help="Next dispatchable agents")
    waves.add_argument("--completed", default="")
    waves.add_argument("--running", default="")
    waves.add_argument("--phase", default="")
    waves.add_argument("--include-on-demand", action="store_true")
    waves.add_argument("--next", action="store_true", help="Print only the comma-separated ready set")

    mindmap = sub.add_parser("mindmap", parents=[common], help="Rebuild notes/MINDMAP.md from evidence")
    mindmap.add_argument("--no-write", action="store_true", help="Print the summary without writing the file")
    mindmap.add_argument("--check", action="store_true", help="Fail if notes/MINDMAP.md is stale")

    gate = sub.add_parser("gate", parents=[common], help="Run the Hard FP Gate on a finding JSON file")
    gate.add_argument("--file", required=True)
    gate.add_argument("--persist", action="store_true", help="Write the finding to the learning engine")
    gate.add_argument("--save", action="store_true", help="Save the gate result under verification/")

    test_gate = sub.add_parser("test-gate", parents=[common], help="DEMO: evaluate a synthetic finding")
    test_gate.add_argument("--title", default="Insecure Deep Link Intent Redirection")
    test_gate.add_argument("--category", default="MASVS-PLATFORM")
    test_gate.add_argument("--severity", default="High", choices=["Critical", "High", "Medium", "Low"])
    test_gate.add_argument(
        "--verified",
        action="store_true",
        help="DEMO ONLY: pretend verification-agent returned CONFIRMED_VALIDATED",
    )
    test_gate.add_argument("--persist", action="store_true", help="Persist the synthetic finding (not recommended)")

    transition = sub.add_parser("transition", parents=[common], help="Validate/apply a lifecycle transition")
    transition.add_argument("--file", required=True)
    transition.add_argument("--to", required=True)
    transition.add_argument("--apply", action="store_true")

    fp_db = sub.add_parser("fp-db", parents=[common], help="Inspect/extend the FP signature database")
    fp_sub = fp_db.add_subparsers(dest="fp_command")
    fp_list = fp_sub.add_parser("list")
    fp_list.add_argument("--json", action="store_true")
    fp_check = fp_sub.add_parser("check")
    fp_check.add_argument("--hash", required=True)
    fp_check.add_argument("--json", action="store_true")
    fp_add = fp_sub.add_parser("add")
    fp_add.add_argument("--hash", required=True)
    fp_add.add_argument("--category", required=True)
    fp_add.add_argument("--description", required=True)
    fp_add.add_argument("--reason", required=True)
    fp_add.add_argument("--dry-run", action="store_true")
    fp_add.add_argument("--json", action="store_true")

    coverage = sub.add_parser("coverage", parents=[common], help="Generate the MASVS coverage matrix")
    coverage.add_argument("--no-write", action="store_true")

    report = sub.add_parser("report", parents=[common], help="Assemble the gated final report")
    report.add_argument(
        "--approve",
        action="store_true",
        help="Explicit user gate: write reports/final-report.md",
    )

    ledger = sub.add_parser("ledger", parents=[common], help="Append a context-ledger entry")
    ledger.add_argument("--agent", required=True)
    ledger.add_argument("--surface", required=True)
    ledger.add_argument("--action", required=True)
    ledger.add_argument("--result", required=True)
    ledger.add_argument("--evidence", default="")
    ledger.add_argument("--remarks", default="")
    ledger.add_argument("--record", action="store_true", help="Also record a tested variant")
    ledger.add_argument("--skill", default="", help="Skill used for --record")
    ledger.add_argument("--device-state", default="", help="Account/device state for --record")
    ledger.add_argument("--reason", default="", help="Reason/observation for --record")
    ledger.add_argument("--next", default="", help="Next untested variants for --record")

    summary = sub.add_parser("summary", parents=[common], help="Summarise a learning-engine session")
    summary.add_argument("--session", default=None)

    return parser


def _load_json(path: str) -> Dict[str, Any]:
    # utf-8-sig tolerates the BOM that Windows editors/PowerShell add.
    with open(path, "r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("finding file must contain a JSON object")
    return data


def _print_gate(result: Dict[str, Any]) -> None:
    print(f"[*] Finding: {result['finding_title']}")
    print(f"[*] Signature: {result['signature_hash']} | In FP DB: {result['in_fp_db']}")
    for key, passed in result["checks"].items():
        mark = "PASS" if passed else "FAIL"
        print(f"    [{mark}] {key}: {result['details'][key]}")
    print(f"[*] Verdict: {result['verdict']} | Highest supported state: {result['highest_supported_state']}")
    print(f"[*] Reporting gate: {'OPEN' if result['reporting_gate_open'] else 'CLOSED'}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "plan"
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    json_requested = bool(getattr(args, "json", False)) or "--json" in raw_argv

    if command == "fp-db":
        forwarded = ["fp-db", args.fp_command or "list"]
        if getattr(args, "hash", None):
            forwarded += ["--hash", args.hash]
        if getattr(args, "category", None):
            forwarded += ["--category", args.category]
        if getattr(args, "description", None):
            forwarded += ["--description", args.description]
        if getattr(args, "reason", None):
            forwarded += ["--reason", args.reason]
        if getattr(args, "dry_run", False):
            forwarded.append("--dry-run")
        if json_requested:
            forwarded.append("--json")
        return findings_mod.main(forwarded)
    try:
        orchestrator = Orchestrator(args.target, args.workspace)
    except registry_mod.RegistryError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    if command == "link-check":
        result = orchestrator.link_check()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[*] Link check: {result['status']} ({result['checked']} references resolved)")
            for warning in result.get("warnings", []):
                print(f"[!] {warning}")
            for error in result.get("errors", []):
                print(f"[-] {error}")
            if result["status"] == "PASS":
                print("[+] Every canonical reference and agent briefing resolves.")
        return 0 if result["status"] == "PASS" else 1

    if command == "validate-registry":
        result = orchestrator.validate_registry()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[*] Registry validation: {result['status']}")
            for error in result.get("errors", []):
                print(f"[-] {error}")
        return 0 if result["status"] == "PASS" else 1

    if command == "plan":
        if args.json:
            print(json.dumps(orchestrator.plan(), indent=2))
        else:
            orchestrator.print_plan()
        return 0

    if command == "bootstrap":
        required_tools = [t.strip() for t in args.require_tools.split(",") if t.strip()]
        result = preflight_mod.run_preflight(
            target=args.target,
            workspace=args.workspace,
            artifact=args.artifact,
            expect_sha256=args.expect_sha256,
            platform=args.platform,
            mode=args.mode,
            scenario=args.scenario,
            require_tools=required_tools,
            allow_external_workspace=args.allow_external_workspace,
            ensure_session=not args.no_session,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[*] Bootstrap: {result['target']} ({result['platform']}) -> {result['workspace']}")
            for tool, status in result["tools"].items():
                print(f"    - {tool:<12}: {status}")
            for reason in result["blocked"]:
                print(f"[-] BLOCKED: {reason}")
            for reason in result["degraded"]:
                print(f"[!] DEGRADED: {reason}")
            print(f"[*] Learning engine session: {result['session']}")
            if result["status"] != "BLOCKED":
                print(f"[+] Artifact SHA-256: {result['artifact_sha256']}")
                print(f"[+] Bootstrap note: {result['notes']['bootstrap']}")
            print(f"[+] PREFLIGHT STATUS: {result['status']}")
        if result["status"] == "BLOCKED":
            return 1
        if result["status"] == "DEGRADED":
            # Mirrors runtime_preflight.py: 2 = DEGRADED, or 1 when --strict.
            return 1 if args.strict else 2
        return 0

    if command == "waves":
        def _ids(value: str) -> List[str]:
            return [item.strip() for item in value.split(",") if item.strip()]

        result = orchestrator.waves(
            completed=_ids(args.completed),
            running=_ids(args.running),
            phases=_ids(args.phase) or None,
            include_on_demand=args.include_on_demand,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        elif args.next:
            print(",".join(result["next"]) if result["next"] else "(nothing dispatchable)")
        else:
            print(f"[*] Concurrency limit: {result['concurrency_limit']}")
            for number, wave in enumerate(result["waves"], start=1):
                print(f"    Wave {number}: {', '.join(wave)}")
            print(f"[*] Next dispatchable ({len(result['next'])}): "
                  f"{', '.join(result['next']) if result['next'] else '(none)'}")
        return 0

    if command == "mindmap":
        if not os.path.isdir(orchestrator.workspace):
            print(f"[-] Workspace not found: {orchestrator.workspace}", file=sys.stderr)
            return 1
        data = mindmap_mod.build_mindmap(orchestrator.workspace, orchestrator.target)
        path = os.path.join(orchestrator.workspace, "notes", "MINDMAP.md")
        if args.check:
            if not os.path.isfile(path):
                print(f"[-] MINDMAP missing: {path}", file=sys.stderr)
                return 1
            if mindmap_mod.comparable_markdown(mindmap_mod.read_text(path)) != mindmap_mod.comparable_markdown(
                mindmap_mod.render_markdown(data)
            ):
                print(f"[-] MINDMAP is stale: {path}", file=sys.stderr)
                return 1
            data["path"] = path
            data["up_to_date"] = True
        elif not args.no_write:
            data["path"] = mindmap_mod.write_mindmap(data)
        else:
            data["path"] = path
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            totals = data["totals"]
            print(f"[*] Mindmap: {data['target']} -> {data['path']}")
            print(
                f"    Evidence files: {totals['evidence_files']} | "
                f"Findings: {totals['findings']} | "
                f"Populated surfaces: {totals['surfaces_with_evidence']}"
            )
            if args.check:
                print("[+] MINDMAP is up to date")
            elif not args.no_write:
                print("[+] Mindmap written")
        return 0

    if command == "gate":
        finding = _load_json(args.file)
        result = orchestrator.evaluate_finding(finding)
        if args.save:
            directory = os.path.join(orchestrator.workspace, "verification")
            os.makedirs(directory, exist_ok=True)
            path = os.path.join(directory, f"gate-{result['signature_hash']}.json")
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(result, handle, indent=2)
                handle.write("\n")
            result["saved_to"] = path
        if args.persist:
            finding_id = orchestrator.persist_finding(finding, result)
            result["persisted_finding_id"] = finding_id
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            _print_gate(result)
            if args.save:
                print(f"[+] Gate result saved: {result['saved_to']}")
            if args.persist:
                print(f"[+] Persisted finding: {result.get('persisted_finding_id')}")
        return 0 if not result["blocking_checks"] else 1

    if command == "test-gate":
        sample = {
            "title": args.title,
            "masvs_category": args.category,
            "severity": args.severity,
            "impact": "DEMO: arbitrary invocation of an unexported activity with app privileges",
            "poc_command": "adb shell am start -a android.intent.action.VIEW -d 'app://redirect?url=file:///data'",
            "reproduced_count": 2,
            "effect_demonstrated": True,
            "cross_context_verified": True,
            # DEMO ONLY: no verification-agent actually ran.  The verdict is
            # labelled so it can never be mistaken for a real validation.
            "verification_verdict": "DEMO_CONFIRMED_VALIDATED" if args.verified else "INCONCLUSIVE",
            "user_approved": False,
        }
        result = orchestrator.evaluate_finding(sample)
        result["demo"] = True
        if args.persist:
            result["persisted_finding_id"] = orchestrator.persist_finding(sample, result)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("[!] DEMO MODE: this finding is synthetic; nothing was validated or persisted"
                  + (" (except with --persist)." if not args.persist else "."))
            _print_gate(result)
        return 0
    if command == "transition":
        finding = _load_json(args.file)
        result = findings_mod.check_transition(finding, args.to)
        applied = False
        if args.apply and result["allowed"]:
            finding["state"] = result["to"]
            with open(args.file, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(finding, handle, indent=2)
                handle.write("\n")
            applied = True
        if args.json:
            result["applied"] = applied
            result["file"] = args.file
            print(json.dumps(result, indent=2))
        else:
            state = "ALLOWED" if result["allowed"] else "REFUSED"
            print(f"[*] {result['from']} -> {result['to']}: {state}")
            for reason in result["reasons"]:
                print(f"    [-] {reason}")
            if applied:
                print(f"[+] State written to {args.file}")
        return 0 if result["allowed"] else 1

    if command == "coverage":
        try:
            from scripts import compliance_matrix as coverage_mod
        except ImportError:
            import compliance_matrix as coverage_mod  # type: ignore[no-redef]

        if not os.path.isdir(orchestrator.workspace):
            print(f"[-] Workspace not found: {orchestrator.workspace}", file=sys.stderr)
            return 1
        matrix = coverage_mod.build_matrix(orchestrator.workspace)
        if not args.no_write:
            matrix["report_paths"] = coverage_mod.write_reports(matrix, orchestrator.target)
        if args.json:
            print(json.dumps(matrix, indent=2))
            return 0
        totals = matrix["totals"]
        print(f"[*] MASVS coverage: {totals['tested']}/{totals['total']} tested | "
              f"{totals['partial']} partial | {totals['not_tested']} not tested")
        for group, stats in matrix["summary"].items():
            print(f"    {group:<11}: {stats['tested']}/{stats['total']}")
        for row in matrix["gaps"][:5]:
            print(f"    P{row['priority']} {row['id']} -> {row['agent']} ({row['status']})")
        if not args.no_write:
            print(f"[+] Coverage matrix: {matrix['report_paths']['coverage']}")
            print(f"[+] Gap list:        {matrix['report_paths']['gaps']}")
        return 0

    if command == "report":
        if not os.path.isdir(orchestrator.workspace):
            print(f"[-] Workspace not found: {orchestrator.workspace}", file=sys.stderr)
            return 1
        result = orchestrator.report(approve=args.approve)
        if args.json:
            print(json.dumps(result, indent=2))
            return 0
        totals = result["totals"]
        print(f"[*] Report preview: {result['target']}")
        print(
            f"    Included: {totals['included']} | Excluded: {totals['excluded']} | "
            f"Candidates: {totals['candidates']}"
        )
        for severity in ("Critical", "High", "Medium", "Low", "Informational"):
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
            print(f"[+] Report written: {result['written_to']}")
        return 0

    if command == "ledger":
        path = orchestrator.append_ledger(
            args.agent, args.surface, args.action, args.result, args.evidence, args.remarks
        )
        record_id = None
        variant_path = None
        if args.record:
            record_id = orchestrator.record_variant(
                args.surface,
                args.action,
                args.result,
                skill_used=args.skill or None,
                evidence_path=args.evidence or None,
                notes=args.reason or None,
            )
            variant_path = orchestrator.append_variant(
                args.surface,
                args.action,
                args.result,
                skill_used=args.skill,
                evidence_path=args.evidence,
                device_state=args.device_state,
                reason=args.reason,
                next_variants=args.next,
            )
        if args.json:
            print(
                json.dumps(
                    {
                        "ledger": path,
                        "tested_variants_file": variant_path,
                        "tested_variant_id": record_id,
                    },
                    indent=2,
                )
            )
        else:
            print(f"[+] Ledger entry appended: {path}")
            if record_id is not None:
                print(f"[+] Tested variant recorded: id={record_id}")
                print(f"[+] Tested variants ledger: {variant_path}")
        return 0

    if command == "summary":
        result = orchestrator.summary(args.session)
        if args.json:
            print(json.dumps(result, indent=2))
            return 0
        if result.get("error"):
            print(f"[-] {result['error']}")
            return 1
        if result.get("target_package") is None:
            print(f"[-] Unknown session: {args.session or orchestrator.session_id}")
            return 1
        print(f"[*] Session {result['session_id']} — {result['target_package']}")
        print(f"    Findings: {result['total_findings']} | States: {result.get('state_breakdown') or {}}")
        for row in result["tested_surfaces"]:
            print(f"    {row['surface']}: {row['count']}x {row['result']}")
        return 0

    if command == "doctor":
        checks: Dict[str, Any] = {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "root": ROOT_DIR,
            "registry": orchestrator.validate_registry(),
            "links": orchestrator.link_check(),
            "tools": preflight_mod.check_tools(),
        }
        if orchestrator.engine is not None:
            checks["learning_engine"] = orchestrator.engine.stats()
            checks["db_integrity"] = _check_db_integrity()
        else:
            checks["learning_engine"] = {"error": "unavailable"}
            checks["db_integrity"] = []
        structural_ok = checks["registry"]["status"] == "PASS" and checks["links"]["status"] == "PASS"
        integrity_ok = not checks["db_integrity"]
        if args.json:
            checks["ok"] = structural_ok and (integrity_ok or not getattr(args, "strict", False))
            print(json.dumps(checks, indent=2))
        else:
            print(f"[*] Python {checks['python']} on {checks['platform']}")
            print(f"[*] Registry: {checks['registry']['status']} | Links: {checks['links']['status']}")
            for name, status in checks["tools"].items():
                print(f"    - {name:<12}: {status}")
            if isinstance(checks["learning_engine"], dict) and "error" not in checks["learning_engine"]:
                print(f"[*] Learning engine: {checks['learning_engine']}")
            for issue in checks["db_integrity"]:
                print(f"[!] Database integrity warning: {issue}")
            if not integrity_ok:
                print("    -> repair with: python -m learning_engine prune --orphans --demo --apply")
            if structural_ok and (integrity_ok or not getattr(args, "strict", False)):
                print("[+] DOCTOR: OK")
            else:
                print("[-] DOCTOR: ISSUES FOUND")
        if not structural_ok:
            return 1
        if getattr(args, "strict", False) and not integrity_ok:
            return 1
        return 0

    parser.print_help()
    return 2


def _check_db_integrity() -> List[str]:
    """Report orphan rows left behind by older engine versions (read-only)."""
    issues: List[str] = []
    engine = LearningEngine() if LearningEngine is not None else None
    if engine is None:
        return issues
    try:
        with engine._connect() as connection:  # noqa: SLF001 - intentional diagnostics
            orphans = connection.execute(
                "SELECT count(*) FROM findings f LEFT JOIN sessions s ON f.session_id = s.session_id "
                "WHERE s.session_id IS NULL"
            ).fetchone()[0]
            if orphans:
                issues.append(f"{orphans} finding(s) reference a missing session")
            orphan_feedback = connection.execute(
                "SELECT count(*) FROM triage_feedback t LEFT JOIN findings f ON t.finding_id = f.finding_id "
                "WHERE f.finding_id IS NULL"
            ).fetchone()[0]
            if orphan_feedback:
                issues.append(f"{orphan_feedback} triage_feedback row(s) reference a missing finding")
    except Exception as exc:  # pragma: no cover - diagnostics must not crash
        issues.append(f"integrity check failed: {exc}")
    return issues


if __name__ == "__main__":
    sys.exit(main())
