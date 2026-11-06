#!/usr/bin/env python3
"""
Runtime preflight and session bootstrap (the scope gate).

Responsibilities
----------------
* Validate the target identifier (Android package / iOS bundle id).
* Verify the artifact exists and, optionally, that its SHA-256 matches the
  pinned value supplied by the program (evidence integrity).
* Check tooling availability and decide READY / DEGRADED / BLOCKED.
* Create the per-engagement workspace tree, notes skeleton and artifact
  metadata, and optionally open a LearningEngine session.

Exit codes: 0 = READY, 1 = BLOCKED, 2 = DEGRADED (use --strict to fail on
DEGRADED as well).  The orchestrator must stop when the status is BLOCKED.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

SUBDIRECTORIES = [
    "notes",
    "static",
    "intel",
    "frida",
    "dynamic",
    "traffic",
    "crypto",
    "storage",
    "ipc",
    "webview",
    "resilience",
    "exploitation",
    "verification",
    "compliance",
    "findings",
    "evidence",
    "screenshots",
    "reports",
    "device",
]

TOOLS_TO_CHECK = [
    "adb",
    "frida",
    "apktool",
    "jadx",
    "sqlite3",
    "mitmproxy",
    "python",
]

# Tools that are mandatory before any device-bound work can start.
DEVICE_TOOLS = ["adb", "frida"]
# Tools that are mandatory before any static work can start.
STATIC_TOOLS = ["python"]

ANDROID_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
IOS_BUNDLE_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def calculate_sha256(filepath: str) -> str:
    """Return the SHA-256 of a file, or UNKNOWN_FILE_NOT_FOUND."""
    if not os.path.isfile(filepath):
        return "UNKNOWN_FILE_NOT_FOUND"
    hasher = hashlib.sha256()
    with open(filepath, "rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_target(target: str, platform: str = "auto") -> Dict[str, Any]:
    """Validate an Android package name or iOS bundle identifier."""
    target = (target or "").strip()
    if not target:
        return {"valid": False, "platform": platform, "reason": "target identifier is empty"}
    if len(target) > 255:
        return {"valid": False, "platform": platform, "reason": "target identifier is too long"}

    android_ok = bool(ANDROID_PACKAGE_RE.match(target))
    ios_ok = bool(IOS_BUNDLE_RE.match(target))

    if platform == "android":
        ok = android_ok
        reason = "" if ok else "not a valid Android package name (e.g. com.vendor.app)"
    elif platform == "ios":
        ok = ios_ok
        reason = "" if ok else "not a valid iOS bundle identifier (e.g. com.vendor.app)"
    else:
        ok = android_ok or ios_ok
        reason = "" if ok else "not a valid Android package name or iOS bundle identifier"

    if ok and platform == "auto":
        platform = "android" if android_ok else "ios"
    return {"valid": ok, "platform": platform, "reason": reason}


def check_tools(tools: Optional[Sequence[str]] = None) -> Dict[str, str]:
    """Return {tool: FOUND|NOT_FOUND} for each requested tool."""
    result: Dict[str, str] = {}
    for tool in tools or TOOLS_TO_CHECK:
        result[tool] = "FOUND" if shutil.which(tool) is not None else "NOT_FOUND"
    return result


def _resolve_workspace(workspace_path: Optional[str], target: str) -> str:
    if workspace_path and workspace_path.strip():
        return os.path.abspath(os.path.expanduser(workspace_path.strip()))
    return os.path.abspath(os.path.join(ROOT_DIR, "testing", target))


def _is_within(path: str, parent: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(parent)]) == os.path.abspath(parent)
    except ValueError:  # different drives on Windows
        return False


def ensure_workspace(
    workspace_path: str,
    target: str,
    artifact_path: Optional[str] = None,
    session_id: Optional[str] = None,
    platform: str = "auto",
    mode: str = "hunt",
    scenario: str = "mobile static analysis",
    refresh: bool = False,
) -> Dict[str, Any]:
    """Create the engagement workspace and its notes skeleton (idempotent)."""
    os.makedirs(workspace_path, exist_ok=True)
    created_dirs: List[str] = []
    for sub in SUBDIRECTORIES:
        path = os.path.join(workspace_path, sub)
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
            created_dirs.append(sub)

    artifact_hash = calculate_sha256(artifact_path) if artifact_path else "N/A"
    now = datetime.now().isoformat(timespec="seconds")

    def write_if_missing(relative: str, content: str) -> bool:
        path = os.path.join(workspace_path, relative)
        if os.path.exists(path) and not refresh:
            return False
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        return True

    tools = check_tools()
    tool_lines = "\n".join(f"| `{name}` | {status} |" for name, status in tools.items())

    bootstrap = (
        f"# Session Bootstrap: {target}\n\n"
        f"- **Target Package:** `{target}`\n"
        f"- **Platform:** {platform}\n"
        f"- **Artifact Path:** `{artifact_path or 'Not provided'}`\n"
        f"- **Artifact SHA-256:** `{artifact_hash}`\n"
        f"- **Session ID:** `{session_id or 'not started'}`\n"
        f"- **Session Initialized:** {now}\n"
        f"- **Mode:** {mode}\n"
        f"- **Scenario:** {scenario}\n"
        f"- **Scope Lock:** CONFIRMED (authorized target, owned device/accounts)\n\n"
        f"## Tooling\n\n| Tool | Status |\n|---|---|\n{tool_lines}\n\n"
        f"## Evidence Root\n\n`{workspace_path}`\n"
    )
    write_if_missing(os.path.join("notes", "bootstrap.md"), bootstrap)

    mindmap = (
        f"# Attack Surface Mindmap: {target}\n\n"
        "```mermaid\n"
        "graph TD\n"
        f"  Root[\"{target}\"] --> Static[Static / MASVS-CODE]\n"
        "  Root --> Crypto[Crypto / MASVS-CRYPTO]\n"
        "  Root --> Storage[Storage / MASVS-STORAGE]\n"
        "  Root --> Network[Network / MASVS-NETWORK]\n"
        "  Root --> Auth[Auth & Session / MASVS-AUTH]\n"
        "  Root --> IPC[IPC & Deep Links / MASVS-PLATFORM]\n"
        "  Root --> WebView[WebView Bridge / MASVS-PLATFORM]\n"
        "  Root --> Resilience[Resilience / MASVS-RESILIENCE]\n"
        "  Root --> Privacy[Privacy / MASVS-PRIVACY]\n"
        "```\n\n"
        "## Ranked surfaces\n\n"
        "1. (pending static inventory)\n"
    )
    write_if_missing(os.path.join("notes", "MINDMAP.md"), mindmap)

    ledger = (
        f"# CONTEXT LEDGER: {target}\n\n"
        "TIMESTAMP | SESSION_ID | AGENT | SURFACE | ACTION | RESULT | EVIDENCE_PATH | REMARKS\n"
        f"{now} | {session_id or 'unassigned'} | orchestrator-agent | BOOTSTRAP | preflight scope lock | "
        "SUCCESS | notes/bootstrap.md | workspace initialized\n"
    )
    write_if_missing(os.path.join("notes", "CONTEXT_LEDGER.md"), ledger)

    variants = (
        f"# TESTED VARIANTS: {target}\n\n"
        "SURFACE | SKILL SET | VARIANT | EVIDENCE | ACCOUNT/DEVICE STATE | RESULT | REASON | NEXT UNTESTED VARIANTS\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| (none yet) | | | | | | | |\n"
    )
    write_if_missing(os.path.join("notes", "tested-variants.md"), variants)

    auth_session = (
        f"# AUTH SESSION: {target}\n\n"
        "> Owned test accounts only. Reference `login.md`; never store production credentials.\n\n"
        "| Role | Identifier | Tenant | Device | Session artifact | Notes |\n"
        "|---|---|---|---|---|---|\n"
        "| A (standard) | test_user_a@example.com | tenant_alpha | | | |\n"
        "| B (cross-tenant) | test_user_b@example.com | tenant_beta | | | |\n"
    )
    write_if_missing(os.path.join("notes", "auth_session.md"), auth_session)

    artifact_metadata = {
        "target": target,
        "platform": platform,
        "artifact_path": os.path.abspath(artifact_path) if artifact_path else None,
        "artifact_sha256": artifact_hash,
        "session_id": session_id,
        "mode": mode,
        "scenario": scenario,
        "workspace": workspace_path,
        "created_at": now,
    }
    metadata_path = os.path.join(workspace_path, "evidence", "artifact.json")
    if refresh or not os.path.exists(metadata_path):
        os.makedirs(os.path.dirname(metadata_path), exist_ok=True)
        with open(metadata_path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(artifact_metadata, handle, indent=2)
            handle.write("\n")

    return {
        "workspace": workspace_path,
        "created_subdirs": created_dirs,
        "artifact_hash": artifact_hash,
        "artifact_metadata": metadata_path,
        "session_id": session_id,
        "notes": {
            "bootstrap": os.path.join(workspace_path, "notes", "bootstrap.md"),
            "mindmap": os.path.join(workspace_path, "notes", "MINDMAP.md"),
            "ledger": os.path.join(workspace_path, "notes", "CONTEXT_LEDGER.md"),
            "tested_variants": os.path.join(workspace_path, "notes", "tested-variants.md"),
            "auth_session": os.path.join(workspace_path, "notes", "auth_session.md"),
        },
    }


def run_preflight(
    target: str,
    workspace: Optional[str] = None,
    artifact: Optional[str] = None,
    expect_sha256: Optional[str] = None,
    platform: str = "auto",
    mode: str = "hunt",
    scenario: str = "mobile static analysis",
    require_tools: Optional[Sequence[str]] = None,
    allow_external_workspace: bool = False,
    ensure_session: bool = False,
    refresh: bool = False,
) -> Dict[str, Any]:
    """Execute every preflight check and return a structured decision."""
    blocked: List[str] = []
    degraded: List[str] = []
    warnings: List[str] = []

    target_check = validate_target(target, platform)
    platform = target_check["platform"]
    if not target_check["valid"]:
        blocked.append(f"invalid target: {target_check['reason']}")

    workspace_path = _resolve_workspace(workspace, target.strip())
    testing_root = os.path.join(ROOT_DIR, "testing")
    if not allow_external_workspace and not _is_within(workspace_path, testing_root):
        blocked.append(
            f"workspace '{workspace_path}' is outside the evidence root '{testing_root}' "
            "(pass --allow-external-workspace to override)"
        )
    if os.path.exists(workspace_path) and not os.path.isdir(workspace_path):
        blocked.append(f"workspace path exists and is not a directory: {workspace_path}")

    artifact_hash = "N/A"
    if artifact:
        artifact_abs = os.path.abspath(artifact)
        if not os.path.isfile(artifact_abs):
            blocked.append(f"artifact not found: {artifact_abs}")
        else:
            artifact_hash = calculate_sha256(artifact_abs)
            if expect_sha256 and artifact_hash.lower() != expect_sha256.strip().lower():
                blocked.append(
                    f"artifact SHA-256 mismatch: expected {expect_sha256.strip().lower()}, got {artifact_hash}"
                )
    elif expect_sha256:
        blocked.append("--expect-sha256 supplied without --artifact; cannot verify evidence integrity")

    tool_status = check_tools()
    required = list(require_tools or [])
    missing_required = [tool for tool in required if tool_status.get(tool, "NOT_FOUND") != "FOUND"]
    if missing_required:
        blocked.append("required tools missing: " + ", ".join(missing_required))

    missing_device_tools = [t for t in DEVICE_TOOLS if tool_status.get(t, "NOT_FOUND") != "FOUND"]
    if missing_device_tools and not missing_required:
        degraded.append("device tooling missing (device-bound phases blocked): " + ", ".join(missing_device_tools))

    optional_missing = [
        tool
        for tool, status in tool_status.items()
        if status != "FOUND" and tool not in DEVICE_TOOLS and tool not in missing_required
    ]
    if optional_missing:
        degraded.append("optional tooling missing: " + ", ".join(optional_missing))

    if mode not in {"hunt", "audit", "triage"}:
        blocked.append(f"invalid mode '{mode}'")

    session_id: Optional[str] = None
    session_note = "not requested"
    if ensure_session and not blocked:
        try:
            sys.path.insert(0, ROOT_DIR)
            from learning_engine import LearningEngine  # noqa: WPS433 (runtime import)

            engine = LearningEngine()
            technologies = [scenario] if scenario else []
            session = engine.before_recon(target.strip(), technologies, mode=mode)
            session_id = session["session_id"]
            session_note = f"opened ({session['past_lessons_count']} past lessons)"
        except Exception as exc:  # pragma: no cover - defensive: engine must not block the hunt
            warnings.append(f"learning engine session not opened: {exc}")
            session_note = "failed (see warnings)"

    result: Dict[str, Any] = {
        "target": target.strip(),
        "platform": platform,
        "workspace": workspace_path,
        "artifact": os.path.abspath(artifact) if artifact else None,
        "artifact_sha256": artifact_hash,
        "expected_sha256": expect_sha256.lower() if expect_sha256 else None,
        "mode": mode,
        "scenario": scenario,
        "tools": tool_status,
        "blocked": blocked,
        "degraded": degraded,
        "warnings": warnings,
        "session_id": session_id,
        "session": session_note,
        "status": "BLOCKED" if blocked else ("DEGRADED" if degraded else "READY"),
        "checked_at": datetime.now().isoformat(timespec="seconds"),
    }

    if result["status"] != "BLOCKED":
        workspace_info = ensure_workspace(
            workspace_path,
            target.strip(),
            artifact_path=os.path.abspath(artifact) if artifact else None,
            session_id=session_id,
            platform=platform,
            mode=mode,
            scenario=scenario,
            refresh=refresh,
        )
        result.update(
            {
                "created_subdirs": workspace_info["created_subdirs"],
                "artifact_metadata": workspace_info["artifact_metadata"],
                "notes": workspace_info["notes"],
            }
        )
    else:
        result["created_subdirs"] = []

    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Mobile pentesting runtime preflight / scope gate")
    parser.add_argument("--target", required=True, help="Target application package name or bundle ID")
    parser.add_argument("--scenario", default="mobile static analysis", help="Testing scenario")
    parser.add_argument("--mode", default="hunt", choices=["hunt", "audit", "triage"], help="Operational mode")
    parser.add_argument("--workspace", default="", help="Workspace directory (defaults to testing/<target>)")
    parser.add_argument("--artifact", default=None, help="Path to the target APK or IPA")
    parser.add_argument("--expect-sha256", default=None, help="Pinned SHA-256 of the artifact")
    parser.add_argument("--platform", default="auto", choices=["auto", "android", "ios"])
    parser.add_argument("--require-tools", default="", help="Comma-separated tools that must be present")
    parser.add_argument(
        "--allow-external-workspace",
        action="store_true",
        help="Permit a workspace outside <repo>/testing",
    )
    parser.add_argument("--ensure-session", action="store_true", help="Open a LearningEngine session")
    parser.add_argument("--refresh", action="store_true", help="Rewrite notes/metadata files")
    parser.add_argument("--strict", action="store_true", help="Treat DEGRADED as a failure")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable output")

    args = parser.parse_args(argv)
    required_tools = [t.strip() for t in args.require_tools.split(",") if t.strip()]

    result = run_preflight(
        target=args.target,
        workspace=args.workspace or None,
        artifact=args.artifact,
        expect_sha256=args.expect_sha256,
        platform=args.platform,
        mode=args.mode,
        scenario=args.scenario,
        require_tools=required_tools,
        allow_external_workspace=args.allow_external_workspace,
        ensure_session=args.ensure_session,
        refresh=args.refresh,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[*] PREFLIGHT CHECK: Target = {result['target']} | Platform = {result['platform']} | Mode = {result['mode']}")
        print("[*] Environment tooling:")
        for tool, status in result["tools"].items():
            print(f"    - {tool:<12}: {status}")
        for reason in result["blocked"]:
            print(f"[-] BLOCKED: {reason}")
        for reason in result["degraded"]:
            print(f"[!] DEGRADED: {reason}")
        for warning in result["warnings"]:
            print(f"[!] WARNING: {warning}")
        print(f"[*] Learning engine session: {result['session']}")
        if result["status"] != "BLOCKED":
            print(f"[+] Workspace ready: {result['workspace']}")
            print(f"    - Artifact SHA-256: {result['artifact_sha256']}")
            print(f"    - Artifact metadata: {result['artifact_metadata']}")
        print(f"[+] PREFLIGHT STATUS: {result['status']}")

    if result["status"] == "BLOCKED":
        return 1
    if result["status"] == "DEGRADED" and args.strict:
        return 1
    return 0 if result["status"] == "READY" else 2


if __name__ == "__main__":
    sys.exit(main())
