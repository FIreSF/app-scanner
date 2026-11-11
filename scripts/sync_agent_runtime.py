#!/usr/bin/env python3
"""Materialize OpenCode agent definitions and project config from the registry.

The registry (`runtime/registry.json`) and the briefings
(`runtime/opencode/agents/*.md`) stay the single source of truth. This script
turns them into the files an OpenCode runtime actually loads:

    .opencode/agents/<agent-id>.md   system prompt + mode + permissions
    .opencode/opencode.json          skills directory + bug-intel MCP server

Constitution mapping (AGENTS.md):
  * Sub-agents never spawn sub-agents (section 2.6) -> every sub-agent gets a
    blanket `subagent: deny` rule.
  * Only the orchestrator dispatches, and only the registered roster
    (section 1) -> `orchestrator-agent` gets an allow-list of the 16 roster
    ids followed by a blanket deny.
  * The orchestrator is the root agent and is never spawned (section 1) ->
    `mode: primary` for it, `mode: subagent` for everything else.

Usage:
    python scripts/sync_agent_runtime.py                 # write .opencode/
    python scripts/sync_agent_runtime.py --check         # verify, write nothing
    python scripts/sync_agent_runtime.py --dest DIR \
        --skills-path PATH --mcp-command CMD [--no-config]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Sequence, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(ROOT_DIR, "runtime", "registry.json")
BRIEFING_DIR = os.path.join(ROOT_DIR, "runtime", "opencode", "agents")
DEFAULT_DEST = os.path.join(ROOT_DIR, ".opencode")

ORCHESTRATOR_ID = "orchestrator-agent"
DEFAULT_SKILLS_PATH = "./skills"
DEFAULT_MCP_COMMAND = "python3 scripts/mcp_intel_server.py"
MCP_SERVER_ID = "bug-intel"
CONFIG_FILENAME = "opencode.json"
SCHEMA_URL = "https://opencode.ai/config.json"

_PURPOSE_RE = re.compile(r"^\*\*(?:Purpose|Identity):\*\*\s*(.+)$", re.MULTILINE)


class SyncError(Exception):
    """Raised when the registry or a briefing cannot be interpreted."""


def load_registry(path: str = REGISTRY_PATH) -> Dict[str, object]:
    with open(path, "r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _yaml_quote(value: str) -> str:
    """Quote a single-line YAML scalar so colons and quotes stay literal."""
    cleaned = " ".join(value.split())
    return '"' + cleaned.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _purpose_from_briefing(briefing_text: str, fallback: str) -> str:
    match = _PURPOSE_RE.search(briefing_text)
    if match:
        return match.group(1).strip()
    for line in briefing_text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    return fallback


def render_agent(
    agent_id: str,
    entry: Dict[str, object],
    briefing_text: str,
    dispatch_roster: Sequence[str],
) -> str:
    """Render one `.opencode/agents/<id>.md` document."""
    purpose = _purpose_from_briefing(briefing_text, str(entry.get("name", agent_id)))
    description = f"{entry.get('name', agent_id)} — {purpose}"
    is_root = agent_id == ORCHESTRATOR_ID

    lines = ["---"]
    lines.append(f"description: {_yaml_quote(description)}")
    lines.append(f"mode: {'primary' if is_root else 'subagent'}")
    lines.append("permissions:")
    if is_root:
        # The orchestrator may dispatch exactly the registered roster, and
        # nothing else (AGENTS.md sections 1 and 2.6).
        for other_id in sorted(dispatch_roster):
            if other_id == agent_id:
                continue
            lines.append("  - action: subagent")
            lines.append(f"    resource: {other_id}")
            lines.append("    effect: allow")
    lines.append("  - action: subagent")
    lines.append('    resource: "*"')
    lines.append("    effect: deny")
    lines.append("---")
    lines.append("")
    body = briefing_text.rstrip("\n")
    return "\n".join(lines) + "\n" + body + "\n"


def build_expected(
    dest_dir: str,
    skills_path: str = DEFAULT_SKILLS_PATH,
    mcp_command: Sequence[str] = tuple(DEFAULT_MCP_COMMAND.split()),
    include_config: bool = True,
) -> Dict[str, str]:
    """Return {absolute path: exact expected content} for every managed file."""
    registry = load_registry()
    agents = registry.get("agents")
    if not isinstance(agents, dict) or not agents:
        raise SyncError("runtime/registry.json has no agents")
    dispatch_roster = sorted(agents.keys())

    expected: Dict[str, str] = {}
    for agent_id, entry in sorted(agents.items(), key=lambda kv: int(kv[1].get("index", 0))):
        if not isinstance(entry, dict):
            raise SyncError(f"registry entry {agent_id!r} is not an object")
        briefing_path = entry.get("briefing_path")
        if not isinstance(briefing_path, str):
            raise SyncError(f"{agent_id} has no briefing_path")
        full_briefing = os.path.join(ROOT_DIR, briefing_path)
        if not os.path.isfile(full_briefing):
            raise SyncError(f"{agent_id} briefing missing: {briefing_path}")
        expected[os.path.join(dest_dir, "agents", f"{agent_id}.md")] = render_agent(
            agent_id, entry, read_text(full_briefing), dispatch_roster
        )

    if include_config:
        config = {
            "$schema": SCHEMA_URL,
            "skills": [skills_path],
            "mcp": {
                "servers": {
                    MCP_SERVER_ID: {
                        "type": "local",
                        "command": list(mcp_command),
                    }
                }
            },
        }
        expected[os.path.join(dest_dir, CONFIG_FILENAME)] = (
            json.dumps(config, indent=2, ensure_ascii=False) + "\n"
        )
    return expected


def _existing_managed(dest_dir: str) -> List[str]:
    found: List[str] = []
    agents_dir = os.path.join(dest_dir, "agents")
    if os.path.isdir(agents_dir):
        for name in sorted(os.listdir(agents_dir)):
            if name.endswith(".md"):
                found.append(os.path.join(agents_dir, name))
    config_path = os.path.join(dest_dir, CONFIG_FILENAME)
    if os.path.isfile(config_path):
        found.append(config_path)
    return found


def sync(
    dest_dir: str,
    skills_path: str = DEFAULT_SKILLS_PATH,
    mcp_command: Sequence[str] = tuple(DEFAULT_MCP_COMMAND.split()),
    include_config: bool = True,
    check: bool = False,
) -> Tuple[int, int, List[str]]:
    """Write (or verify) the managed files. Returns (written, stale, problems)."""
    expected = build_expected(dest_dir, skills_path, mcp_command, include_config)
    written = 0
    stale: List[str] = []
    problems: List[str] = []

    for path, content in sorted(expected.items()):
        current = None
        if os.path.isfile(path):
            current = read_text(path)
        if current == content:
            continue
        if check:
            stale.append(os.path.relpath(path, dest_dir))
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        written += 1

    managed = set(expected)
    for path in _existing_managed(dest_dir):
        if path not in managed:
            problems.append(f"orphan managed file: {path}")
            if not check:
                os.remove(path)

    if check:
        problems.extend(f"stale or missing: {name}" for name in stale)
    return written, len(stale), problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate OpenCode agent files and config from runtime/registry.json"
    )
    parser.add_argument(
        "--dest",
        default=DEFAULT_DEST,
        help="destination .opencode directory (default: %(default)s)",
    )
    parser.add_argument(
        "--skills-path",
        default=DEFAULT_SKILLS_PATH,
        help="skills directory exactly as OpenCode should resolve it from the "
        "working directory it is started in (default: %(default)s)",
    )
    parser.add_argument(
        "--mcp-command",
        default=DEFAULT_MCP_COMMAND,
        help="command that starts the bug-intel MCP server (default: %(default)s)",
    )
    parser.add_argument("--no-config", action="store_true", help="do not write opencode.json")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the destination matches the registry; write nothing, exit 1 when stale",
    )
    args = parser.parse_args(argv)

    dest_dir = os.path.abspath(os.path.expanduser(args.dest))
    try:
        written, stale, problems = sync(
            dest_dir=dest_dir,
            skills_path=args.skills_path,
            mcp_command=args.mcp_command.split(),
            include_config=not args.no_config,
            check=args.check,
        )
    except SyncError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.check:
        for problem in problems:
            print(f"[!] {problem}")
        if problems:
            print("[!] agent runtime is stale; re-run scripts/sync_agent_runtime.py")
            return 1
        print(f"[+] agent runtime in sync ({len(_existing_managed(dest_dir))} managed files)")
        return 0

    for problem in problems:
        print(f"[!] {problem}")
    print(f"[+] agent runtime synced: {written} file(s) written -> {dest_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
