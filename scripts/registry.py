#!/usr/bin/env python3
"""
Registry loader, validator and wave planner.

`runtime/registry.json` is the canonical machine-readable roster (see
AGENTS.md).  This module is the only place that reads it, so every script and
test agrees on how the roster is interpreted.

Responsibilities
----------------
* Load the registry with clear error messages.
* Validate structure, agent fields, index uniqueness, dependency graph,
  concurrency bounds and every referenced path (briefing, skills).
* Compute dependency waves and the next dispatchable agents while honouring
  the global concurrency ceiling.
* Provide a `link_check()` used by `orchestrator_runner.py link-check` that
  covers *all* canonical references (docs, skills, templates, memory, scripts).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REGISTRY_PATH = os.path.join(ROOT_DIR, "runtime", "registry.json")

ROOT_AGENT_ID = "orchestrator-agent"

REQUIRED_AGENT_FIELDS: Tuple[str, ...] = (
    "id",
    "index",
    "name",
    "class",
    "spawn_trigger",
    "depends_on",
    "touches_device",
    "target_network",
    "max_concurrent",
    "tools_allowed",
    "skills",
    "briefing_path",
)

# Canonical execution phases (docs §6).  Every non-root agent must appear in
# exactly one phase; this is validated so the documentation cannot drift away
# from the registry.
PHASES: List[Tuple[str, str, List[str]]] = [
    ("0", "INTAKE & SCOPE LOCK (orchestrator-agent)", []),
    ("1", "STATIC & INFRASTRUCTURE (parallel)", ["static-agent", "root-device-agent", "emulator-agent"]),
    ("2", "CVE INTEL & STATIC CRYPTO (parallel)", ["mcp-bug-intel-agent", "crypto-analysis-agent"]),
    ("3", "FRIDA HOOK GENERATION", ["frida-script-agent"]),
    ("4A", "DEVICE-BOUND EXPLORATION — WAVE A", ["network-traffic-agent", "storage-analysis-agent", "dynamic-agent"]),
    ("4B", "DEVICE-BOUND EXPLORATION — WAVE B", ["resilience-agent", "ipc-attack-agent", "webview-agent"]),
    ("5", "EXPLOITATION", ["exploitation-agent"]),
    ("6", "ADVERSARIAL VERIFICATION", ["verification-agent"]),
    ("7", "COMPLIANCE GAP CHECK", ["compliance-agent"]),
    ("8", "REPORT ASSEMBLY (user gated)", ["reporting-agent"]),
    ("9", "WRAP-UP & PERSISTENCE", []),
]

# Agents triggered per lead/finding/user gate rather than by phase completion.
# They stay out of the default "next dispatchable" set.
ON_DEMAND_AGENTS = frozenset({"exploitation-agent", "verification-agent", "reporting-agent"})


# Files every session depends on.  Glob entries are expanded by link_check().
CORE_REQUIRED_FILES: Tuple[str, ...] = (
    "AGENTS.md",
    "agent-briefing.md",
    "prioritization.md",
    "login.md",
    "README.md",
    "runtime/registry.json",
    "runtime/opencode/ORCHESTRATION.md",
    ".agents/skills/learning-engine-integration/SKILL.md",
    "memory/FALSE_POSITIVE_DB.md",
    "memory/CONTEXT_LEDGER.md",
    "memory/methodology.md",
    "memory/patterns.md",
    "memory/report-lessons.md",
    "skills/master-bugbounty-rules.md",
    "learning_engine/engine.py",
    "learning_engine/schema.sql",
    "scripts/orchestrator_runner.py",
    "scripts/runtime_preflight.py",
    "scripts/skill_registry.py",
    "scripts/registry.py",
    "scripts/findings.py",
    "scripts/compliance_matrix.py",
    "scripts/writeup_index.py",
    "scripts/mindmap.py",
    "scripts/report_builder.py",
    "writeups/README.md",
    "writeups/index.md",
)

CORE_REQUIRED_GLOBS: Tuple[str, ...] = (
    "memory/targets/*.md",
    "templates/frida/*.js",
    "runtime/opencode/agents/*.md",
)


class RegistryError(Exception):
    """Raised when the registry cannot be loaded or parsed."""


class ValidationResult:
    """Container for registry/link validation output."""

    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.checked: int = 0

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def status(self) -> str:
        return "PASS" if self.ok else "FAIL"

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "checked": self.checked,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            # Backwards-compatible key used by the original CLI output.
            "missing": list(self.errors),
        }


def load_registry(path: str = REGISTRY_PATH) -> Dict[str, Any]:
    """Load and parse the registry, raising RegistryError on failure."""
    if not os.path.isfile(path):
        raise RegistryError(f"Registry not found at {path}")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"Registry is not valid JSON ({path}): {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError(f"Registry root must be an object ({path})")
    return data


def iter_agents(registry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return agent definitions sorted by their declared index."""
    agents = registry.get("agents") or {}
    if not isinstance(agents, dict):
        return []
    return sorted(agents.values(), key=lambda a: a.get("index", 10**6))


def agent_ids(registry: Dict[str, Any]) -> List[str]:
    return [a["id"] for a in iter_agents(registry) if isinstance(a, dict) and "id" in a]


def sub_agent_ids(registry: Dict[str, Any]) -> List[str]:
    return [aid for aid in agent_ids(registry) if aid != ROOT_AGENT_ID]


def concurrency_limit(registry: Dict[str, Any]) -> int:
    try:
        limit = int(registry.get("concurrency_limit", 3))
    except (TypeError, ValueError):
        limit = 3
    return max(1, limit)


def get_agent(registry: Dict[str, Any], agent_id: str) -> Optional[Dict[str, Any]]:
    agents = registry.get("agents") or {}
    agent = agents.get(agent_id)
    return agent if isinstance(agent, dict) else None


def _find_cycles(graph: Dict[str, Sequence[str]]) -> List[List[str]]:
    """Return dependency cycles (each a list of node ids) using depth-first search."""
    WHITE, GREY, BLACK = 0, 1, 2
    colour: Dict[str, int] = {node: WHITE for node in graph}
    cycles: List[List[str]] = []
    path: List[str] = []

    def visit(node: str) -> None:
        colour[node] = GREY
        path.append(node)
        for child in graph.get(node, ()):
            if child not in colour:
                continue
            if colour[child] == GREY:
                if child in path:
                    cycles.append(path[path.index(child):] + [child])
            elif colour[child] == WHITE:
                visit(child)
        path.pop()
        colour[node] = BLACK

    for node in graph:
        if colour[node] == WHITE:
            visit(node)
    return cycles


def validate_registry(registry: Dict[str, Any], root_dir: str = ROOT_DIR) -> ValidationResult:
    """Validate registry structure, graph and referenced paths."""
    result = ValidationResult()

    for key in ("name", "version", "concurrency_limit", "agents"):
        if key not in registry:
            result.error(f"Registry is missing required top-level key '{key}'")

    agents = registry.get("agents")
    if not isinstance(agents, dict) or not agents:
        result.error("Registry 'agents' must be a non-empty object")
        return result

    limit = concurrency_limit(registry)
    if not isinstance(registry.get("concurrency_limit"), int) or limit < 1:
        result.error("'concurrency_limit' must be a positive integer")

    if ROOT_AGENT_ID not in agents:
        result.error(f"Root agent '{ROOT_AGENT_ID}' is missing from the registry")

    seen_indexes: Dict[int, str] = {}
    for key, agent in agents.items():
        if not isinstance(agent, dict):
            result.error(f"Agent '{key}' must be an object")
            continue

        for field in REQUIRED_AGENT_FIELDS:
            if field not in agent:
                result.error(f"Agent '{key}' is missing required field '{field}'")

        if agent.get("id") != key:
            result.error(f"Agent key '{key}' does not match its id '{agent.get('id')}'")

        index = agent.get("index")
        if not isinstance(index, int):
            result.error(f"Agent '{key}' index must be an integer")
        elif index in seen_indexes:
            result.error(f"Duplicate agent index {index}: '{seen_indexes[index]}' and '{key}'")
        else:
            seen_indexes[index] = key

        if not str(agent.get("spawn_trigger", "")).strip():
            result.error(f"Agent '{key}' has an empty spawn_trigger")

        depends_on = agent.get("depends_on")
        if not isinstance(depends_on, list):
            result.error(f"Agent '{key}' depends_on must be a list")
            depends_on = []
        for dep in depends_on:
            if dep not in agents:
                result.error(f"Agent '{key}' depends on unknown agent '{dep}'")
            if dep == key:
                result.error(f"Agent '{key}' depends on itself")

        max_concurrent = agent.get("max_concurrent")
        if not isinstance(max_concurrent, int) or max_concurrent < 1:
            result.error(f"Agent '{key}' max_concurrent must be a positive integer")
        elif max_concurrent > limit:
            result.error(
                f"Agent '{key}' max_concurrent ({max_concurrent}) exceeds the global "
                f"concurrency_limit ({limit})"
            )

        tools = agent.get("tools_allowed")
        if not isinstance(tools, list) or not tools:
            result.error(f"Agent '{key}' tools_allowed must be a non-empty list")

        skills = agent.get("skills")
        if not isinstance(skills, list):
            result.error(f"Agent '{key}' skills must be a list")
            skills = []
        for skill in skills:
            skill_path = os.path.join(root_dir, skill)
            if not os.path.isfile(skill_path):
                result.error(f"Agent '{key}' references missing skill '{skill}'")
            else:
                result.checked += 1

        briefing = agent.get("briefing_path")
        if not briefing:
            result.error(f"Agent '{key}' has an empty briefing_path")
        else:
            briefing_path = os.path.join(root_dir, briefing)
            if not os.path.isfile(briefing_path):
                result.error(f"Agent '{key}' briefing is missing: {briefing}")
            else:
                result.checked += 1

    graph = {
        key: [d for d in (agent.get("depends_on") or []) if isinstance(d, str)]
        for key, agent in agents.items()
        if isinstance(agent, dict)
    }
    for cycle in _find_cycles(graph):
        result.error("Dependency cycle detected: " + " -> ".join(cycle))

    root_agents = [k for k, a in agents.items() if isinstance(a, dict) and a.get("class") == "Root / Main"]
    if root_agents != [ROOT_AGENT_ID]:
        result.error(
            "Exactly one agent must have class 'Root / Main' and it must be "
            f"'{ROOT_AGENT_ID}' (found: {root_agents or 'none'})"
        )

    indexes = sorted(seen_indexes)
    if indexes and indexes != list(range(len(indexes))):
        result.error(f"Agent indexes must be contiguous from 0; found {indexes}")

    phased: Set[str] = set()
    for phase_id, _title, members in PHASES:
        for member in members:
            if member not in agents:
                result.error(f"Phase {phase_id} references unknown agent '{member}'")
            if member in phased:
                result.error(f"Agent '{member}' is assigned to more than one phase")
            phased.add(member)
    missing_from_phases = sorted(set(sub_agent_ids(registry)) - phased)
    if missing_from_phases:
        result.error("Agents missing from the execution phase plan: " + ", ".join(missing_from_phases))

    return result


def link_check(root_dir: str = ROOT_DIR, registry_path: str = REGISTRY_PATH) -> ValidationResult:
    """Validate the registry plus every canonical file reference in the repo."""
    result = ValidationResult()
    try:
        registry = load_registry(registry_path)
    except RegistryError as exc:
        result.error(str(exc))
        return result

    registry_result = validate_registry(registry, root_dir)
    result.errors.extend(registry_result.errors)
    result.warnings.extend(registry_result.warnings)
    result.checked += registry_result.checked

    for relative in CORE_REQUIRED_FILES:
        path = os.path.join(root_dir, relative)
        if os.path.isfile(path):
            result.checked += 1
        else:
            result.error(f"Missing core file: {relative}")

    import glob as _glob

    for pattern in CORE_REQUIRED_GLOBS:
        matches = _glob.glob(os.path.join(root_dir, pattern))
        if not matches:
            result.error(f"Missing core files matching: {pattern}")
        else:
            result.checked += len(matches)

    return result


def dependency_waves(registry: Dict[str, Any]) -> List[List[str]]:
    """Kahn-layered dependency waves for sub-agents (root excluded)."""
    agents = registry.get("agents") or {}
    sub_ids = set(sub_agent_ids(registry))
    remaining = set(sub_ids)
    completed: Set[str] = {ROOT_AGENT_ID}
    waves: List[List[str]] = []

    while remaining:
        ready = sorted(
            (
                aid
                for aid in remaining
                if all(dep in completed for dep in (agents[aid].get("depends_on") or []))
            ),
            key=lambda aid: agents[aid].get("index", 10**6),
        )
        if not ready:  # cycle guard — validate_registry reports the real error
            waves.append(sorted(remaining, key=lambda aid: agents[aid].get("index", 10**6)))
            break
        waves.append(ready)
        completed.update(ready)
        remaining.difference_update(ready)
    return waves


def phase_order() -> Dict[str, int]:
    """Map phase id -> ordinal position (0 = intake)."""
    return {phase_id: position for position, (phase_id, _title, _members) in enumerate(PHASES)}


def phase_of(agent_id: str) -> Optional[str]:
    for phase_id, _title, members in PHASES:
        if agent_id in members:
            return phase_id
    return None


def next_dispatchable(
    registry: Dict[str, Any],
    completed: Iterable[str] = (),
    running: Iterable[str] = (),
    limit: Optional[int] = None,
    phases: Optional[Iterable[str]] = None,
    include_on_demand: bool = False,
) -> List[str]:
    """Return agents that may be spawned now, capped by the concurrency limit.

    Agents are ordered by phase, then registry index.  Per-lead / per-finding /
    user-gated agents (`exploitation-agent`, `verification-agent`,
    `reporting-agent`) are excluded unless `include_on_demand` is set.
    """
    agents = registry.get("agents") or {}
    done = set(completed) | {ROOT_AGENT_ID}
    active = set(running)
    ceiling = concurrency_limit(registry)
    if limit is not None:
        ceiling = min(ceiling, max(0, int(limit)))
    slots = max(0, ceiling - len(active))
    if slots == 0:
        return []

    order = phase_order()
    allowed_phases = set(phases) if phases else None

    ready = [
        aid
        for aid in sub_agent_ids(registry)
        if aid not in done
        and aid not in active
        and all(dep in done for dep in (agents[aid].get("depends_on") or []))
        and (include_on_demand or aid not in ON_DEMAND_AGENTS)
        and (allowed_phases is None or phase_of(aid) in allowed_phases)
    ]
    ready.sort(key=lambda aid: (order.get(phase_of(aid) or "9", 99), agents[aid].get("index", 10**6)))
    return ready[:slots]



def _parse_id_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Registry validator and wave planner")
    sub = parser.add_subparsers(dest="command")

    validate_parser = sub.add_parser("validate", help="Validate registry structure and references")
    validate_parser.add_argument("--json", action="store_true")

    agents_parser = sub.add_parser("agents", help="List registered agents")
    agents_parser.add_argument("--json", action="store_true")

    waves_parser = sub.add_parser("waves", help="Show dependency waves or next dispatchable agents")
    waves_parser.add_argument("--completed", default="", help="Comma-separated completed agent ids")
    waves_parser.add_argument("--running", default="", help="Comma-separated running agent ids")
    waves_parser.add_argument("--limit", type=int, default=None, help="Override concurrency ceiling")
    waves_parser.add_argument("--phase", default="", help="Restrict to phase id(s), e.g. 1 or 4A,4B")
    waves_parser.add_argument(
        "--include-on-demand",
        action="store_true",
        help="Include exploitation/verification/reporting agents",
    )
    waves_parser.add_argument("--next", action="store_true", help="Print only the next dispatchable set")
    waves_parser.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    try:
        registry = load_registry()
    except RegistryError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    if args.command == "validate":
        result = validate_registry(registry)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"[*] Registry validation: {result.status} ({result.checked} referenced files resolved)")
            for warning in result.warnings:
                print(f"[!] {warning}")
            for error in result.errors:
                print(f"[-] {error}")
        return 0 if result.ok else 1

    if args.command == "agents":
        rows = [
            {
                "index": agent.get("index"),
                "id": agent.get("id"),
                "class": agent.get("class"),
                "device": bool(agent.get("touches_device")),
                "network": bool(agent.get("target_network")),
                "max_concurrent": agent.get("max_concurrent"),
                "depends_on": agent.get("depends_on") or [],
            }
            for agent in iter_agents(registry)
        ]
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            print(f"{'IDX':<4}{'AGENT':<26}{'CLASS':<16}{'DEV':<5}{'NET':<5}{'MAX':<4}DEPENDS ON")
            for row in rows:
                print(
                    f"{row['index']:<4}{row['id']:<26}{row['class']:<16}"
                    f"{('yes' if row['device'] else 'no'):<5}{('yes' if row['network'] else 'no'):<5}"
                    f"{row['max_concurrent']:<4}{', '.join(row['depends_on']) or '-'}"
                )
        return 0

    completed = _parse_id_list(args.completed)
    running = _parse_id_list(args.running)
    phase_filter = _parse_id_list(args.phase) or None
    waves = dependency_waves(registry)
    nxt = next_dispatchable(
        registry,
        completed,
        running,
        args.limit,
        phases=phase_filter,
        include_on_demand=args.include_on_demand,
    )

    if args.json:
        payload = {
            "waves": waves,
            "next": nxt,
            "concurrency_limit": concurrency_limit(registry),
            "phases": [
                {"id": phase_id, "title": title, "agents": members}
                for phase_id, title, members in PHASES
            ],
        }
        print(json.dumps(payload, indent=2))
    elif args.next:
        print(",".join(nxt) if nxt else "(nothing dispatchable)")
    else:
        print(f"[*] Concurrency limit: {concurrency_limit(registry)}")
        print("[*] Canonical phases:")
        for phase_id, title, members in PHASES:
            label = ", ".join(members) if members else "(orchestrator only)"
            print(f"    [{phase_id}] {title}: {label}")
        print("[*] Dependency waves:")
        for number, wave in enumerate(waves, start=1):
            print(f"    Wave {number}: {', '.join(wave)}")
        print(f"[*] Next dispatchable ({len(nxt)}): {', '.join(nxt) if nxt else '(none)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
