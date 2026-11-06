"""Shared helpers for the framework test suite."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import tempfile
from typing import Any, Dict, Iterator, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@contextlib.contextmanager
def temp_dir(prefix: str = "mobile_agent_test_") -> Iterator[str]:
    path = tempfile.mkdtemp(prefix=prefix)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@contextlib.contextmanager
def isolated_engine_db() -> Iterator[str]:
    """Point the learning engine at a throwaway database for the duration."""
    previous = os.environ.get("MOBILE_AGENT_LEARNING_DB")
    with temp_dir("mobile_agent_db_") as directory:
        db_path = os.path.join(directory, "memory.db")
        os.environ["MOBILE_AGENT_LEARNING_DB"] = db_path
        try:
            yield db_path
        finally:
            if previous is None:
                os.environ.pop("MOBILE_AGENT_LEARNING_DB", None)
            else:
                os.environ["MOBILE_AGENT_LEARNING_DB"] = previous


def write_json(path: str, payload: Dict[str, Any]) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return path


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def make_finding(**overrides: Any) -> Dict[str, Any]:
    finding: Dict[str, Any] = {
        "title": "Intent redirection to unexported activity",
        "masvs_category": "MASVS-PLATFORM",
        "severity": "High",
        "impact": "Attacker launches an unexported activity with victim app privileges",
        "poc_command": "adb shell am start -n com.example/.Redirect",
        "reproduced_count": 2,
        "effect_demonstrated": True,
        "cross_context_verified": True,
        "verification_verdict": "CONFIRMED_VALIDATED",
        "user_approved": False,
        "state": "CONFIRMED",
        "chain": "intent redirection -> private file read",
    }
    finding.update(overrides)
    return finding


def load_registry_module():
    from scripts import registry

    return registry


def load_findings_module():
    from scripts import findings

    return findings


def load_preflight_module():
    from scripts import runtime_preflight

    return runtime_preflight


def load_skill_module():
    from scripts import skill_registry

    return skill_registry


def load_coverage_module():
    from scripts import compliance_matrix

    return compliance_matrix


def load_writeup_module():
    from scripts import writeup_index

    return writeup_index


def load_mindmap_module():
    from scripts import mindmap

    return mindmap


def load_report_module():
    from scripts import report_builder

    return report_builder


def load_runner_module():
    from scripts import orchestrator_runner

    return orchestrator_runner


def load_engine_class():
    from learning_engine import LearningEngine

    return LearningEngine
