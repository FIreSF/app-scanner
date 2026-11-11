#!/usr/bin/env python3
"""
SQLite-backed Learning Engine.

Implements the five lifecycle memory hooks described in
`.agents/skills/learning-engine-integration/SKILL.md`:

1. before_recon(target, technologies)   -> open a session, return past lessons
2. during_testing(surface, test_result) -> append a tested variant
3. after_finding(finding_dict)          -> persist a finding + signature hash
4. before_summary(target)               -> aggregate the session
5. after_triage(feedback_dict)          -> record triage outcome (+ lesson on FP)

Design notes
------------
* Every connection is opened and closed inside a context manager; no leaked
  file descriptors.
* `PRAGMA foreign_keys = ON` is enforced, so orphan rows are impossible.
* The engine records state; it never decides it. Promotion authority lives in
  `scripts/findings.py` (state machine + Hard FP Gate).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "learning_memory.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

VALID_RESULTS = {"PASS", "VULN", "BLOCKED", "FP"}
VALID_VERDICTS = {"ACCEPTED", "DUPLICATE", "NOT_APPLICABLE", "OUT_OF_SCOPE", "FALSE_POSITIVE"}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}


class LearningEngine:
    """Thin, transactional wrapper around the learning memory database."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("MOBILE_AGENT_LEARNING_DB") or DEFAULT_DB_PATH
        self._init_db()

    # ------------------------------------------------------------------ #
    # Connection handling
    # ------------------------------------------------------------------ #
    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _init_db(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.db_path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        if not os.path.isfile(SCHEMA_PATH):
            raise FileNotFoundError(f"Learning engine schema not found at {SCHEMA_PATH}")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as handle:
            schema = handle.read()
        with self._connect() as connection:
            connection.executescript(schema)

    def close(self) -> None:
        """Compatibility no-op: connections are always closed per call."""
        return None

    # ------------------------------------------------------------------ #
    # Hook 1: before_recon
    # ------------------------------------------------------------------ #
    def before_recon(
        self,
        target: str,
        technologies: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        mode: str = "hunt",
    ) -> Dict[str, Any]:
        if not str(target or "").strip():
            raise ValueError("target must be a non-empty package name or bundle id")
        session_id = session_id or f"sess_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        tech_json = json.dumps(technologies or [])
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO sessions (session_id, target_package, technologies, mode) "
                "VALUES (?, ?, ?, ?)",
                (session_id, target, tech_json, mode),
            )
            cursor = connection.execute(
                "SELECT surface, pattern, lesson FROM lessons_learned ORDER BY id DESC LIMIT 20"
            )
            lessons = [dict(row) for row in cursor.fetchall()]

        return {
            "session_id": session_id,
            "target": target,
            "technologies": technologies or [],
            "mode": mode,
            "past_lessons_count": len(lessons),
            "relevant_lessons": lessons,
            "status": "INITIALIZED",
        }

    # Alias used by newer call sites.
    start_session = before_recon

    # ------------------------------------------------------------------ #
    # Hook 2: during_testing
    # ------------------------------------------------------------------ #
    def during_testing(
        self,
        session_id: str,
        surface: str,
        variant_tested: str,
        result: str,
        skill_used: Optional[str] = None,
        evidence_path: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> int:
        result = str(result or "").strip().upper()
        if result not in VALID_RESULTS:
            raise ValueError(f"result must be one of {sorted(VALID_RESULTS)} (got '{result}')")
        if not str(surface or "").strip() or not str(variant_tested or "").strip():
            raise ValueError("surface and variant_tested must be non-empty")
        with self._connect() as connection:
            cursor = connection.execute(
                """INSERT INTO tested_variants
                   (session_id, surface, variant_tested, skill_used, result, evidence_path, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (session_id, surface, variant_tested, skill_used, result, evidence_path, notes),
            )
            return int(cursor.lastrowid)

    # ------------------------------------------------------------------ #
    # Hook 3: after_finding
    # ------------------------------------------------------------------ #
    def after_finding(self, finding: Dict[str, Any]) -> str:
        if not isinstance(finding, dict):
            raise TypeError("finding must be a dict")
        finding_id = finding.get("finding_id") or f"FIND-{uuid.uuid4().hex[:8].upper()}"
        session_id = finding.get("session_id") or ""
        target_package = finding.get("target_package") or "unknown"
        title = finding.get("title") or "Untitled Finding"
        severity = finding.get("severity") or "Medium"
        state = finding.get("state") or "OBSERVATION"
        masvs_category = finding.get("masvs_category") or "MASVS-CODE"
        impact = finding.get("impact") or ""
        poc_path = finding.get("poc_path") or ""
        verified = 1 if finding.get("verified") else 0

        if not session_id:
            raise ValueError("finding.session_id is required (call before_recon first)")
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")

        signature_raw = f"{target_package}:{title}:{masvs_category}"
        signature_hash = finding.get("signature_hash") or hashlib.sha256(
            signature_raw.encode("utf-8")
        ).hexdigest()[:8]

        with self._connect() as connection:
            # `finding_id` is the table's primary key, but ids such as
            # FIND-0001 are reused by every engagement. Never overwrite another
            # target's row: store the collision under `<target>#<finding_id>`.
            stored_id = finding_id
            existing = connection.execute(
                "SELECT target_package FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
            if existing is not None and (existing["target_package"] or "") != target_package:
                stored_id = f"{target_package}#{finding_id}"
            connection.execute(
                """INSERT OR REPLACE INTO findings
                   (finding_id, session_id, target_package, title, severity, state,
                    signature_hash, masvs_category, impact, poc_path, verified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    stored_id,
                    session_id,
                    target_package,
                    title,
                    severity,
                    state,
                    signature_hash,
                    masvs_category,
                    impact,
                    poc_path,
                    verified,
                ),
            )
        return stored_id

    # ------------------------------------------------------------------ #
    # Hook 4: before_summary
    # ------------------------------------------------------------------ #
    def before_summary(self, session_id: str) -> Dict[str, Any]:
        with self._connect() as connection:
            session_row = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            findings = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at", (session_id,)
                ).fetchall()
            ]
            surfaces = [
                dict(row)
                for row in connection.execute(
                    "SELECT surface, result, count(*) AS count FROM tested_variants "
                    "WHERE session_id = ? GROUP BY surface, result ORDER BY surface",
                    (session_id,),
                ).fetchall()
            ]

        severity_counts = {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Informational")}
        state_counts: Dict[str, int] = {}
        for finding in findings:
            severity_counts[finding.get("severity", "Informational")] = (
                severity_counts.get(finding.get("severity", "Informational"), 0) + 1
            )
            state_counts[finding.get("state", "OBSERVATION")] = (
                state_counts.get(finding.get("state", "OBSERVATION"), 0) + 1
            )

        return {
            "session_id": session_id,
            "target_package": dict(session_row)["target_package"] if session_row else None,
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "state_breakdown": state_counts,
            "findings": findings,
            "tested_surfaces": surfaces,
        }

    # ------------------------------------------------------------------ #
    # Hook 5: after_triage
    # ------------------------------------------------------------------ #
    def after_triage(
        self,
        finding_id: Any = None,
        verdict: Optional[str] = None,
        comment: Optional[str] = None,
        feedback: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Record triage feedback.

        Accepts either a feedback dict as the first positional argument
        (spec §11) or `(finding_id, verdict, comment)`.
        """
        if isinstance(finding_id, dict) and feedback is None:
            feedback = finding_id
            finding_id = None
        if feedback is not None:
            finding_id = finding_id or feedback.get("finding_id")
            verdict = verdict or feedback.get("verdict")
            comment = comment if comment is not None else feedback.get("comment")

        verdict = str(verdict or "").strip().upper()
        if not finding_id:
            raise ValueError("finding_id is required")
        if verdict not in VALID_VERDICTS:
            raise ValueError(f"verdict must be one of {sorted(VALID_VERDICTS)}")

        with self._connect() as connection:
            connection.execute(
                "INSERT INTO triage_feedback (finding_id, verdict, comment) VALUES (?, ?, ?)",
                (finding_id, verdict, comment),
            )
            if verdict == "FALSE_POSITIVE":
                row = connection.execute(
                    "SELECT title, masvs_category FROM findings WHERE finding_id = ?", (finding_id,)
                ).fetchone()
                if row:
                    connection.execute(
                        "INSERT INTO lessons_learned (surface, pattern, lesson) VALUES (?, ?, ?)",
                        (
                            row["masvs_category"] or "UNKNOWN",
                            row["title"],
                            f"Reported as FP: {comment or 'Triaged out'}",
                        ),
                    )
        return True

    # ------------------------------------------------------------------ #
    # Query / maintenance helpers
    # ------------------------------------------------------------------ #
    def end_session(self, session_id: str, summary: Optional[str] = None) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE sessions SET end_time = ? WHERE session_id = ?",
                (datetime.now().isoformat(timespec="seconds"), session_id),
            )
            if cursor.rowcount == 0:
                return False
            if summary:
                connection.execute(
                    "INSERT INTO lessons_learned (surface, pattern, lesson) VALUES (?, ?, ?)",
                    ("SESSION_SUMMARY", session_id, summary),
                )
        return True

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_sessions(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [dict(row) for row in rows]

    def list_findings(self, session_id: Optional[str] = None, target: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM findings"
        clauses: List[str] = []
        params: List[Any] = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if target:
            clauses.append("target_package = ?")
            params.append(target)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at"
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_finding(
        self, finding_id: str, target_package: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Return one finding row, optionally scoped to a target package."""
        query = "SELECT * FROM findings WHERE finding_id = ?"
        params: List[Any] = [finding_id]
        if target_package:
            query += " AND target_package = ?"
            params.append(target_package)
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
        return dict(row) if row else None

    def resolve_finding_id(
        self, finding_id: str, target_package: str
    ) -> Optional[str]:
        """Return the id this finding is stored under for `target_package`.

        `findings.finding_id` is the primary key of the table, but every
        engagement reuses ids such as `FIND-0001`. A finding therefore lives
        either under its plain id (when that id belongs to this target) or
        under the scoped form `<target>#<finding_id>` (when the plain id is
        already taken by another target). Returns None when the target has no
        such finding.
        """
        plain = self.get_finding(finding_id)
        if plain is not None and (plain.get("target_package") or "") == target_package:
            return finding_id
        scoped_id = f"{target_package}#{finding_id}"
        scoped = self.get_finding(scoped_id)
        if scoped is not None and (scoped.get("target_package") or "") == target_package:
            return scoped_id
        return None

    def set_finding_state(self, finding_id: str, state: str, verified: Optional[bool] = None) -> bool:
        assignments = ["state = ?"]
        params: List[Any] = [state]
        if verified is not None:
            assignments.append("verified = ?")
            params.append(1 if verified else 0)
        params.append(finding_id)
        with self._connect() as connection:
            cursor = connection.execute(
                f"UPDATE findings SET {', '.join(assignments)} WHERE finding_id = ?", params
            )
        return cursor.rowcount > 0

    def find_by_signature(self, signature_hash: str) -> List[Dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM findings WHERE signature_hash = ?", (signature_hash,)
            ).fetchall()
        return [dict(row) for row in rows]

    def record_false_positive(self, finding_id: str, reason: Optional[str] = None) -> bool:
        return self.after_triage(finding_id, "FALSE_POSITIVE", reason)

    def stats(self) -> Dict[str, Any]:
        with self._connect() as connection:
            sessions = connection.execute("SELECT count(*) FROM sessions").fetchone()[0]
            findings = connection.execute("SELECT count(*) FROM findings").fetchone()[0]
            variants = connection.execute("SELECT count(*) FROM tested_variants").fetchone()[0]
            feedback = connection.execute("SELECT count(*) FROM triage_feedback").fetchone()[0]
            lessons = connection.execute("SELECT count(*) FROM lessons_learned").fetchone()[0]
        return {
            "db_path": self.db_path,
            "sessions": sessions,
            "findings": findings,
            "tested_variants": variants,
            "triage_feedback": feedback,
            "lessons_learned": lessons,
        }


if __name__ == "__main__":
    if __package__ in (None, ""):
        # Executed as a plain script (`python learning_engine/engine.py`): put the
        # repository root on sys.path so the package-relative CLI imports resolve.
        import sys

        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from learning_engine.cli import main

    raise SystemExit(main())
