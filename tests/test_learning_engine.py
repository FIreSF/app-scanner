"""Learning engine hook, integrity and lifecycle tests."""

from __future__ import annotations

import os
import sqlite3
import unittest

from tests import support


class LearningEngineTests(unittest.TestCase):
    def setUp(self):
        self._directory = support.temp_dir()
        self.directory = self._directory.__enter__()
        self.db_path = os.path.join(self.directory, "memory.db")
        self.engine = support.load_engine_class()(self.db_path)

    def tearDown(self):
        self._directory.__exit__(None, None, None)

    # ------------------------------------------------------------------ #
    def test_schema_is_created(self):
        connection = sqlite3.connect(self.db_path)
        try:
            tables = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        finally:
            connection.close()
        for table in ("sessions", "tested_variants", "findings", "triage_feedback", "lessons_learned"):
            self.assertIn(table, tables)

    def test_full_lifecycle(self):
        session = self.engine.before_recon("com.example.app", ["okhttp", "sqlite"], mode="hunt")
        session_id = session["session_id"]
        self.assertEqual(session["status"], "INITIALIZED")
        self.assertIsNotNone(self.engine.get_session(session_id))

        variant_id = self.engine.during_testing(
            session_id,
            "ipc",
            "exported-activity-intent-redirection",
            "VULN",
            skill_used="skills/ipc-deeplink-exploitation.md",
            evidence_path="ipc/poc.sh",
        )
        self.assertIsInstance(variant_id, int)

        finding_id = self.engine.after_finding(
            {
                "session_id": session_id,
                "target_package": "com.example.app",
                "title": "Intent redirection",
                "severity": "High",
                "state": "CONFIRMED",
                "masvs_category": "MASVS-PLATFORM",
                "impact": "unexported activity launch",
                "poc_path": "ipc/poc.sh",
            }
        )
        self.assertTrue(finding_id.startswith("FIND-"))

        summary = self.engine.before_summary(session_id)
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["severity_breakdown"]["High"], 1)
        self.assertEqual(summary["state_breakdown"]["CONFIRMED"], 1)
        self.assertEqual(len(summary["tested_surfaces"]), 1)

        self.assertTrue(self.engine.after_triage(finding_id, "FALSE_POSITIVE", "expected behaviour"))
        self.assertEqual(self.engine.stats()["triage_feedback"], 1)
        self.assertEqual(self.engine.stats()["lessons_learned"], 1)

    def test_after_triage_accepts_feedback_dict(self):
        session_id = self.engine.before_recon("com.example.app")["session_id"]
        finding_id = self.engine.after_finding(
            {"session_id": session_id, "target_package": "com.example.app", "title": "x"}
        )
        self.assertTrue(
            self.engine.after_triage({"finding_id": finding_id, "verdict": "DUPLICATE", "comment": "dup"})
        )
        self.assertEqual(self.engine.stats()["triage_feedback"], 1)

    def test_invalid_triage_verdict_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.after_triage("FIND-X", "MAYBE", None)

    def test_invalid_variant_result_rejected(self):
        session_id = self.engine.before_recon("com.example.app")["session_id"]
        with self.assertRaises(ValueError):
            self.engine.during_testing(session_id, "ipc", "variant", "MAYBE")

    def test_foreign_key_enforced_for_variants(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.engine.during_testing("sess_missing", "ipc", "variant", "PASS")

    def test_finding_requires_session(self):
        with self.assertRaises(ValueError):
            self.engine.after_finding({"title": "no session"})

    def test_finding_requires_valid_severity(self):
        session_id = self.engine.before_recon("com.example.app")["session_id"]
        with self.assertRaises(ValueError):
            self.engine.after_finding(
                {"session_id": session_id, "target_package": "com.example.app", "title": "x", "severity": "Severe"}
            )

    def test_before_recon_requires_target(self):
        with self.assertRaises(ValueError):
            self.engine.before_recon("  ")

    def test_state_updates_and_lookup(self):
        session_id = self.engine.before_recon("com.example.app")["session_id"]
        finding_id = self.engine.after_finding(
            {
                "session_id": session_id,
                "target_package": "com.example.app",
                "title": "x",
                "signature_hash": "abcdef12",
            }
        )
        self.assertTrue(self.engine.set_finding_state(finding_id, "VALIDATED", verified=True))
        stored = self.engine.get_finding(finding_id)
        self.assertEqual(stored["state"], "VALIDATED")
        self.assertEqual(stored["verified"], 1)
        matches = self.engine.find_by_signature("abcdef12")
        self.assertEqual(len(matches), 1)

    def test_end_session_and_list_sessions(self):
        session_id = self.engine.before_recon("com.example.app")["session_id"]
        self.assertTrue(self.engine.end_session(session_id, "wrapped up"))
        self.assertIsNotNone(self.engine.get_session(session_id)["end_time"])
        self.assertEqual(len(self.engine.list_sessions()), 1)
        self.assertFalse(self.engine.end_session("sess_missing"))

    def test_list_findings_filters(self):
        session_id = self.engine.before_recon("com.example.app")["session_id"]
        self.engine.after_finding({"session_id": session_id, "target_package": "com.example.app", "title": "one"})
        other_session = self.engine.before_recon("com.other.app")["session_id"]
        self.engine.after_finding({"session_id": other_session, "target_package": "com.other.app", "title": "two"})
        self.assertEqual(len(self.engine.list_findings(target="com.example.app")), 1)
        self.assertEqual(len(self.engine.list_findings(session_id=session_id)), 1)
        self.assertEqual(len(self.engine.list_findings()), 2)

    def test_env_override_is_honoured(self):
        with support.isolated_engine_db() as env_db:
            engine = support.load_engine_class()()
            self.assertEqual(os.path.abspath(engine.db_path), os.path.abspath(env_db))

    def test_engine_runs_as_plain_script(self):
        """`python learning_engine/engine.py stats` is documented and must work."""
        import subprocess
        import sys

        script = os.path.join(support.ROOT_DIR, "learning_engine", "engine.py")
        env = dict(os.environ, MOBILE_AGENT_LEARNING_DB=self.db_path)
        completed = subprocess.run(
            [sys.executable, script, "stats"],
            cwd=support.ROOT_DIR,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("db_path", completed.stdout)
        self.assertNotIn("ModuleNotFoundError", completed.stderr)

    def test_module_entry_point_matches_script_entry_point(self):
        """`python -m learning_engine` and the plain script share one CLI."""
        import subprocess
        import sys

        env = dict(os.environ, MOBILE_AGENT_LEARNING_DB=self.db_path)
        module = subprocess.run(
            [sys.executable, "-m", "learning_engine", "stats"],
            cwd=support.ROOT_DIR,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(module.returncode, 0, module.stderr)
        self.assertIn("db_path", module.stdout)

    def test_init_and_end_support_json(self):
        import json
        import subprocess
        import sys

        env = dict(os.environ, MOBILE_AGENT_LEARNING_DB=self.db_path)
        init = subprocess.run(
            [
                sys.executable,
                "-m",
                "learning_engine",
                "init",
                "--target",
                "com.example.json",
                "--session-id",
                "sess_json",
                "--json",
            ],
            cwd=support.ROOT_DIR,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(init.returncode, 0, init.stderr)
        payload = json.loads(init.stdout)
        self.assertEqual(payload["session_id"], "sess_json")

        end = subprocess.run(
            [sys.executable, "-m", "learning_engine", "end", "--session", "sess_json", "--json"],
            cwd=support.ROOT_DIR,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(end.returncode, 0, end.stderr)
        self.assertTrue(json.loads(end.stdout)["closed"])


if __name__ == "__main__":
    unittest.main()
