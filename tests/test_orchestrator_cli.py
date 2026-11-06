"""End-to-end CLI tests (argument order, dry-run guarantees, exit codes)."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stdout

from tests import support


class OrchestratorCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = support.load_runner_module()

    def _run(self, argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = self.runner.main(argv)
        return code, buffer.getvalue()

    # ------------------------------------------------------------------ #
    def test_link_check_passes(self):
        code, output = self._run(["link-check"])
        self.assertEqual(code, 0)
        self.assertIn("PASS", output)

    def test_plan_accepts_target_after_subcommand(self):
        code, output = self._run(["plan", "--target", "com.example.after", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["target"], "com.example.after")
        self.assertEqual(payload["concurrency_limit"], 3)

    def test_plan_accepts_target_before_subcommand(self):
        code, output = self._run(["--target", "com.example.before", "plan", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["target"], "com.example.before")

    def test_bootstrap_accepts_target_after_subcommand(self):
        with support.isolated_engine_db():
            with support.temp_dir() as directory:
                code, output = self._run(
                    [
                        "bootstrap",
                        "--target",
                        "com.example.app",
                        "--workspace",
                        directory,
                        "--allow-external-workspace",
                        "--no-session",
                    ]
                )
                self.assertTrue(os.path.isfile(os.path.join(directory, "notes", "bootstrap.md")))
                self.assertTrue(os.path.isfile(os.path.join(directory, "evidence", "artifact.json")))
        # 0 = READY, 2 = DEGRADED (optional tooling missing on this host).
        self.assertIn(code, (0, 2))
        self.assertIn("PREFLIGHT STATUS", output)

    def test_bootstrap_exit_code_matches_preflight_contract(self):
        """The runner must agree with runtime_preflight.py: 0 READY, 1 BLOCKED, 2 DEGRADED."""
        with support.isolated_engine_db():
            with support.temp_dir() as directory:
                code, output = self._run(
                    [
                        "bootstrap",
                        "--target",
                        "com.example.app",
                        "--workspace",
                        directory,
                        "--allow-external-workspace",
                        "--no-session",
                    ]
                )
        status = output.rsplit("PREFLIGHT STATUS:", 1)[1].strip()
        expected = {"READY": 0, "BLOCKED": 1, "DEGRADED": 2}[status]
        self.assertEqual(code, expected)

    def test_bootstrap_strict_fails_on_degraded(self):
        with support.isolated_engine_db():
            with support.temp_dir() as directory:
                code, output = self._run(
                    [
                        "bootstrap",
                        "--target",
                        "com.example.app",
                        "--workspace",
                        directory,
                        "--allow-external-workspace",
                        "--no-session",
                        "--strict",
                    ]
                )
        status = output.rsplit("PREFLIGHT STATUS:", 1)[1].strip()
        self.assertEqual(code, 0 if status == "READY" else 1)

    def test_bootstrap_invalid_target_exits_one(self):
        with support.temp_dir() as directory:
            code, _ = self._run(
                [
                    "bootstrap",
                    "--target",
                    "not a package!!",
                    "--workspace",
                    directory,
                    "--allow-external-workspace",
                    "--no-session",
                ]
            )
        self.assertEqual(code, 1)

    def test_gate_on_complete_finding(self):
        with support.temp_dir() as directory:
            path = support.write_json(os.path.join(directory, "finding.json"), support.make_finding())
            code, output = self._run(["gate", "--file", path, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(output)
        self.assertEqual(payload["verdict"], "APPROVED")
        self.assertEqual(payload["final_state"], "VALIDATED")

    def test_gate_blocks_unverified_finding(self):
        with support.temp_dir() as directory:
            finding = support.make_finding(verification_verdict="INCONCLUSIVE")
            path = support.write_json(os.path.join(directory, "finding.json"), finding)
            code, output = self._run(["gate", "--file", path, "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output)["verdict"], "DOWNGRADED")

    def test_gate_accepts_utf8_bom_file(self):
        with support.temp_dir() as directory:
            path = os.path.join(directory, "finding.json")
            with open(path, "w", encoding="utf-8-sig", newline="\n") as handle:
                json.dump(support.make_finding(), handle)
            code, _ = self._run(["gate", "--file", path])
        self.assertEqual(code, 0)

    def test_test_gate_does_not_persist_by_default(self):
        with support.isolated_engine_db():
            engine = support.load_engine_class()()
            before = engine.stats()["findings"]
            code, output = self._run(["test-gate", "--title", "Demo Finding", "--severity", "High"])
            after = engine.stats()["findings"]
        self.assertEqual(code, 0)
        self.assertIn("DEMO MODE", output)
        self.assertEqual(before, after)

    def test_test_gate_verdict_is_not_a_real_verification(self):
        code, output = self._run(["test-gate", "--verified", "--json"])
        payload = json.loads(output)
        self.assertEqual(code, 0)
        self.assertNotEqual(payload["final_state"], "REPORTABLE")
        self.assertFalse(payload["reporting_gate_open"])

    def test_transition_refusal_exit_code(self):
        with support.temp_dir() as directory:
            finding = support.make_finding(state="CONFIRMED")
            path = support.write_json(os.path.join(directory, "finding.json"), finding)
            code, output = self._run(["transition", "--file", path, "--to", "REPORTABLE"])
        self.assertEqual(code, 1)
        self.assertIn("REFUSED", output)

    def test_transition_apply_writes_state(self):
        with support.temp_dir() as directory:
            path = support.write_json(os.path.join(directory, "finding.json"), support.make_finding())
            code, _ = self._run(["transition", "--file", path, "--to", "VALIDATED", "--apply"])
            stored = json.loads(support.read_text(path))
        self.assertEqual(code, 0)
        self.assertEqual(stored["state"], "VALIDATED")

    def test_fp_db_check_known_and_unknown(self):
        code, _ = self._run(["fp-db", "check", "--hash", "3a8f1b20"])
        self.assertEqual(code, 0)
        code, _ = self._run(["fp-db", "check", "--hash", "ffffffff"])
        self.assertEqual(code, 1)

    def test_fp_db_commands_support_json(self):
        code, output = self._run(["fp-db", "list", "--json"])
        self.assertEqual(code, 0)
        self.assertIsInstance(json.loads(output), list)

        code, output = self._run(["fp-db", "check", "--hash", "ffffffff", "--json"])
        payload = json.loads(output)
        self.assertEqual(code, 1)
        self.assertFalse(payload["known"])

    def test_mindmap_writes_and_checks(self):
        with support.temp_dir() as directory:
            code, output = self._run(
                ["mindmap", "--target", "com.example.app", "--workspace", directory]
            )
            path = os.path.join(directory, "notes", "MINDMAP.md")
            self.assertTrue(os.path.isfile(path))
            content = support.read_text(path)
            check_code, _ = self._run(
                ["mindmap", "--target", "com.example.app", "--workspace", directory, "--check"]
            )
        self.assertEqual(code, 0)
        self.assertIn("Mindmap written", output)
        self.assertIn("graph TD", content)
        self.assertEqual(check_code, 0)

    def test_report_dry_run_then_approve(self):
        with support.temp_dir() as directory:
            finding = support.make_finding(state="VALIDATED")
            support.write_json(os.path.join(directory, "findings", "FIND-1.json"), finding)
            code, output = self._run(
                ["report", "--target", "com.example.app", "--workspace", directory, "--json"]
            )
            payload = json.loads(output)
            report_path = os.path.join(directory, "reports", "final-report.md")
            self.assertFalse(os.path.exists(report_path))
            approve_code, _ = self._run(
                ["report", "--target", "com.example.app", "--workspace", directory, "--approve"]
            )
            self.assertTrue(os.path.isfile(report_path))
        self.assertEqual(code, 0)
        self.assertEqual(payload["totals"]["included"], 1)
        self.assertEqual(approve_code, 0)

    def test_ledger_record_updates_tested_variants(self):
        with support.isolated_engine_db():
            with support.temp_dir() as directory:
                code, _ = self._run(
                    [
                        "ledger",
                        "--target",
                        "com.example.app",
                        "--workspace",
                        directory,
                        "--agent",
                        "ipc-attack-agent",
                        "--surface",
                        "IPC",
                        "--action",
                        "exported activity intent replay",
                        "--result",
                        "BLOCKED",
                        "--evidence",
                        "ipc/intents.log",
                        "--record",
                        "--skill",
                        "ipc-deeplink-exploitation.md",
                        "--device-state",
                        "emulator-5554 / user A",
                        "--reason",
                        "permission denied",
                        "--next",
                        "user B, deep link entry",
                    ]
                )
                content = support.read_text(os.path.join(directory, "notes", "tested-variants.md"))
        self.assertEqual(code, 0)
        self.assertIn("ipc-deeplink-exploitation.md", content)
        self.assertIn("emulator-5554 / user A", content)
        self.assertNotIn("(none yet)", content)

    def test_transition_apply_json_is_valid(self):
        with support.temp_dir() as directory:
            path = support.write_json(
                os.path.join(directory, "finding.json"),
                support.make_finding(state="CONFIRMED"),
            )
            code, output = self._run(
                ["transition", "--file", path, "--to", "VALIDATED", "--apply", "--json"]
            )
            payload = json.loads(output)
            stored = json.loads(support.read_text(path))
        self.assertEqual(code, 0)
        self.assertTrue(payload["applied"])
        self.assertEqual(stored["state"], "VALIDATED")

    def test_ledger_appends_entry(self):
        with support.temp_dir() as directory:
            code, _ = self._run(
                [
                    "ledger",
                    "--target",
                    "com.example.app",
                    "--workspace",
                    directory,
                    "--agent",
                    "static-agent",
                    "--surface",
                    "MANIFEST",
                    "--action",
                    "component enumeration",
                    "--result",
                    "FOUND_EXPORTS",
                    "--evidence",
                    "static/manifest.json",
                ]
            )
            content = support.read_text(os.path.join(directory, "notes", "CONTEXT_LEDGER.md"))
        self.assertEqual(code, 0)
        self.assertIn("static-agent | MANIFEST | component enumeration | FOUND_EXPORTS", content)

    def test_coverage_writes_reports(self):
        with support.temp_dir() as directory:
            code, output = self._run(
                ["coverage", "--target", "com.example.app", "--workspace", directory]
            )
            coverage_file = os.path.join(directory, "compliance", "masvs-coverage.md")
            self.assertTrue(os.path.isfile(coverage_file))
        self.assertEqual(code, 0)
        self.assertIn("MASVS coverage", output)

    def test_waves_next(self):
        code, output = self._run(
            [
                "waves",
                "--completed",
                "static-agent,root-device-agent,emulator-agent",
                "--next",
            ]
        )
        self.assertEqual(code, 0)
        self.assertIn("mcp-bug-intel-agent", output)

    def test_summary_unknown_session(self):
        with support.isolated_engine_db():
            code, _ = self._run(["summary", "--session", "sess_missing"])
        self.assertEqual(code, 1)

    def test_doctor_runs(self):
        with support.isolated_engine_db():
            code, output = self._run(["doctor"])
        self.assertEqual(code, 0)
        self.assertIn("DOCTOR", output)

    def test_validate_registry(self):
        code, output = self._run(["validate-registry"])
        self.assertEqual(code, 0)
        self.assertIn("PASS", output)


if __name__ == "__main__":
    unittest.main()
