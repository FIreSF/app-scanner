"""Final report assembly gate tests (spec §6 Phase 8, §8)."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from tests import support


class ReportBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = support.load_report_module()

    def _workspace(self, directory: str, target: str = "com.example.app") -> str:
        support.write_json(
            os.path.join(directory, "evidence", "artifact.json"),
            {
                "target": target,
                "platform": "android",
                "artifact_sha256": "b" * 64,
                "session_id": "sess_report",
            },
        )
        os.makedirs(os.path.join(directory, "findings"), exist_ok=True)
        return directory

    def _finding(self, workspace: str, name: str, **overrides):
        payload = support.make_finding(**overrides)
        support.write_json(os.path.join(workspace, "findings", name), payload)
        return payload

    def test_dry_run_does_not_write(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            self._finding(workspace, "one.json", state="VALIDATED")
            result = self.report.build_report(workspace)
            self.assertFalse(os.path.exists(os.path.join(workspace, "reports", "final-report.md")))
        self.assertTrue(result["approval_required"])
        self.assertEqual(result["totals"]["included"], 1)
        self.assertIn("NOT APPROVED", result["markdown"])

    def test_approve_writes_report(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            self._finding(workspace, "one.json", state="REPORTABLE", user_approved=True)
            result = self.report.build_report(workspace, approve=True)
            path = os.path.join(workspace, "reports", "final-report.md")
            self.assertTrue(os.path.isfile(path))
            content = support.read_text(path)
        self.assertEqual(result["written_to"], path)
        self.assertIn("Intent redirection to unexported activity", content)
        self.assertIn("User gate:** APPROVED", content)
        self.assertIn("b" * 64, content)

    def test_confirmed_finding_is_excluded(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            self._finding(workspace, "one.json", state="CONFIRMED")
            result = self.report.build_report(workspace)
        self.assertEqual(result["totals"]["included"], 0)
        self.assertEqual(result["totals"]["excluded"], 1)
        self.assertIn("below VALIDATED", result["excluded"][0]["reason"])

    def test_declared_state_above_evidence_is_excluded(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            # REPORTABLE without user approval cannot survive recomputation.
            self._finding(workspace, "one.json", state="REPORTABLE", user_approved=False)
            result = self.report.build_report(workspace)
        self.assertEqual(result["totals"]["included"], 0)
        self.assertEqual(result["totals"]["integrity_issues"], 1)
        self.assertIn("exceeds evidence-supported", result["excluded"][0]["reason"])

    def test_findings_are_ordered_by_severity(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            self._finding(workspace, "low.json", title="Low issue", severity="Low", state="VALIDATED")
            self._finding(workspace, "crit.json", title="Critical issue", severity="Critical", state="VALIDATED")
            self._finding(workspace, "high.json", title="High issue", severity="High", state="VALIDATED")
            result = self.report.build_report(workspace)
        self.assertEqual(
            [row["title"] for row in result["included"]],
            ["Critical issue", "High issue", "Low issue"],
        )

    def test_coverage_summary_is_embedded(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            self._finding(workspace, "one.json", state="VALIDATED")
            os.makedirs(os.path.join(workspace, "storage"), exist_ok=True)
            with open(os.path.join(workspace, "storage", "findings.md"), "w", encoding="utf-8") as handle:
                handle.write("# storage evidence\n")
            result = self.report.build_report(workspace)
        self.assertGreaterEqual(result["coverage"]["totals"]["tested"], 1)
        self.assertIn("MASVS v2.0 coverage", result["markdown"])

    def test_no_findings_still_renders(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            result = self.report.build_report(workspace)
        self.assertEqual(result["totals"]["candidates"], 0)
        self.assertIn("No finding passed the reporting gate", result["markdown"])

    def test_cli_json_and_dry_run(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            self._finding(workspace, "one.json", state="VALIDATED")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = self.report.main(["--workspace", workspace, "--json"])
            payload = json.loads(buffer.getvalue())
            self.assertFalse(os.path.exists(os.path.join(workspace, "reports", "final-report.md")))
        self.assertEqual(code, 0)
        self.assertEqual(payload["totals"]["included"], 1)
        self.assertFalse(payload["approved"])

    def test_cli_missing_workspace(self):
        with support.temp_dir() as directory:
            missing = os.path.join(directory, "nope")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = self.report.main(["--workspace", missing])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
