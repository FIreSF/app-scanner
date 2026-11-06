"""Attack-surface mindmap builder tests (spec §6 Phase 9, §7)."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from tests import support


class MindmapBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mindmap = support.load_mindmap_module()

    def _workspace(self, directory: str, target: str = "com.example.app") -> str:
        support.write_json(
            os.path.join(directory, "evidence", "artifact.json"),
            {
                "target": target,
                "platform": "android",
                "artifact_sha256": "a" * 64,
                "session_id": "sess_test",
            },
        )
        os.makedirs(os.path.join(directory, "findings"), exist_ok=True)
        return directory

    def _write(self, path: str, content: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)

    def test_empty_workspace_still_renders(self):
        with support.temp_dir() as directory:
            data = self.mindmap.build_mindmap(directory, "com.example.app")
            markdown = self.mindmap.render_markdown(data)
        self.assertEqual(data["totals"]["findings"], 0)
        self.assertIn("graph TD", markdown)
        self.assertIn("No evidence or findings yet", markdown)
        self.assertIn("com.example.app", markdown)

    def test_evidence_counts_and_groups(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            self._write(os.path.join(workspace, "static", "manifest.json"), "{}")
            self._write(os.path.join(workspace, "traffic", "api-map.json"), "{}")
            data = self.mindmap.build_mindmap(workspace)
        surfaces = {row["dir"]: row for row in data["surfaces"]}
        self.assertEqual(surfaces["static"]["evidence_count"], 1)
        self.assertEqual(surfaces["traffic"]["evidence_count"], 1)
        self.assertEqual(surfaces["storage"]["evidence_count"], 0)
        groups = {row["group"]: row for row in data["groups"]}
        self.assertEqual(groups["CODE"]["evidence_count"], 1)
        self.assertEqual(groups["NETWORK"]["evidence_count"], 1)

    def test_findings_are_sorted_by_lifecycle_then_severity(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            support.write_json(
                os.path.join(workspace, "findings", "low.json"),
                {"title": "Low lead", "severity": "Low", "state": "LEAD", "masvs_category": "MASVS-CODE"},
            )
            support.write_json(
                os.path.join(workspace, "findings", "high.json"),
                {"title": "High validated", "severity": "High", "state": "VALIDATED", "masvs_category": "MASVS-PLATFORM"},
            )
            data = self.mindmap.build_mindmap(workspace)
        self.assertEqual(data["findings"][0]["title"], "High validated")
        self.assertEqual(data["findings"][0]["group"], "PLATFORM")
        self.assertEqual(data["totals"]["state_counts"]["VALIDATED"], 1)

    def test_markdown_escapes_mermaid_quotes_and_table_pipes(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            support.write_json(
                os.path.join(workspace, "findings", "one.json"),
                {
                    "title": 'Quote "and" pipe | inside',
                    "severity": "High",
                    "state": "CONFIRMED",
                    "masvs_category": "MASVS-PLATFORM",
                },
            )
            markdown = self.mindmap.render_markdown(self.mindmap.build_mindmap(workspace))
        mermaid = markdown.split("```mermaid", 1)[1].split("```", 1)[0]
        self.assertNotIn('"and"', mermaid)
        self.assertIn("Quote 'and' pipe", mermaid)
        self.assertIn("\\| inside", markdown)

    def test_write_and_check(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            data = self.mindmap.build_mindmap(workspace)
            path = self.mindmap.write_mindmap(data)
            self.assertTrue(os.path.isfile(path))

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = self.mindmap.main(["--workspace", workspace, "--check"])
            self.assertEqual(code, 0)
            self.assertIn("up to date", buffer.getvalue())

            self._write(os.path.join(workspace, "static", "new.json"), "{}")
            with redirect_stdout(io.StringIO()):
                stale_code = self.mindmap.main(["--workspace", workspace, "--check"])
            self.assertEqual(stale_code, 1)

    def test_cli_json_and_no_write(self):
        with support.temp_dir() as directory:
            workspace = self._workspace(directory)
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = self.mindmap.main(["--workspace", workspace, "--json", "--no-write"])
            payload = json.loads(buffer.getvalue())
            self.assertFalse(os.path.exists(os.path.join(workspace, "notes", "MINDMAP.md")))
        self.assertEqual(code, 0)
        self.assertEqual(payload["target"], "com.example.app")

    def test_cli_missing_workspace(self):
        with support.temp_dir() as directory:
            missing = os.path.join(directory, "nope")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = self.mindmap.main(["--workspace", missing])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
