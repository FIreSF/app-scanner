"""MASVS coverage matrix tests."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stdout

from tests import support


class CoverageMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.coverage = support.load_coverage_module()

    def test_control_catalog_is_complete(self):
        ids = [control["id"] for control in self.coverage.MASVS_CONTROLS]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 23)
        for group in self.coverage.GROUP_ORDER:
            self.assertTrue(any(control["group"] == group for control in self.coverage.MASVS_CONTROLS))

    def test_empty_workspace_reports_no_coverage(self):
        with support.temp_dir() as directory:
            matrix = self.coverage.build_matrix(directory)
            self.assertEqual(matrix["totals"]["tested"], 0)
            self.assertEqual(matrix["totals"]["not_tested"], 23)
            self.assertEqual(len(matrix["gaps"]), 23)

    def test_expected_artifact_marks_control_tested(self):
        with support.temp_dir() as directory:
            static_dir = os.path.join(directory, "static")
            os.makedirs(static_dir)
            support.write_json(os.path.join(static_dir, "library-inventory.json"), {"libs": []})
            matrix = self.coverage.build_matrix(directory)
            by_id = {row["id"]: row for row in matrix["controls"]}
            self.assertEqual(by_id["MASVS-CODE-4"]["status"], "not-tested")  # intel dir, not static
            support.write_json(os.path.join(directory, "intel", "cve-matches.json"), {"matches": []})
            matrix = self.coverage.build_matrix(directory)
            by_id = {row["id"]: row for row in matrix["controls"]}
            self.assertEqual(by_id["MASVS-CODE-4"]["status"], "tested")
            self.assertIn("cve-matches.json", by_id["MASVS-CODE-4"]["evidence"])

    def test_unexpected_file_marks_partial(self):
        with support.temp_dir() as directory:
            storage_dir = os.path.join(directory, "storage")
            os.makedirs(storage_dir)
            with open(os.path.join(storage_dir, "raw-dump.bin"), "wb") as handle:
                handle.write(b"\x00\x01")
            matrix = self.coverage.build_matrix(directory)
            by_id = {row["id"]: row for row in matrix["controls"]}
            self.assertEqual(by_id["MASVS-STORAGE-1"]["status"], "partial")
            # STORAGE-1, STORAGE-2 and PRIVACY-1 all read the storage directory.
            self.assertEqual(matrix["totals"]["partial"], 3)

    def test_reports_are_written(self):
        with support.temp_dir() as directory:
            matrix = self.coverage.build_matrix(directory)
            paths = self.coverage.write_reports(matrix, "com.example.app")
            coverage_text = support.read_text(paths["coverage"])
            gap_text = support.read_text(paths["gaps"])
            self.assertIn("MASVS v2.0 Coverage Matrix", coverage_text)
            self.assertIn("com.example.app", coverage_text)
            self.assertIn("MASVS Gap List", gap_text)
            self.assertIn("MASVS-STORAGE-1", gap_text)

    def test_cli_json_output(self):
        with support.temp_dir() as directory:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = self.coverage.main(["--workspace", directory, "--json", "--no-write"])
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["totals"]["total"], 23)

    def test_cli_missing_workspace(self):
        with support.temp_dir() as directory:
            missing = os.path.join(directory, "nope")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(self.coverage.main(["--workspace", missing, "--no-write"]), 1)


if __name__ == "__main__":
    unittest.main()
