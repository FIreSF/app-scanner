"""Scope-gate / workspace bootstrap tests."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stdout

from tests import support


class TargetValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.preflight = support.load_preflight_module()

    def test_valid_android_package(self):
        result = self.preflight.validate_target("com.example.app")
        self.assertTrue(result["valid"])
        self.assertEqual(result["platform"], "android")

    def test_valid_ios_bundle(self):
        result = self.preflight.validate_target("com.example.app", "ios")
        self.assertTrue(result["valid"])
        self.assertEqual(result["platform"], "ios")

    def test_invalid_targets(self):
        for bad in ("", "   ", "not a package!!", "com", ".com.example", "com..example", "a" * 300):
            result = self.preflight.validate_target(bad)
            self.assertFalse(result["valid"], f"{bad!r} should be invalid")


class PreflightDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.preflight = support.load_preflight_module()

    def test_invalid_target_blocks(self):
        with support.temp_dir() as directory:
            result = self.preflight.run_preflight(
                "not a package!!", workspace=directory, allow_external_workspace=True
            )
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any("invalid target" in reason for reason in result["blocked"]))

    def test_workspace_outside_evidence_root_blocks(self):
        with support.temp_dir() as directory:
            result = self.preflight.run_preflight("com.example.app", workspace=directory)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any("outside the evidence root" in reason for reason in result["blocked"]))

    def test_allow_external_workspace_permits_bootstrap(self):
        with support.temp_dir() as directory:
            result = self.preflight.run_preflight(
                "com.example.app", workspace=directory, allow_external_workspace=True
            )
            self.assertIn(result["status"], {"READY", "DEGRADED"})
            self.assertTrue(os.path.isdir(os.path.join(directory, "notes")))

    def test_missing_artifact_blocks(self):
        with support.temp_dir() as directory:
            result = self.preflight.run_preflight(
                "com.example.app",
                workspace=directory,
                artifact=os.path.join(directory, "missing.apk"),
                allow_external_workspace=True,
            )
            self.assertEqual(result["status"], "BLOCKED")

    def test_sha256_mismatch_blocks(self):
        with support.temp_dir() as directory:
            artifact = os.path.join(directory, "app.apk")
            with open(artifact, "wb") as handle:
                handle.write(b"not a real apk")
            result = self.preflight.run_preflight(
                "com.example.app",
                workspace=directory,
                artifact=artifact,
                expect_sha256="0" * 64,
                allow_external_workspace=True,
            )
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(any("mismatch" in reason for reason in result["blocked"]))

    def test_sha256_match_is_accepted(self):
        with support.temp_dir() as directory:
            artifact = os.path.join(directory, "app.apk")
            with open(artifact, "wb") as handle:
                handle.write(b"fake apk bytes")
            expected = self.preflight.calculate_sha256(artifact)
            result = self.preflight.run_preflight(
                "com.example.app",
                workspace=directory,
                artifact=artifact,
                expect_sha256=expected,
                allow_external_workspace=True,
            )
            self.assertNotEqual(result["status"], "BLOCKED")
            self.assertEqual(result["artifact_sha256"], expected)

    def test_required_tool_missing_blocks(self):
        with support.temp_dir() as directory:
            result = self.preflight.run_preflight(
                "com.example.app",
                workspace=directory,
                require_tools=["definitely-not-a-real-tool"],
                allow_external_workspace=True,
            )
            self.assertEqual(result["status"], "BLOCKED")

    def test_workspace_scaffold_is_created(self):
        with support.temp_dir() as directory:
            result = self.preflight.run_preflight(
                "com.example.app", workspace=directory, allow_external_workspace=True
            )
            for subdir in self.preflight.SUBDIRECTORIES:
                self.assertTrue(os.path.isdir(os.path.join(directory, subdir)), subdir)
            for note in ("bootstrap.md", "MINDMAP.md", "CONTEXT_LEDGER.md", "tested-variants.md", "auth_session.md"):
                self.assertTrue(os.path.isfile(os.path.join(directory, "notes", note)), note)
            metadata = json.loads(support.read_text(os.path.join(directory, "evidence", "artifact.json")))
            self.assertEqual(metadata["target"], "com.example.app")
            self.assertEqual(metadata["workspace"], result["workspace"])

    def test_notes_are_not_overwritten(self):
        with support.temp_dir() as directory:
            self.preflight.run_preflight(
                "com.example.app", workspace=directory, allow_external_workspace=True
            )
            bootstrap = os.path.join(directory, "notes", "bootstrap.md")
            with open(bootstrap, "w", encoding="utf-8", newline="\n") as handle:
                handle.write("custom bootstrap\n")
            self.preflight.run_preflight(
                "com.example.app", workspace=directory, allow_external_workspace=True
            )
            self.assertEqual(support.read_text(bootstrap), "custom bootstrap\n")

    def test_ensure_session_opens_learning_session(self):
        with support.isolated_engine_db():
            with support.temp_dir() as directory:
                result = self.preflight.run_preflight(
                    "com.example.app",
                    workspace=directory,
                    allow_external_workspace=True,
                    ensure_session=True,
                )
                self.assertIsNotNone(result["session_id"])
                engine = support.load_engine_class()()
                self.assertIsNotNone(engine.get_session(result["session_id"]))
                bootstrap = support.read_text(os.path.join(directory, "notes", "bootstrap.md"))
                self.assertIn(result["session_id"], bootstrap)

    def test_main_exit_codes(self):
        with support.temp_dir() as directory:
            with redirect_stdout(io.StringIO()):
                blocked = self.preflight.main(
                    ["--target", "bad target!!", "--workspace", directory, "--allow-external-workspace"]
                )
            self.assertEqual(blocked, 1)

            with redirect_stdout(io.StringIO()):
                ok = self.preflight.main(
                    ["--target", "com.example.app", "--workspace", directory, "--allow-external-workspace"]
                )
            self.assertIn(ok, {0, 2})


if __name__ == "__main__":
    unittest.main()
