"""Reconciliation of workspace findings with the learning engine (`findings`)."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stdout

from learning_engine.engine import LearningEngine
from tests import support


class FindingsSyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = support.load_runner_module()

    def _run(self, argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = self.runner.main(argv)
        return code, buffer.getvalue()

    def _temp_workspace(self):
        holder = support.temp_dir()
        directory = holder.__enter__()
        self.addCleanup(holder.__exit__, None, None, None)
        return directory

    def _workspace_with(self, payload):
        directory = self._temp_workspace()
        findings_dir = os.path.join(directory, "findings")
        os.makedirs(findings_dir, exist_ok=True)
        with open(
            os.path.join(findings_dir, f"{payload['id']}.json"), "w", encoding="utf-8"
        ) as handle:
            json.dump(payload, handle, indent=2)
        return directory

    def _engine(self):
        engine = LearningEngine()
        self.addCleanup(engine.close)
        return engine

    # ------------------------------------------------------------------ #
    def test_dry_run_reports_the_plan_and_writes_nothing(self):
        with support.isolated_engine_db():
            directory = self._workspace_with(support.make_finding(id="FIND-0001"))
            code, output = self._run(
                ["findings", "--target", "com.example.findsync", "--workspace", directory, "--json"]
            )
            self.assertEqual(code, 0)
            payload = json.loads(output)
            self.assertTrue(payload["dry_run"])
            self.assertEqual(payload["counts"], {"record": 1})
            self.assertEqual(self._engine().list_findings(), [])

    def test_apply_records_the_finding_under_its_workspace_id(self):
        with support.isolated_engine_db():
            directory = self._workspace_with(support.make_finding(id="FIND-0001"))
            args = ["findings", "--target", "com.example.findsync", "--workspace", directory]
            code, _ = self._run(args + ["--apply", "--json"])
            self.assertEqual(code, 0)

            rows = json.loads(self._run(args + ["--json"])[1])
            self.assertEqual(rows["counts"], {"in-sync": 1})

            stored = self._engine().get_finding("FIND-0001")
            self.assertIsNotNone(stored, "the workspace id must be preserved")
            # The stored state is the recomputed gate state, not a claim.
            self.assertEqual(stored["state"], rows["rows"][0]["gate_state"])

    def test_declared_reportable_that_fails_the_gate_is_never_stored_as_reportable(self):
        with support.isolated_engine_db():
            finding = support.make_finding(
                id="FIND-0002",
                state="REPORTABLE",
                verification_verdict="INCONCLUSIVE",
                cross_context_verified=False,
            )
            directory = self._workspace_with(finding)
            code, _ = self._run(
                [
                    "findings",
                    "--target",
                    "com.example.findsync",
                    "--workspace",
                    directory,
                    "--apply",
                    "--json",
                ]
            )
            self.assertEqual(code, 0)
            stored = self._engine().get_finding("FIND-0002")
            self.assertIsNotNone(stored)
            self.assertNotEqual(stored["state"], "REPORTABLE")

    def test_state_drift_between_engine_and_gate_is_reported_then_updated(self):
        with support.isolated_engine_db():
            directory = self._workspace_with(support.make_finding(id="FIND-0003"))
            args = ["findings", "--target", "com.example.findsync", "--workspace", directory]
            self.assertEqual(self._run(args + ["--apply"])[0], 0)

            self._engine().set_finding_state("FIND-0003", "OBSERVATION", verified=False)

            code, output = self._run(args)
            self.assertEqual(code, 0)
            self.assertIn("would update", output)
            expected = json.loads(self._run(args + ["--json"])[1])["rows"][0]["gate_state"]

            self.assertEqual(self._run(args + ["--apply"])[0], 0)
            refreshed = self._engine().get_finding("FIND-0003")
            self.assertEqual(refreshed["state"], expected)
            self.assertNotEqual(refreshed["state"], "OBSERVATION")

    def test_finding_without_an_id_is_an_error_and_fails_the_command(self):
        with support.isolated_engine_db():
            directory = self._temp_workspace()
            os.makedirs(os.path.join(directory, "findings"), exist_ok=True)
            payload = support.make_finding()
            payload.pop("state", None)
            with open(
                os.path.join(directory, "findings", "orphan.json"), "w", encoding="utf-8"
            ) as handle:
                json.dump(payload, handle)

            code, output = self._run(
                ["findings", "--target", "com.example.noid", "--workspace", directory, "--json"]
            )
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output)["counts"], {"error": 1})

    def test_finding_id_is_derived_from_the_evidence_filename(self):
        with support.isolated_engine_db():
            directory = self._temp_workspace()
            os.makedirs(os.path.join(directory, "findings"), exist_ok=True)
            payload = support.make_finding()
            payload.pop("state", None)  # legacy evidence file: no id field
            with open(
                os.path.join(directory, "findings", "FIND-0009.json"), "w", encoding="utf-8"
            ) as handle:
                json.dump(payload, handle)

            args = ["findings", "--target", "com.example.legacy", "--workspace", directory]
            code, output = self._run(args + ["--json"])
            self.assertEqual(code, 0)
            payload_out = json.loads(output)
            self.assertEqual(payload_out["rows"][0]["finding_id"], "FIND-0009")
            self.assertEqual(payload_out["counts"], {"record": 1})

            self.assertEqual(self._run(args + ["--apply"])[0], 0)
            self.assertIsNotNone(self._engine().get_finding("FIND-0009"))

    def test_same_finding_id_in_two_targets_never_overwrites(self):
        """Every engagement reuses FIND-0001; the memory must keep them apart."""
        with support.isolated_engine_db():
            first = self._workspace_with(support.make_finding(id="FIND-0001"))
            second = self._workspace_with(support.make_finding(id="FIND-0001"))

            args_first = [
                "findings",
                "--target",
                "com.example.first",
                "--workspace",
                first,
                "--apply",
            ]
            args_second = [
                "findings",
                "--target",
                "com.example.second",
                "--workspace",
                second,
                "--apply",
            ]
            self.assertEqual(self._run(args_first)[0], 0)
            self.assertEqual(self._run(args_second)[0], 0)

            engine = self._engine()
            rows_first = engine.list_findings(target="com.example.first")
            rows_second = engine.list_findings(target="com.example.second")
            self.assertEqual(len(rows_first), 1)
            self.assertEqual(len(rows_second), 1)
            self.assertEqual(rows_first[0]["target_package"], "com.example.first")
            self.assertEqual(rows_second[0]["target_package"], "com.example.second")
            self.assertNotEqual(rows_first[0]["finding_id"], rows_second[0]["finding_id"])
            # The second target was stored under a scoped id, never on top of
            # the first target's row.
            self.assertTrue(rows_second[0]["finding_id"].startswith("com.example.second#"))

            # Both must now be stable: a second run finds them in sync.
            self.assertEqual(self._run(args_first + ["--json"])[0], 0)
            payload_first = json.loads(self._run(args_first + ["--json"])[1])
            payload_second = json.loads(self._run(args_second + ["--json"])[1])
            self.assertEqual(payload_first["counts"], {"in-sync": 1})
            self.assertEqual(payload_second["counts"], {"in-sync": 1})

    def test_missing_findings_directory_reports_an_error(self):
        with support.isolated_engine_db():
            directory = self._temp_workspace()
            code, output = self._run(
                ["findings", "--target", "com.example.empty", "--workspace", directory, "--json"]
            )
            self.assertEqual(code, 1)
            self.assertIn("error", json.loads(output))


class PersistFindingIdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = support.load_runner_module()

    def test_persist_finding_keeps_the_workspace_finding_id(self):
        with support.isolated_engine_db():
            holder = support.temp_dir()
            directory = holder.__enter__()
            self.addCleanup(holder.__exit__, None, None, None)
            orchestrator = self.runner.Orchestrator(
                target_package="com.example.persistid", workspace=directory
            )
            self.addCleanup(orchestrator.engine.close)
            finding = support.make_finding(id="FIND-0007")
            gate = orchestrator.evaluate_finding(finding)
            persisted = orchestrator.persist_finding(finding, gate)
            self.assertEqual(persisted, "FIND-0007")
            self.assertIsNotNone(orchestrator.engine.get_finding("FIND-0007"))


if __name__ == "__main__":
    unittest.main()
