"""Hard FP Gate, state machine and FP database tests."""

from __future__ import annotations

import hashlib
import os
import unittest

from tests import support


class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = support.load_findings_module()

    def test_signature_hash_matches_documented_algorithm(self):
        expected = hashlib.sha256(b"MASVS-PLATFORM:identifier:signal").hexdigest()[:8]
        actual = self.findings.signature_hash("MASVS-PLATFORM", "identifier", "signal")
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 8)

    def test_state_normalisation(self):
        self.assertEqual(self.findings.normalize_state("high-confidence"), "HIGH_CONFIDENCE")
        self.assertEqual(self.findings.normalize_state("validated"), "VALIDATED")
        with self.assertRaises(ValueError):
            self.findings.normalize_state("banana")


class FalsePositiveDbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = support.load_findings_module()
        cls.db = cls.findings.FalsePositiveDB()

    def test_repository_db_parses(self):
        entries = self.db.entries()
        self.assertGreaterEqual(len(entries), 17)
        for entry in entries:
            self.assertRegex(entry["signature_hash"], r"^[0-9a-f]{8}$")
            self.assertTrue(entry["category"])
            self.assertTrue(entry["reason"])

    def test_exact_lookup(self):
        entry = self.db.lookup("3a8f1b20")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["category"], "STORAGE")

    def test_partial_hash_is_not_a_match(self):
        self.assertIsNone(self.db.lookup("3a8f"))
        self.assertIsNone(self.db.lookup("a8f1b2"))

    def test_prose_is_not_a_match(self):
        self.assertIsNone(self.db.lookup("Google API key"))

    def test_add_entry_roundtrip(self):
        with support.temp_dir() as directory:
            path = os.path.join(directory, "FALSE_POSITIVE_DB.md")
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    "# FP DB\n\n| Signature Hash | Category | Pattern Description | Reason for FP |\n"
                    "|---|---|---|---|\n"
                    "| `deadbeef` | CODE | existing row | known |\n\n"
                    "## Signature Hash Format\n\n```python\npass\n```\n"
                )
            db = self.findings.FalsePositiveDB(path)
            self.assertTrue(db.contains("deadbeef"))
            self.assertTrue(db.add("cafebabe", "PLATFORM", "new row", "verified reason"))
            self.assertTrue(db.contains("cafebabe"))
            self.assertFalse(db.add("cafebabe", "PLATFORM", "new row", "verified reason"))
            content = support.read_text(path)
            self.assertIn("## Signature Hash Format", content)
            self.assertLess(content.index("cafebabe"), content.index("## Signature Hash Format"))

    def test_add_rejects_bad_hash(self):
        db = self.findings.FalsePositiveDB()
        with self.assertRaises(ValueError):
            db.add("nothex", "CODE", "desc", "reason")

    def test_add_rejects_empty_fields(self):
        db = self.findings.FalsePositiveDB()
        with self.assertRaises(ValueError):
            db.add("deadbeef", "", "desc", "reason")


class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = support.load_findings_module()

    def _gate(self, **overrides):
        return self.findings.evaluate_gate(support.make_finding(**overrides))

    def test_complete_finding_without_user_approval_stops_at_validated(self):
        result = self._gate()
        self.assertEqual(result["verdict"], "APPROVED")
        self.assertFalse(result["reporting_gate_open"])
        self.assertEqual(result["final_state"], "VALIDATED")

    def test_complete_finding_with_user_approval_is_reportable(self):
        result = self._gate(user_approved=True)
        self.assertTrue(result["reporting_gate_open"])
        self.assertEqual(result["final_state"], "REPORTABLE")

    def test_fabricated_verification_is_rejected(self):
        result = self._gate(verification_verdict="DEMO_CONFIRMED_VALIDATED")
        self.assertIn("7_verification_agent_verdict", result["blocking_checks"])
        self.assertEqual(result["verdict"], "DOWNGRADED")

    def test_missing_poc_is_rejected(self):
        finding = support.make_finding()
        finding.pop("poc_command")
        result = self.findings.evaluate_gate(finding)
        self.assertIn("2_exploitable", result["blocking_checks"])

    def test_single_reproduction_is_rejected(self):
        result = self._gate(reproduced_count=1)
        self.assertIn("4_raw_poc_reproducible", result["blocking_checks"])

    def test_missing_cross_context_is_rejected(self):
        result = self._gate(cross_context_verified=False, cross_contexts=[])
        self.assertIn("5_cross_context", result["blocking_checks"])

    def test_placeholder_impact_is_rejected(self):
        result = self._gate(impact="TBD")
        self.assertIn("1_real_impact", result["blocking_checks"])

    def test_low_severity_without_chain_is_not_leverageable(self):
        result = self._gate(severity="Low", chain="")
        self.assertIn("3_leverageable", result["blocking_checks"])

    def test_low_severity_with_chain_is_leverageable(self):
        result = self._gate(severity="Low", chain="low -> session theft -> ATO")
        self.assertNotIn("3_leverageable", result["blocking_checks"])

    def test_known_false_positive_is_blocked(self):
        with support.temp_dir() as directory:
            path = os.path.join(directory, "fp.md")
            sig = self.findings.signature_hash("MASVS-PLATFORM", "known", "impact")
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    "| Signature Hash | Category | Pattern Description | Reason for FP |\n"
                    "|---|---|---|---|\n"
                    f"| `{sig}` | PLATFORM | known fp | public behaviour |\n"
                )
            db = self.findings.FalsePositiveDB(path)
            finding = support.make_finding(identifier="known", impact="impact")
            result = self.findings.evaluate_gate(finding, db)
            self.assertTrue(result["in_fp_db"])
            self.assertIn("6_fp_db_cleared", result["blocking_checks"])
            self.assertEqual(result["highest_supported_state"], "INFORMATIONAL")

    def test_missing_verification_evidence_file_is_rejected(self):
        result = self._gate(verification_path="verification/does-not-exist.md")
        self.assertIn("7_verification_agent_verdict", result["blocking_checks"])

    def test_missing_poc_file_is_reported(self):
        result = self._gate(poc_path="ipc/missing.sh", poc_command="")
        self.assertIn("2_exploitable", result["blocking_checks"])

    def test_highest_supported_state_progression(self):
        cases = [
            ({"impact": ""}, "OBSERVATION"),
            ({"reproduced_count": 1}, "OBSERVATION"),
            ({"effect_demonstrated": False}, "LEAD"),
            ({"poc_command": ""}, "HIGH_CONFIDENCE"),
            ({"verification_verdict": "INCONCLUSIVE"}, "CONFIRMED"),
            ({"user_approved": False}, "VALIDATED"),
            ({"user_approved": True}, "REPORTABLE"),
        ]
        for overrides, expected in cases:
            finding = support.make_finding(**overrides)
            self.assertEqual(
                self.findings.highest_supported_state(finding),
                expected,
                f"overrides={overrides}",
            )


class TransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = support.load_findings_module()

    def test_observation_to_lead_requires_two_reproductions(self):
        finding = {"state": "OBSERVATION", "reproduced_count": 1}
        result = self.findings.check_transition(finding, "LEAD")
        self.assertFalse(result["allowed"])

    def test_observation_to_lead_allowed(self):
        finding = {"state": "OBSERVATION", "reproduced_count": 2}
        result = self.findings.check_transition(finding, "LEAD")
        self.assertTrue(result["allowed"], result["reasons"])

    def test_skipping_states_is_refused(self):
        finding = {"state": "OBSERVATION", "reproduced_count": 2}
        result = self.findings.check_transition(finding, "CONFIRMED")
        self.assertFalse(result["allowed"])

    def test_confirmed_to_validated_requires_verdict(self):
        finding = support.make_finding(verification_verdict="INCONCLUSIVE")
        result = self.findings.check_transition(finding, "VALIDATED")
        self.assertFalse(result["allowed"])

    def test_confirmed_to_validated_allowed(self):
        finding = support.make_finding()
        result = self.findings.check_transition(finding, "VALIDATED")
        self.assertTrue(result["allowed"], result["reasons"])

    def test_reportable_requires_user_gate(self):
        finding = support.make_finding(state="VALIDATED")
        result = self.findings.check_transition(finding, "REPORTABLE")
        self.assertFalse(result["allowed"])
        self.assertTrue(any("user approval" in reason for reason in result["reasons"]))

    def test_reportable_allowed_after_approval(self):
        finding = support.make_finding(state="VALIDATED", user_approved=True)
        result = self.findings.check_transition(finding, "REPORTABLE")
        self.assertTrue(result["allowed"], result["reasons"])

    def test_apply_transition_returns_copy(self):
        finding = support.make_finding()
        result = self.findings.apply_transition(finding, "VALIDATED")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["finding"]["state"], "VALIDATED")
        self.assertEqual(finding["state"], "CONFIRMED")

    def test_any_state_can_be_downgraded_to_informational(self):
        for state in ("OBSERVATION", "LEAD", "HIGH_CONFIDENCE", "CONFIRMED", "VALIDATED", "REPORTABLE"):
            result = self.findings.check_transition({"state": state}, "INFORMATIONAL")
            self.assertTrue(result["allowed"], f"{state} should be downgradable")


if __name__ == "__main__":
    unittest.main()
