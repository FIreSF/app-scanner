"""Scenario resolver tests."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from tests import support


class ResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skill_mod = support.load_skill_module()
        cls.registry_mod = support.load_registry_module()
        cls.registry = cls.registry_mod.load_registry()

    def test_all_mappings_validate_against_registry(self):
        self.assertEqual(self.skill_mod.validate_mappings(), [])

    def test_every_registered_sub_agent_has_a_scenario(self):
        covered = set()
        for mapping in self.skill_mod.SCENARIO_MAPPINGS.values():
            covered.update(mapping["agents"])
        missing = set(self.registry_mod.sub_agent_ids(self.registry)) - covered
        self.assertEqual(missing, set(), f"agents without a scenario: {sorted(missing)}")

    def test_report_resolves_to_reporting_agent(self):
        result = self.skill_mod.resolve_scenario("report")
        self.assertTrue(result["matched"])
        self.assertIn("reporting", result["results"])
        self.assertEqual(result["results"]["reporting"]["agents"], ["reporting-agent"])

    def test_ssl_pinning_resolves_to_traffic(self):
        result = self.skill_mod.resolve_scenario("ssl pinning bypass")
        self.assertIn("traffic", result["results"])

    def test_deep_link_resolves_to_intent(self):
        result = self.skill_mod.resolve_scenario("deep link handling")
        self.assertIn("intent", result["results"])

    def test_masvs_resolves_to_compliance(self):
        result = self.skill_mod.resolve_scenario("masvs coverage gap")
        self.assertIn("compliance", result["results"])

    def test_multi_surface_query_returns_multiple(self):
        result = self.skill_mod.resolve_scenario("webview intent storage crypto")
        self.assertTrue({"webview", "intent", "storage", "crypto"}.issubset(result["results"]))

    def test_unknown_scenario_is_explicit(self):
        result = self.skill_mod.resolve_scenario("nonsense keyword")
        self.assertFalse(result["matched"])
        self.assertIn("default", result["results"])
        self.assertEqual(result["unmatched_tokens"], ["nonsense", "keyword"])

    def test_empty_query_is_unmatched(self):
        result = self.skill_mod.resolve_scenario("")
        self.assertFalse(result["matched"])
        self.assertEqual(result["results"], {})

    def test_cli_validate_and_list(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(self.skill_mod.main(["--validate"]), 0)
            self.assertEqual(self.skill_mod.main(["--list"]), 0)
        self.assertIn("validated", buffer.getvalue())

    def test_cli_unknown_scenario_exits_nonzero(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.skill_mod.main(["--scenario", "nonsense"]), 1)


if __name__ == "__main__":
    unittest.main()
