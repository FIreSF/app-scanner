"""Registry structure, reference and wave-planning tests."""

from __future__ import annotations

import copy
import os
import unittest

from tests import support


class RegistryValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry_mod = support.load_registry_module()
        cls.registry = cls.registry_mod.load_registry()

    def test_real_registry_is_valid(self):
        result = self.registry_mod.validate_registry(self.registry)
        self.assertEqual(result.status, "PASS", result.errors)
        self.assertGreater(result.checked, 20)

    def test_link_check_passes_for_repository(self):
        result = self.registry_mod.link_check()
        self.assertEqual(result.status, "PASS", result.errors)

    def test_indexes_are_contiguous(self):
        indexes = [agent["index"] for agent in self.registry_mod.iter_agents(self.registry)]
        self.assertEqual(indexes, list(range(len(indexes))))

    def test_unknown_dependency_is_rejected(self):
        broken = copy.deepcopy(self.registry)
        broken["agents"]["static-agent"]["depends_on"] = ["ghost-agent"]
        result = self.registry_mod.validate_registry(broken)
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any("unknown agent 'ghost-agent'" in error for error in result.errors))

    def test_dependency_cycle_is_rejected(self):
        broken = copy.deepcopy(self.registry)
        broken["agents"]["static-agent"]["depends_on"] = ["reporting-agent"]
        broken["agents"]["reporting-agent"]["depends_on"] = ["static-agent"]
        result = self.registry_mod.validate_registry(broken)
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any("cycle" in error.lower() for error in result.errors))

    def test_duplicate_index_is_rejected(self):
        broken = copy.deepcopy(self.registry)
        broken["agents"]["static-agent"]["index"] = broken["agents"]["dynamic-agent"]["index"]
        result = self.registry_mod.validate_registry(broken)
        self.assertTrue(any("Duplicate agent index" in error for error in result.errors))

    def test_missing_briefing_is_rejected(self):
        broken = copy.deepcopy(self.registry)
        broken["agents"]["static-agent"]["briefing_path"] = "runtime/opencode/agents/nope.md"
        result = self.registry_mod.validate_registry(broken)
        self.assertTrue(any("briefing is missing" in error for error in result.errors))

    def test_missing_skill_is_rejected(self):
        broken = copy.deepcopy(self.registry)
        broken["agents"]["static-agent"]["skills"] = ["skills/does-not-exist.md"]
        result = self.registry_mod.validate_registry(broken)
        self.assertTrue(any("missing skill" in error for error in result.errors))

    def test_max_concurrent_above_ceiling_is_rejected(self):
        broken = copy.deepcopy(self.registry)
        broken["agents"]["static-agent"]["max_concurrent"] = 99
        result = self.registry_mod.validate_registry(broken)
        self.assertTrue(any("exceeds the global concurrency_limit" in error for error in result.errors))

    def test_every_agent_appears_in_a_phase(self):
        phased = set()
        for _phase_id, _title, members in self.registry_mod.PHASES:
            phased.update(members)
        self.assertEqual(phased, set(self.registry_mod.sub_agent_ids(self.registry)))


class WavePlanningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry_mod = support.load_registry_module()
        cls.registry = cls.registry_mod.load_registry()

    def test_concurrency_limit_is_three(self):
        self.assertEqual(self.registry_mod.concurrency_limit(self.registry), 3)

    def test_phase_one_dispatch_is_capped(self):
        next_agents = self.registry_mod.next_dispatchable(self.registry)
        self.assertEqual(next_agents, ["static-agent", "root-device-agent", "emulator-agent"])

    def test_phase_two_requires_phase_one(self):
        completed = ["static-agent", "root-device-agent", "emulator-agent"]
        next_agents = self.registry_mod.next_dispatchable(self.registry, completed)
        self.assertIn("mcp-bug-intel-agent", next_agents)
        self.assertIn("crypto-analysis-agent", next_agents)
        self.assertNotIn("frida-script-agent", next_agents)

    def test_running_agents_consume_slots(self):
        next_agents = self.registry_mod.next_dispatchable(
            self.registry, completed=[], running=["static-agent", "root-device-agent"]
        )
        self.assertEqual(len(next_agents), 1)
        self.assertEqual(next_agents[0], "emulator-agent")

    def test_full_capacity_returns_nothing(self):
        next_agents = self.registry_mod.next_dispatchable(
            self.registry,
            running=["static-agent", "root-device-agent", "emulator-agent"],
        )
        self.assertEqual(next_agents, [])

    def test_on_demand_agents_are_excluded_by_default(self):
        next_agents = self.registry_mod.next_dispatchable(self.registry)
        for agent in ("exploitation-agent", "verification-agent", "reporting-agent"):
            self.assertNotIn(agent, next_agents)

    def test_on_demand_agents_can_be_requested(self):
        next_agents = self.registry_mod.next_dispatchable(
            self.registry, phases=["5"], include_on_demand=True
        )
        self.assertEqual(next_agents, ["exploitation-agent"])

    def test_on_demand_agents_are_hidden_even_when_phase_matches(self):
        next_agents = self.registry_mod.next_dispatchable(self.registry, phases=["5"])
        self.assertEqual(next_agents, [])

    def test_phase_filter(self):
        next_agents = self.registry_mod.next_dispatchable(self.registry, phases=["2"])
        self.assertEqual(next_agents, [])

    def test_dependency_waves_cover_every_sub_agent(self):
        waves = self.registry_mod.dependency_waves(self.registry)
        flattened = [agent for wave in waves for agent in wave]
        self.assertEqual(sorted(flattened), sorted(self.registry_mod.sub_agent_ids(self.registry)))

    def test_dependencies_always_resolve_before_dependants(self):
        waves = self.registry_mod.dependency_waves(self.registry)
        seen = set()
        for wave in waves:
            for agent in wave:
                for dependency in self.registry["agents"][agent]["depends_on"]:
                    if dependency == "orchestrator-agent":
                        continue
                    self.assertIn(dependency, seen, f"{agent} scheduled before {dependency}")
            seen.update(wave)


if __name__ == "__main__":
    unittest.main()
