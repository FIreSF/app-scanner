"""OpenCode runtime wiring: generated agents, project config, skill discovery."""

from __future__ import annotations

import json
import os
import re
import unittest

from scripts import sync_agent_runtime
from tests import support

FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)


def _frontmatter(path: str) -> dict:
    text = support.read_text(path)
    match = FRONTMATTER_RE.match(text)
    if not match:
        return {}
    fields = {}
    for line in match.group(1).splitlines():
        if line.startswith((" ", "-")) or ":" not in line:
            continue  # nested list item, e.g. a permission rule
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip().strip('"')
    return fields


def _permission_rules(path: str) -> list:
    rules = []
    text = support.read_text(path)
    in_permissions = False
    current = None
    for line in text.splitlines():
        if line.startswith("permissions:"):
            in_permissions = True
            continue
        if not in_permissions:
            continue
        if line.startswith("  - action:"):
            current = {"action": line.split(":", 1)[1].strip()}
            rules.append(current)
        elif current is not None and line.strip().startswith(("resource:", "effect:")):
            key, value = line.strip().split(":", 1)
            current[key] = value.strip().strip('"')
        elif line and not line.startswith((" ", "-")):
            break
    return rules


class GeneratedAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = sync_agent_runtime.build_expected(sync_agent_runtime.DEFAULT_DEST)
        cls.registry = sync_agent_runtime.load_registry()
        cls.agents_dir = os.path.join(sync_agent_runtime.DEFAULT_DEST, "agents")

    def test_every_registered_agent_has_a_generated_file_in_sync(self):
        stale = []
        for path, content in self.expected.items():
            self.assertTrue(os.path.isfile(path), f"missing managed file: {path}")
            if support.read_text(path) != content:
                stale.append(os.path.relpath(path, sync_agent_runtime.ROOT_DIR))
        self.assertEqual(stale, [], "run scripts/sync_agent_runtime.py to refresh")

    def test_generated_file_names_match_the_registry_roster(self):
        expected_names = {f"{agent_id}.md" for agent_id in self.registry["agents"]}
        actual_names = {name for name in os.listdir(self.agents_dir) if name.endswith(".md")}
        self.assertEqual(actual_names, expected_names)

    def test_sub_agents_are_subagents_and_cannot_spawn(self):
        for agent_id in self.registry["agents"]:
            if agent_id == sync_agent_runtime.ORCHESTRATOR_ID:
                continue
            path = os.path.join(self.agents_dir, f"{agent_id}.md")
            fields = _frontmatter(path)
            self.assertEqual(fields.get("mode"), "subagent", agent_id)
            rules = _permission_rules(path)
            self.assertTrue(
                any(
                    rule.get("action") == "subagent"
                    and rule.get("resource") == "*"
                    and rule.get("effect") == "deny"
                    for rule in rules
                ),
                f"{agent_id} must not spawn sub-agents (AGENTS.md 2.6)",
            )

    def test_orchestrator_is_primary_with_a_dispatch_allow_list(self):
        path = os.path.join(self.agents_dir, f"{sync_agent_runtime.ORCHESTRATOR_ID}.md")
        fields = _frontmatter(path)
        self.assertEqual(fields.get("mode"), "primary")
        rules = _permission_rules(path)
        allowed = {
            rule.get("resource")
            for rule in rules
            if rule.get("action") == "subagent" and rule.get("effect") == "allow"
        }
        roster = set(self.registry["agents"]) - {sync_agent_runtime.ORCHESTRATOR_ID}
        self.assertEqual(allowed, roster)
        self.assertEqual(rules[-1].get("resource"), "*")
        self.assertEqual(rules[-1].get("effect"), "deny")

    def test_descriptions_are_present_and_specific(self):
        for agent_id in self.registry["agents"]:
            path = os.path.join(self.agents_dir, f"{agent_id}.md")
            description = _frontmatter(path).get("description", "")
            self.assertGreater(len(description), 30, agent_id)
            self.assertNotIn("\n", description, agent_id)

    def test_check_mode_reports_a_clean_tree(self):
        self.assertEqual(sync_agent_runtime.main(["--check"]), 0)


class ProjectConfigTests(unittest.TestCase):
    def test_config_declares_skills_directory_and_bug_intel_mcp_server(self):
        path = os.path.join(sync_agent_runtime.DEFAULT_DEST, "opencode.json")
        config = json.loads(support.read_text(path))
        self.assertEqual(config["$schema"], sync_agent_runtime.SCHEMA_URL)
        self.assertIn("./skills", config["skills"])
        server = config["mcp"]["servers"][sync_agent_runtime.MCP_SERVER_ID]
        self.assertEqual(server["type"], "local")
        self.assertTrue(server["command"])
        self.assertTrue(
            os.path.isfile(os.path.join(sync_agent_runtime.ROOT_DIR, "scripts", "mcp_intel_server.py")),
            "mcp_intel_server.py is the command target and must exist",
        )

    def test_mcp_command_starts_with_an_interpreter(self):
        command = sync_agent_runtime.DEFAULT_MCP_COMMAND.split()
        self.assertGreaterEqual(len(command), 2)
        self.assertTrue(os.path.isfile(os.path.join(sync_agent_runtime.ROOT_DIR, command[1])))


class SkillDiscoveryTests(unittest.TestCase):
    def test_flat_skills_carry_a_discoverable_description(self):
        skills_dir = os.path.join(support.ROOT_DIR, "skills")
        names = [name for name in os.listdir(skills_dir) if name.endswith(".md")]
        self.assertGreaterEqual(len(names), 29)
        for name in names:
            path = os.path.join(skills_dir, name)
            fields = _frontmatter(path)
            description = fields.get("description", "")
            self.assertTrue(description, f"{name} has no description frontmatter")
            self.assertGreater(len(description), 30, name)
            self.assertTrue(fields.get("name"), f"{name} has no name frontmatter")

    def test_nested_skills_carry_a_description(self):
        root = os.path.join(support.ROOT_DIR, ".agents", "skills")
        found = []
        for current, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            if "SKILL.md" in files:
                found.append(os.path.join(current, "SKILL.md"))
        self.assertTrue(found)
        for path in found:
            fields = _frontmatter(path)
            self.assertTrue(
                fields.get("description"), f"{path} needs a description to be advertised"
            )


if __name__ == "__main__":
    unittest.main()
