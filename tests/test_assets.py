"""Asset integrity tests: documentation, JSON and instrumentation templates."""

from __future__ import annotations

import json
import os
import re
import unittest

from tests import support

TEXT_SUFFIXES = {".md", ".py", ".js", ".sql", ".json"}


def _walk(root: str):
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", "testing"}]
        for name in files:
            yield os.path.join(current, name)


class AssetIntegrityTests(unittest.TestCase):
    def test_text_files_are_valid_utf8_without_replacement_characters(self):
        offenders = []
        for path in _walk(support.ROOT_DIR):
            if os.path.splitext(path)[1].lower() not in TEXT_SUFFIXES:
                continue
            with open(path, "rb") as handle:
                raw = handle.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                offenders.append(f"{path}: {exc}")
                continue
            if "\ufffd" in text:
                offenders.append(f"{path}: contains U+FFFD replacement character")
            if path.endswith((".md", ".py", ".js", ".sql")) and not text.strip():
                offenders.append(f"{path}: file is empty")
        self.assertEqual(offenders, [])

    def test_all_json_files_parse(self):
        for path in _walk(support.ROOT_DIR):
            if path.endswith(".json"):
                with open(path, "r", encoding="utf-8") as handle:
                    json.load(handle)  # raises on malformed JSON

    def test_every_agent_briefing_has_an_output_contract(self):
        agents_dir = os.path.join(support.ROOT_DIR, "runtime", "opencode", "agents")
        briefings = [name for name in os.listdir(agents_dir) if name.endswith(".md")]
        self.assertEqual(len(briefings), 17)
        for name in briefings:
            text = support.read_text(os.path.join(agents_dir, name))
            self.assertIn("Output Contract", text, name)
            self.assertIn("**Class:**", text, name)

    def test_frida_templates_have_markers_and_balanced_braces(self):
        templates = os.path.join(support.ROOT_DIR, "templates", "frida")
        files = sorted(name for name in os.listdir(templates) if name.endswith(".js"))
        self.assertGreaterEqual(len(files), 6)
        for name in files:
            text = support.read_text(os.path.join(templates, name))
            self.assertIn("console.log", text, name)
            self.assertEqual(text.count("{"), text.count("}"), f"unbalanced braces in {name}")
            self.assertIn("FRIDA", text, f"missing FRIDA marker in {name}")

    def test_scripts_have_no_placeholder_markers(self):
        scripts_dir = os.path.join(support.ROOT_DIR, "scripts")
        for name in os.listdir(scripts_dir):
            if not name.endswith(".py"):
                continue
            text = support.read_text(os.path.join(scripts_dir, name))
            for marker in ("TODO", "FIXME", "XXX"):
                self.assertNotIn(marker, text, f"{name} contains {marker}")

    def test_readme_references_existing_scripts(self):
        readme = support.read_text(os.path.join(support.ROOT_DIR, "README.md"))
        referenced = set(re.findall(r"scripts/([A-Za-z0-9_]+\.py)", readme))
        self.assertTrue(referenced)
        for name in referenced:
            self.assertTrue(
                os.path.isfile(os.path.join(support.ROOT_DIR, "scripts", name)),
                f"README references missing scripts/{name}",
            )

    def test_documented_skill_paths_exist(self):
        registry = json.loads(support.read_text(os.path.join(support.ROOT_DIR, "runtime", "registry.json")))
        for agent in registry["agents"].values():
            for skill in agent["skills"]:
                self.assertTrue(
                    os.path.isfile(os.path.join(support.ROOT_DIR, skill)),
                    f"{agent['id']} references missing {skill}",
                )


if __name__ == "__main__":
    unittest.main()
