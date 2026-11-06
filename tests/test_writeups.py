"""Writeup index pipeline tests (spec §11 `/update`)."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stdout

from tests import support


class WriteupIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.writeups = support.load_writeup_module()

    def _write(self, directory: str, name: str, content: str) -> str:
        path = os.path.join(directory, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        return path

    def test_front_matter_is_parsed(self):
        with support.temp_dir() as directory:
            path = self._write(
                directory,
                "processed/intent-redirection.md",
                "---\n"
                "title: Intent redirection to unexported activity\n"
                "vuln_class: platform\n"
                "source: hackerone\n"
                "tags: [android, intent, ipc]\n"
                "---\n\n# Ignored heading\n\nBody.\n",
            )
            meta = self.writeups.parse_writeup(path, root_dir=directory)
            self.assertEqual(meta["title"], "Intent redirection to unexported activity")
            self.assertEqual(meta["vuln_class"], "platform")
            self.assertEqual(meta["source"], "hackerone")
            self.assertEqual(meta["tags"], ["android", "intent", "ipc"])
            self.assertTrue(meta["has_front_matter"])
            self.assertEqual(meta["path"], "processed/intent-redirection.md")

    def test_missing_front_matter_falls_back_to_heading(self):
        with support.temp_dir() as directory:
            path = self._write(
                directory,
                "processed/no-meta.md",
                "# Backup exfiltration via adb\n\nDetails.\n",
            )
            meta = self.writeups.parse_writeup(path, root_dir=directory)
            self.assertEqual(meta["title"], "Backup exfiltration via adb")
            self.assertEqual(meta["vuln_class"], "uncategorised")
            self.assertEqual(meta["source"], "unknown")
            self.assertEqual(meta["tags"], [])
            self.assertFalse(meta["has_front_matter"])

    def test_missing_heading_falls_back_to_filename(self):
        with support.temp_dir() as directory:
            path = self._write(directory, "processed/some-case.md", "no heading here\n")
            meta = self.writeups.parse_writeup(path, root_dir=directory)
            self.assertEqual(meta["title"], "some-case")

    def test_collect_ignores_non_markdown_and_dotfiles(self):
        with support.temp_dir() as directory:
            processed = os.path.join(directory, "processed")
            raw = os.path.join(directory, "raw")
            self._write(directory, "processed/a.md", "# Alpha\n")
            self._write(directory, "processed/notes.txt", "ignore me")
            self._write(directory, "raw/.gitkeep", "")
            self._write(directory, "raw/hackerone-report.html", "<html></html>")

            data = self.writeups.collect_writeups(
                processed_dir=processed, raw_dir=raw, root_dir=directory
            )
            self.assertEqual([item["title"] for item in data["processed"]], ["Alpha"])
            self.assertEqual(data["raw"], ["raw/hackerone-report.html"])

    def test_collect_sorts_by_vuln_class_then_title(self):
        with support.temp_dir() as directory:
            self._write(directory, "processed/b.md", "---\nvuln_class: network\n---\n# Zebra\n")
            self._write(directory, "processed/a.md", "---\nvuln_class: platform\n---\n# Beta\n")
            self._write(directory, "processed/c.md", "---\nvuln_class: platform\n---\n# Alpha\n")
            data = self.writeups.collect_writeups(
                processed_dir=os.path.join(directory, "processed"),
                raw_dir=os.path.join(directory, "raw"),
                root_dir=directory,
            )
            self.assertEqual(
                [(item["vuln_class"], item["title"]) for item in data["processed"]],
                [("network", "Zebra"), ("platform", "Alpha"), ("platform", "Beta")],
            )

    def test_missing_directories_are_tolerated(self):
        with support.temp_dir() as directory:
            data = self.writeups.collect_writeups(
                processed_dir=os.path.join(directory, "nope"),
                raw_dir=os.path.join(directory, "also-nope"),
                root_dir=directory,
            )
            self.assertEqual(data, {"processed": [], "raw": []})

    def test_render_index_lists_rows_and_raw_pending(self):
        data = {
            "processed": [
                {
                    "path": "processed/a.md",
                    "title": "Intent redirection",
                    "vuln_class": "platform",
                    "source": "hackerone",
                    "tags": [],
                    "has_front_matter": True,
                }
            ],
            "raw": ["raw/pending.html"],
        }
        rendered = self.writeups.render_index(data)
        self.assertIn("**Processed writeups:** 1", rendered)
        self.assertIn("| Intent redirection | platform | hackerone | `processed/a.md` |", rendered)
        self.assertIn("## Pending raw material", rendered)
        self.assertIn("- `raw/pending.html`", rendered)

    def test_render_index_empty_state(self):
        rendered = self.writeups.render_index({"processed": [], "raw": []})
        self.assertIn("_No processed writeups yet.", rendered)
        self.assertNotIn("## Pending raw material", rendered)

    def test_write_index_creates_parent_directory(self):
        with support.temp_dir() as directory:
            target = os.path.join(directory, "nested", "index.md")
            self.writeups.write_index({"processed": [], "raw": []}, target)
            self.assertTrue(os.path.isfile(target))
            self.assertIn("# Writeup Index", support.read_text(target))

    def test_cli_json_mode(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = self.writeups.main(["--json"])
        self.assertEqual(code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(set(payload), {"processed", "raw"})

    def test_repository_index_is_up_to_date(self):
        """The committed writeups/index.md must match a fresh render."""
        data = self.writeups.collect_writeups()
        expected = self.writeups.render_index(data)
        self.assertEqual(
            self.writeups.read_text(self.writeups.INDEX_PATH),
            expected,
            "writeups/index.md is stale; run: python scripts/writeup_index.py",
        )

    def test_registry_requires_writeup_assets(self):
        registry = support.load_registry_module()
        self.assertIn("scripts/writeup_index.py", registry.CORE_REQUIRED_FILES)
        self.assertIn("writeups/index.md", registry.CORE_REQUIRED_FILES)
        self.assertIn("writeups/README.md", registry.CORE_REQUIRED_FILES)


if __name__ == "__main__":
    unittest.main()
