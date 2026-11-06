# Writeups

Source material used for similar-case expansion (spec §11 `/update`).

```
writeups/raw/        fetched, untouched source material (HTML, PDF, screenshots, notes)
writeups/processed/  normalised markdown, one file per writeup
writeups/index.md    generated table of contents consumed by orchestrator-agent
```

Rules:

1. Never edit files in `raw/` — keep the original for provenance.
2. Process raw material into `processed/<vuln_class>-<short-slug>.md`.
3. Optional YAML front matter (flat keys, inline lists only):

   ```markdown
   ---
   title: Intent redirection to unexported activity
   vuln_class: platform
   source: hackerone
   tags: [android, intent, ipc]
   ---
   ```

   Without front matter the first `# heading` becomes the title and the
   writeup is filed as `uncategorised`.
4. Rebuild the index after every batch:

   ```bash
   python scripts/writeup_index.py           # regenerate index.md
   python scripts/writeup_index.py --check   # CI-style freshness check
   python scripts/writeup_index.py --json    # machine-readable metadata
   ```

`writeups/index.md` is generated — edit the processed writeups, not the index.
