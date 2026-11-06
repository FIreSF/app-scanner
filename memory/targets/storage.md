# MASVS-STORAGE CHECKLIST (memory/targets/storage.md)

1. [ ] Check `shared_prefs/` for plaintext auth tokens, user passwords, or API keys.
2. [ ] Dump SQLite/Realm databases: check for unencrypted PII, credit cards, chat logs.
3. [ ] Check cache directory and internal files (`/data/data/<pkg>/files/`).
4. [ ] Inspect `AndroidManifest.xml` for `android:allowBackup="true"`. Test backup with `adb backup`.
5. [ ] Check external storage usage: are sensitive files written to `/sdcard/` or external cache?
6. [ ] Clipboard security: does copying sensitive input leave data in the system clipboard?
7. [ ] Screenshot caching: does the application disable screenshot caching on sensitive screens (`FLAG_SECURE`)?
