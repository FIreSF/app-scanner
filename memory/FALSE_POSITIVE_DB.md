# FALSE POSITIVE SIGNATURE DATABASE (memory/FALSE_POSITIVE_DB.md)
**Standard:** Bug Bounty Quality Assurance | The 7-Question Hard FP Gate  
**Rule:** Before promoting an OBSERVATION to LEAD or CONFIRMED, compute the signature hash:
`SHA256(category:identifier:signal_substring)[:8]`
If a match is found in this database, automatically downgrade the finding to INFORMATIONAL.

| Signature Hash | Category | Pattern Description | Reason for FP |
|---|---|---|---|
| `3a8f1b20` | STORAGE | Plaintext Google API key in strings.xml | Client-side Maps/Places keys are public by design; restricted by package signature. |
| `8b2c4e11` | STORAGE | Firebase URL in AndroidManifest / strings | Firebase RTDB URLs are client-public; security depends on Firebase Rules, not URL secrecy. |
| `e12d90a4` | CODE | Hardcoded AWS ARN with public Cognito identity pool | Cognito Identity Pools are meant to be embedded in apps; authenticated via IAM roles. |
| `7f41c9b3` | PLATFORM | Exported Activity with `android.intent.action.MAIN` | Launch activities must be exported to be invoked by the OS launcher. |
| `d50284e9` | RESILIENCE | RootBeer check bypassed in emulator | Emulators inherently report root indicators; does not prove bypass on physical target. |
| `14f6b2aa` | NETWORK | Insecure HTTP connection during captive portal check | OS/Library captive portal and connectivity checks (`clients3.google.com/generate_204`) use plain HTTP intentionally. |
| `9c1e7a08` | CRYPTO | MD5 used for file cache key hashing | MD5 utilized exclusively as a cache key generation hash; not used for authentication or cryptography. |
| `f2098b1a` | IPC | Exported FileProvider with `grantUriPermissions="true"` | Expected behavior for sharing selected files to camera/gallery; not vulnerable unless root path `.` is exported. |
| `6b432a18` | PLATFORM | Deep link scheme with internal router redirecting to 404 | Schema exists but target component or endpoint has been deprecated/disabled. |
| `a4c9812e` | STORAGE | Crashlytics / Sentry / Bugsnag Client DSN in strings | Telemetry and crash reporting DSN keys are client-facing write-only ingest keys. |
| `2b7e1516` | CODE | CVE version match in unreferenced third-party library | Library bundled but target vulnerable class/method is never loaded, called, or reachable (dead code). |
| `c8310f54` | PLATFORM | Intent extra parsed with strict ComponentName whitelist | Target Intent is validated against an explicit whitelist of allowed internal classes before launching. |
| `5e91a073` | AUTH | Biometric callback hooked on client with CryptoObject | Client callback can be spoofed, but Keystore CryptoObject remains locked in hardware TEE, blocking backend decryption. |
| `10da8e44` | NETWORK | Absence of SSL Certificate Pinning on mobile client | Defense-in-depth client control; does not constitute an exploitable server-side vulnerability by external attackers. |
| `47fa32c1` | STORAGE | `android:allowBackup="true"` without sensitive backup extraction | `allowBackup` is enabled, but sensitive credentials, keys, and tokens are explicitly excluded in backup_rules.xml. |
| `98b42e77` | STORAGE | Unencrypted SQLite database readable by root on test device | All sandboxes are accessible to root; only valid if an unprivileged third-party app or provider can extract it. |
| `62d19f05` | CODE | Obfuscation disabled / ProGuard inactive in debug build | Expected behavior during debug development builds; invalid against production release APK. |

## Signature Hash Format
```python
import hashlib
sig = hashlib.sha256(f"{category}:{identifier}:{signal}".encode()).hexdigest()[:8]
```
