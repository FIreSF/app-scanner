# MASVS-AUTH CHECKLIST (memory/targets/auth.md)

1. [ ] Test biometric authentication flows: check if biometric check is client-side only (can be bypassed via Frida hook on `BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded`).
2. [ ] Verify token storage: ensure refresh/access tokens are stored in EncryptedSharedPreferences / Android Keystore.
3. [ ] Audit session termination: verify logout invalidates tokens server-side.
4. [ ] Replay attacks: verify API requests cannot be replayed without nonce/timestamp validation.
5. [ ] OAuth / SSO redirect interception: ensure custom scheme redirects validate state parameters and exact client IDs.
