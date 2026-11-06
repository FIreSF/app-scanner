# MASVS-NETWORK CHECKLIST (memory/targets/network.md)

1. [ ] Cleartext traffic: verify `android:usesCleartextTraffic="false"` in AndroidManifest and `NSAppTransportSecurity` in iOS Info.plist.
2. [ ] Network Security Config: inspect `res/xml/network_security_config.xml` for custom trust anchors or debug overrides.
3. [ ] SSL Certificate Pinning: test if app implements pinning (e.g., OkHttp CertificatePinner, TrustKit, native).
4. [ ] Pinning Bypass Validation: verify if generic Frida pinning bypass scripts disable verification.
5. [ ] Mixed content & HTTP redirects: verify no fallback to plain HTTP upon TLS error.
