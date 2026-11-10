# ASTER Guard — security model (0.2.0)

## Asset and scope
The app reads metadata Android exposes through PackageManager and ConnectivityManager, and, with user consent, NetworkStatsManager. It never exfiltrates these data. It can hash another application's base APK if that path is readable.

## Threat signals (not verdicts)
Scores are intentionally transparent. They flag some combinations of package **capabilities**; they do not establish intent. Scanner checks requested permissions and separate granted permissions; special permissions (overlay, accessibility, admin) can be merely declared, not activated. System apps are currently bypassed by heuristic weighting, so they are **not** considered trusted or verified.

## Sources of false negatives
Malicious code can run with apparently harmless permissions; dynamic loading, reflection, split APKs, app sandbox restrictions, patched system builds, root-level changes and short-lived behavior may not be visible. Without curated indicators and behavioral telemetry this project has low coverage compared with established products.

## Sources of false positives
Accessibility tools, device management, MDM, launchers, automation and legitimate older applications can look suspicious. App signatures may change legitimately through signing certificate rotation. A negative scan is not a safety guarantee; a positive score is not an instruction to uninstall.

## Network capabilities
The app shows current OS network metadata and historical byte counters for per-UID usage. It does **not** observe domains, packets, app URLs, requests, TLS plaintext, certificates used by other apps, or exact peer attribution. Network stats may include VPN overhead or unavailable data.

## Why no embedded CA or HTTPS MITM
An embedded CA is not automatically trusted by modern Android applications. Even a user-installed CA is often not trusted for apps targeting modern Android, and certificate pinning stops many interceptions. Automatically lowering device TLS trust creates severe security risk, especially for a security app. Any future opt-in TLS inspection would need a clearly bounded, reviewable threat model and explicit per-app consent.

## Permissions
- QUERY_ALL_PACKAGES: needed to enumerate apps in a security audit.
- PACKAGE_USAGE_STATS: special user-controlled system access for usage counters; declaration alone is insufficient.
- ACCESS_NETWORK_STATE: active network state.
- Not requested: INTERNET, VPN service, accessibility, device admin, SMS, contacts, storage access.

## Design decisions
- No background service, scheduler, receiver or boot action.
- No untrusted APK execution; ZIP metadata only with cap 20,000 entries.
- SHA-256 streamed in 64 KiB chunks when requested.
- Limits for dynamic data collection; display only the top 80 traffic records.
- Deep analysis is on demand and results do not mutate core risk score.
- No cloud dependence.

## Testing needed before production
Clean builds, unit tests, Android lint, on-device Android 6/8/10/12/14/15/16 tests, split APK coverage, battery profiling, file read failures, accessibility and TalkBack, actual false-positive rate, malware benchmarks and signed reproducible releases.
