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


## Version 0.3.0 additions

- Shizuku is strictly opt-in. Permission dialog controlled by Shizuku; allowlisted read-only commands only, with timeout and size bounds.
- GitHub updater performs a single outbound HTTPS request at app launch; it never downloads, installs, or replaces APKs automatically.
- OSV.dev only receives exact Maven names and versions after explicit user approval; app code, telemetry, user-identifying data and APK files are not transmitted.
- Static DEX parser uses capped byte reads and table validations. It reports references, not live execution.
- Imported PCAP is inspected locally, with size/packet limits. It is not traffic capture, not per-app attribution, and does not decrypt TLS.
- Health reports battery temperature (not CPU), Android thermal status, memory/storage and usage-foreground time. Shizuku process RSS can be stale or incomplete.
- Game mode is user-initiated DND, not memory-killing or CPU tuning. Android may apply different policy semantics by OS build; always provide an off switch.
- Target broad Android compatibility and data minimization; do not claim maliciousness, a CVE or exploitation without reproducible evidence.


## Version 0.4.0 live capture risk assessment

- ASTER does not implement VpnService or bind/route IP traffic. It uses the documented PCAPdroid CaptureCtrl API and explicitly requires a separately installed third-party companion. PCAPdroid handles TCP/UDP forwarding.
- The user sees PCAPdroid's own consent UI and VPN notification. VPN conflicts and Android's one-VPN limitation are disclosed before capture.
- ASTER's UDP receiver is bound to 127.0.0.1; parsed frames are immediately discarded; only bounded IP/destination and cleartext DNS/SNI metadata are kept in RAM.
- No auto-installation of CA, no MITM, no arbitrary app process intrusion, no TLS plaintext extraction.
- The local listener terminates after three minutes or 35k frames; PCAPdroid may continue capturing, and must be stopped by its notification or ASTER's Stop action.
- PCAPdroid integration is optional and is NOT part of the APK's dependency graph. The third-party app's distribution, privacy policy and maintenance are independent.
- Android emulator tests cannot validate physical ARM32/ARM64 compatibility, safe coexistence with other VPNs, or real power consumption.


## Version 0.5.0 DEX and Shizuku additions

- DEX code inspector uses the BSD-licensed `org.smali:dexlib2:2.5.2`; source API instructions are read-only. No execution of inspected code, no remote upload, no Java source reconstruction. Output is limited to 900 instructions/105 kB per method, dex payload limited to 64 MiB.
- Searchable class/method navigation loads on demand and shows app-owned classes before dependencies; users can open other libraries.
- Shizuku UserService uses an explicit permission prompt; `IExecService` only executes fixed command templates with safely validated package identifiers, bounded time and output. Force-stop requires extra user confirmation and is prohibited for system or ASTER packages on both client and service.
- No arbitrary shell execution, no grant/revoke of dangerous permissions without OS consent, no root assumptions.
- Latest GitHub release is normal (not prerelease) for discoverability but still uses ephemeral debug-key signing. This does NOT mean production readiness.


## Version 0.6.0 uninstalled-file scanner

- User explicitly chooses a `content://` URI with Android `ACTION_OPEN_DOCUMENT`. No `MANAGE_EXTERNAL_STORAGE`, no indiscriminate MediaStore enumeration, no backup or sharing of file bytes.
- `FileInspector` computes SHA-256 using a stream, limiting reads to 512 MiB, PDF/script string analysis to first 8 MiB. Files exceeding the cap are marked **partially inspected** with no complete hash.
- ZIP/OOXML scan processes a bounded number of entries and 64 MiB total inflated bytes; paths are never extracted and ZIP traversal names are noted but cannot escape to storage.
- APK bytecode browser is optional and caches only 96 MiB or smaller APKs into app-private cache with path validation; never installs or executes code.
- No RAR/7z unpacking, dynamic Windows PE execution, Office VBA macro execution, hidden TLS MITM, or antivirus signature database. Reports are diagnostic heuristics with clear caveats.
- SHA-256 is a fingerprint, not a declaration of legitimacy or malware; a file without flags must not be described as safe.
