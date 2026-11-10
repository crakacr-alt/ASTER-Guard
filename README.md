# ASTER Guard

**ASTER Guard 0.3.0** — lightweight, privacy-first Android app auditor with a modern native dark UI.

> **This is an experimental security *auditor*, not a validated malware scanner.** It cannot guarantee detection, replace Play Protect, isolate threats, or inspect encrypted HTTPS payloads.

## Features

- User-initiated scanning of installed packages, with `QUERY_ALL_PACKAGES` visibility.
- Interpretable heuristics: declared overlay / accessibility / device-admin capabilities, SMS combinations, APK installation capability, old target SDK, debug builds, exported components.
- Signing certificate SHA-256 and local baseline comparison for subsequent scans.
- On-demand APK file SHA-256 and bounded ZIP entry analysis (embedded APK/DEX/JAR in assets and raw resources; extra DEX; native libraries).
- Installer information, version, requested and granted permissions, install/update timestamps.
- Active network transport, DNS servers, private DNS, proxy and VPN status.
- Per-UID receive/transmit counters for the last 24h when Android Usage Access is granted (Wi-Fi and mobile; batched system queries).
- Dark UI, risk filters, app details, shareable text report.
- No background services or scheduled network checks. Internet access only for GitHub release check **on app launch** and opt-in OSV Maven version checks.
- Optional Shizuku integration, with explicit user permission and allowlisted read-only commands to inspect process/memory snapshots; ADB privileges are not root.
- On-demand DEX class/method identifiers, embedded SDK families (versions may be unknown), split APK and native-library inventory, and code-string URL hosts; **not** source reconstruction or live debugging.
- Limited exact-version Maven dependency OSV.dev lookup on user action only. No CVE guesses from unnamed/versionless SDKs.
- Offline PCAP import: destination IP/ports, cleartext DNS/HTTP Host and TLS SNI where present. **Not** a live VPN sniffer or TLS decryptor.
- One-shot battery temperature, thermal throttling status, RAM/storage snapshots, system/kernel/security patch and recommendations; optional Usage Access foreground time by app (not actual CPU/RAM).
- Game profile with explicit Do Not Disturb permission and reversible toggling; own-app cache cleanup; never force-kills apps or falsely claims to free Android memory.
- Android 7.0+ (API 24+). Java bytecode/dex only: works with ARMv7 32-bit and ARM64 64-bit, and other Android ABIs.

## Get an APK

**[Download the Android APK directly from GitHub Releases](https://github.com/crakacr-alt/ASTER-Guard/releases/tag/v0.3.0-test)** — in *Assets*, tap **`ASTER-Guard-v0.3.0-debug.apk`**. This is a test build; the APK is directly downloadable without extracting the GitHub Actions ZIP.

The CI [GitHub Actions workflow](https://github.com/crakacr-alt/ASTER-Guard/actions/workflows/android.yml) automatically runs tests, lint, builds the APK and publishes the versioned test release after success. GitHub Actions also retains the `ASTER-Guard-debug-apk` build artifact.

Debug APK is signed with the standard ephemeral CI debug signing key. It is for **testing only**. A reproducible, trusted release needs a dedicated signing key under the project owner's control; **do not** treat debug artifacts as a verified production release.

## Build

Requires Android SDK 35, Android Gradle Plugin 8.7.3, Gradle 8.9, JDK 17.

```bash
gradle --no-daemon testDebugUnitTest lintDebug assembleDebug
```

The debug APK is produced under `app/build/outputs/apk/debug/`. There are no native shared objects or heavyweight UI frameworks.

## Privacy and Android limitations

- Android 11+ restricts installed app visibility; `QUERY_ALL_PACKAGES` is requested for an antivirus-style audit. Publication on Google Play is subject to its policy review.
- OS network usage counters require explicitly granted special Usage Access and may be incomplete or delayed; a shared UID can correspond to multiple packages.
- Imported PCAP captures support offline inspection; no live VPN packet forwarding or HTTPS decryption is implemented. Installing an embedded CA would neither grant trust to every app nor bypass certificate pinning.
- Android app sandboxing prevents arbitrary access to other apps' private files, runtime code, messages and decrypted HTTPS data.
- A risk score describes **capability combinations**, not confirmed exploitation. System packages are excluded from the current heuristics and may still be compromised.
- Signer changes can have benign causes including legitimate signing rotation; verify against the developer before acting.
- The project does not include a verified threat-intelligence database, rootkit detection, runtime sandbox or continuous protection.
- Scan is deliberately manual; SHA-256 of a full APK is calculated only when opening the deep check.

## What optimization really means

Game profile can request Android Notification Policy access and switch interruptions to priority-only **when you tap enable**. Tap disable to restore the prior setting if unchanged. Android 15+ may apply an app-owned automatic zen rule instead. It never auto-kills other apps; clearing RAM often leads to extra reloads. The "clean cache" action only deletes ASTER's own cache and does not promise FPS gains.

**Per-app load:** without privileged tracing, Android does not expose reliable instantaneous CPU/RAM figures for arbitrary third-party apps. The Usage Access list reports foreground duration, Shizuku's optional process shell report includes RSS/meminfo; these must not be interpreted as accurate CPU percentage or a live debugger.

**Kernel CVE checks:** a Linux kernel version or Android security-patch string alone cannot prove a CVE is present, because OEMs backport fixes. The app reports build and patch data, not fabricated CVE matches.

## Release readiness

The CI APK remains a temporary-key debug build. Before calling it a production release, add a permanent secure signing key (held by the maintainer, not committed), reproducible release builds, instrumented tests on Android 7–16 including Samsung/MIUI, validated malware/benign accuracy metrics and false-positive review, SBOM, privacy review, performance/battery baselines, a robust per-app VPN networking engine with lossless packet forwarding and explicit user choice, and a maintained signed vulnerability feed. This project cannot match established antivirus products on detection without curated intelligence and real malware-corpus evaluation.

## Review and tests

See [security model](docs/SECURITY_MODEL.md) and [GitHub Actions](.github/workflows/android.yml). Unit tests cover bounded risk scores and combinations. Android lint and APK compilation run in CI; these checks do **not** constitute a physical-device compatibility test or malware detection evaluation.

## Roadmap

1. Add locally updateable **signed** known-threat indicators, with a trusted verification chain and strict false-positive handling.
2. Add optional, explicit-consent local VPN metadata capture (DNS, host and IP), without breaking connectivity or requiring HTTPS interception.
3. Add split-APK-aware analysis and incremental cache keyed by lastUpdateTime + certificate digest.
4. Add emulator/device tests, accuracy benchmarks on harmless and known-malicious corpora, and power profiling.
5. Add dedicated release signing, SBOM, signed versioned releases and documented reproducibility.

### Design goals

Quiet by default, fast on demand, inspectable findings and understandable limitations. No scareware, exaggerated claims or auto-deletion.
