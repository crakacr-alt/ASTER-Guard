# ASTER Guard

**ASTER Guard 0.7.0** — lightweight, privacy-first Android app auditor with a modern native dark UI.

> **This is an experimental security *auditor*, not a validated malware scanner.** It cannot guarantee detection, replace Play Protect, isolate threats, or inspect encrypted HTTPS payloads.

## Features

- **In-app code privacy lab:** inspect DEX call sites referencing ad and tracking SDKs, advertising ID, device ID, location, microphone, contacts, SMS, shell and network APIs. Calls are static references, **not live execution proof**. Opt-in Shizuku AppOps overrides for a limited selection of sensitive permissions on user apps.
- **In-app guest Android lab controller:** all controls run inside ASTER UI. Pair with a **separately running** rooted AOSP Android Emulator on your own lab host using pinned TLS cert SHA-256 + token; choose guest app, upload APK with explicit consent, start/stop, guest radio soft controls, PID logcat, proc/maps/native backtrace, Java JDWP attach/step/breakpoints (only debuggable VM processes), and optional HPROF heap dump saved through Android file picker. Host bridge/API in lab/ directory. **The guest OS is not inside the APK and root never touches the main phone.**
- **Important lab safety:** radio off does NOT guarantee host egress isolation, and logs do not capture every syscall. Use verified host firewall/network namespace and disposable host before opening live malware. APK repatching/re-signing, full Java decompilation and native LLDB are not implemented.
- **Scan any file without installing/opening it:** Android Storage Access Framework document picker; APK, EXE/DLL/PE, PDF, DOC/DOCX/DOCM, XLS/XLSX/XLSM, PPT/PPTX/PPTM, PPS/PPSX, PNG/JPEG/GIF/WEBP, ZIP/JAR, RAR/7z/GZIP, ELF, scripts and unknown files. No broad filesystem permission.
- **File type from magic bytes**, SHA-256 of files up to 512 MiB, PDF JavaScript/OpenAction/Launch/embedded file flags, OOXML VBA/macros/ActiveX/embedded EXE/remote relationships, ZIP path-traversal names, executable disguised as image/document. ZIP inflation is capped at 64 MiB and 1,200 entries; RAR/7z are fingerprinted but not unpacked.
- **Non-installed APK static code browser:** select a file in the picker; if an APK, tap "Inspect DEX/Smali", which copies up to 96 MiB into ASTER's private cache and opens the real class/method/bytecode explorer without installing the app. This is a manual action and the temporary cache is subject to OS cleanup.
- User-initiated scanning of installed packages, with `QUERY_ALL_PACKAGES` visibility.
- Interpretable heuristics: declared overlay / accessibility / device-admin capabilities, SMS combinations, APK installation capability, old target SDK, debug builds, exported components.
- Signing certificate SHA-256 and local baseline comparison for subsequent scans.
- On-demand APK file SHA-256 and bounded ZIP entry analysis (embedded APK/DEX/JAR in assets and raw resources; extra DEX; native libraries).
- Installer information, version, requested and granted permissions, install/update timestamps.
- Active network transport, DNS servers, private DNS, proxy and VPN status.
- Per-UID receive/transmit counters for the last 24h when Android Usage Access is granted (Wi-Fi and mobile; batched system queries).
- Dark UI, risk filters, app details, shareable text report.
- No resident background scan services or scheduled network checks. Internet access only for GitHub release check **on app launch** and opt-in OSV Maven version checks.
- Optional Shizuku 13 API UserService integration: explicit permission, allowlisted diagnostics and confirmed third-party force-stop. No root, no arbitrary shell commands, no invisible privilege escalation.
- **Actual read-only DEX/Smali instruction explorer:** installed app → class browser (search, own classes vs libraries) → method → register/opcode/reference disassembly with copy/share, including split APK / multidex. Loads on demand; 64 MiB/Dex cap. This is **actual bytecode**, not reconstructed Java source or live execution.
- On-demand APK static inventory: embedded SDK families (version often unknown), split APK, native libraries and code-string hosts.
- **Shizuku toolkit inside each app's detail panel:** user-approved ADB/shell package inspection, AppOps view, process memory, APK path and explicit-confirmation force-stop for third-party apps; system apps and ASTER force-stop blocked.
- Limited exact-version Maven dependency OSV.dev lookup on user action only. No CVE guesses from unnamed/versionless SDKs.
- **Live, consent-driven packet metadata mode** via the officially documented PCAPdroid companion API. PCAPdroid must be separately installed and authorized by the user: it operates the actual packet-forwarding local VPN. ASTER binds a loopback-only UDP listener, requests a short, limited PCAP stream, and extracts destinations/DNS/SNI of a selected package in memory. ASTER has **no built-in VPN**, does not upload payloads or decrypt HTTPS, and never establishes a broken TUN interface.
- Offline PCAP import: destination IP/ports, cleartext DNS/HTTP Host and TLS SNI where present. Not a TLS decryptor.
- One-shot battery temperature, thermal throttling status, RAM/storage snapshots, system/kernel/security patch and recommendations; optional Usage Access foreground time by app (not actual CPU/RAM).
- Game profile with explicit Do Not Disturb permission and reversible toggling; own-app cache cleanup; never force-kills apps or falsely claims to free Android memory.
- Android 7.0+ (API 24+). Java bytecode/dex only: works with ARMv7 32-bit and ARM64 64-bit, and other Android ABIs.

## Reverse engineering: use it
After scanning installed packages, choose an app → **Open DEX/Smali code**. Search classes, tap a class, search/select a method, and view real executable DEX opcodes and referenced methods/strings; copy or share as text. The first screen prioritizes the app's package instead of AndroidX dependency methods. Use **Show all libraries** to explore dependencies. This is intentionally read-only and never injects into protected processes.

## Shizuku: use it
Install [Shizuku](https://shizuku.rikka.app/guide/setup/), start its ADB wireless debugging service and grant ASTER permission. In ASTER select **System** to confirm connected status, or open an app's detail → **Shizuku tools**. Available operations are limited to known command templates: package details, AppOps state, package APK paths, memory snapshot and confirmed force-stop of non-system/non-ASTER apps. Shizuku cannot silently grant all permissions, provide root, decrypt pinned HTTPS or attach a debugger to any non-debuggable process.

## How to scan a downloaded or external file

Open **Overview → Choose and scan file** (also available in the **APK** tab). Select any readable file from Android's system picker, including Downloads and supported document providers. ASTER streams bytes and performs an offline structural scan; it does not install, execute, or upload the file. It displays a format signature, complete SHA-256 when under the 512 MiB cap, and explicit risk indicators. You can copy/share the report.

For an **uninstalled APK**, choose the additional **Inspect DEX/Smali** action. ASTER copies up to 96 MiB of this APK to its private cache and opens the on-device DEX code viewer. APKs larger than this still receive the general file scan; full DEX browsing is not offered through the temporary-copy path. The APK is never installed.

An **EXE** is recognized as a Windows executable but not emulated or sandboxed. **PNG/JPEG** receive magic signature and hash checks, not a full image-decoder vulnerability audit. **PDF** checks uncompressed markers only; encrypted or compressed streams can hide JavaScript. **Old DOC/XLS/PPT** receive an OLE-container warning rather than a claim that all VBA code has been parsed. File-type mismatch/Office macros are risk indicators, **not proof of malware**. A file without flags is **not declared clean**.

## Start ASTER Lab

1. In the app open Overview → Android Lab for guest controls, or select an installed app → Privacy code lab, or open the same lab from a selected APK.
2. To use dynamic debugging, follow [lab/README.md](lab/README.md) to create a separate rooted x86/x86_64 Android Emulator and local HTTPS pairing credentials. Connect manually with certificate SHA-256 and token. Android permissions do not offer a universal full guest virtual machine inside the primary device.
3. Select a package installed in the guest, or explicitly upload one from the phone; run it, inspect process logcat, memory map and native stack, attach JDWP if the process is debuggable, or create an HPROF heap dump if Android supports it.
4. Guest radio settings are soft; do not run unknown live malware without externally verified host egress isolation.
5. Host security constraints are documented in [lab threat model](docs/LAB_THREAT_MODEL.md). The controller has **no arbitrary host/ADB shell endpoint** and does not execute an APK on the primary phone.

## Get an APK

**[Download the Android APK from Latest GitHub Release](https://github.com/crakacr-alt/ASTER-Guard/releases/latest)** — in *Assets*, tap **`ASTER-Guard-v0.7.0-debug.apk`**. Direct link: [APK for Android](https://github.com/crakacr-alt/ASTER-Guard/releases/download/v0.7.0/ASTER-Guard-v0.7.0-debug.apk). **This is a debug-key test build**, promoted to the normal visible Releases page for easier download; it is *not* a production-signed security product.

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

Game profile can request Android Notification Policy access and switch interruptions to priority-only **when you tap enable**. A one-shot inexact alarm tries to restore the previous setting after 90 minutes (may run late under Doze); reopening ASTER also checks expiry. Tap disable manually to restore sooner. The previous setting is restored only if it still matches the profile's expected state. Android 15+ may apply an app-owned automatic zen rule instead. It never auto-kills other apps; clearing RAM often leads to extra reloads. The "clean cache" action only deletes ASTER's own cache and does not promise FPS gains.

**Per-app load:** without privileged tracing, Android does not expose reliable instantaneous CPU/RAM figures for arbitrary third-party apps. The Usage Access list reports foreground duration, Shizuku's optional shell diagnostics provide a live snapshot of `top` CPU counters and `ps` RSS/meminfo; these must not be interpreted as accurate CPU percentage or a live debugger.

**Kernel CVE checks:** a Linux kernel version or Android security-patch string alone cannot prove a CVE is present, because OEMs backport fixes. The app reports build and patch data, not fabricated CVE matches.

## Live capture with PCAPdroid
1. Install [PCAPdroid](https://github.com/emanuele-f/PCAPdroid/releases) separately (external application, author Emanuele Faranda).
2. In ASTER select **Network → Choose application and start**, select an installed app or All Apps. PCAPdroid asks for consent (and may replace your existing VPN; Android generally allows only one active VPN).
3. Visit the selected app, return to ASTER, choose **Show network addresses**, and **Stop capture in PCAPdroid**. You can always stop through PCAPdroid's own notification.
4. The ASTER listener is loopback-only and limited to 3 minutes / 35k packets. IP, TCP/UDP port and extractable DNS/HTTP Host/TLS SNI are analyzed in-memory. No raw payloads are stored.
5. If ASTER closes or the listener times out, PCAPdroid can still be capturing. **Stop capture in PCAPdroid explicitly.** The third-party VPN engine keeps forwarding traffic independently; ASTER never runs a fail-closed VPN.
6. For optional TLS decryption you must follow PCAPdroid's own *separate* explicitly authorized settings; ASTER never installs a CA or silently decrypts other apps.
7. Testing on both Android 10/15 emulators is a smoke test of ASTER, not proof that PCAPdroid integration works on every phone/ROM.

## Test evidence and physical power study
The [Android CI workflow](.github/workflows/android.yml) runs host unit tests, lint, instrumentation on API 29 and 35 emulators, and uploads memory/startup/CPU observations in artifacts before releasing a test APK.
See [performance protocol](docs/PERFORMANCE_PROTOCOL.md) and [detection evaluation](docs/DETECTION_EVALUATION.md). An emulator **cannot** validate per-device ARMv7 energy usage or malware detection rates.
No real-phone tests or real benign/malware corpus metrics have been completed.

## Release readiness

The CI APK remains an ephemeral-key test build (per maintainer request, NO production signing key is configured). Before production: physically test ARMv7 and ARM64 phones including Samsung/MIUI, validate real malware/benign accuracy and false-positive rates, produce physical battery/fps benchmarks, create a standardized verified SBOM, audit the network companion interaction and its lifecycle, and maintain vetted/signed vulnerability intelligence. Do not call any of these completed based solely on emulator success. This project cannot match established antivirus products on detection without curated intelligence and real malware-corpus evaluation.

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
