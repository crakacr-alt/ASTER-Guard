# ASTER Guest Lab: rootable Android Emulator controlled from ASTER

**All buttons and reports are inside ASTER Guard**. The full Android Emulator and root guest run on a separate authorized Linux workstation, not within the primary phone.

## Setup

Install the Android SDK emulator, adb, sdkmanager, avdmanager; Java 17+ (for the jdb Java debugger), Python 3.10+, openssl and KVM.

Run bash lab/setup.sh to generate **TLS transport** certificate and pairing token locally. It does not generate an Android APK signing key. Never commit lab/private.

Start a rootable AOSP guest using bash lab/start_guest.sh 35 x86_64 (Android 15), or bash lab/start_guest.sh 24 x86 (Android 7). SDK availability of x86/64 differs by API. Production Play images frequently refuse adb root. Guest data wipes on every new launch.

With the emulator running, execute:

    python3 lab/aster_lab_bridge.py --cert lab/private/cert.pem --key lab/private/key.pem --token-file lab/private/pairing_token

By default HTTPS listens only on 127.0.0.1:8742. For your phone, connect a trusted private tunnel, or bind a firewalled LAN IP with --host 192.168.x.x --allow-lan. Never expose publicly.

Open ASTER -> Overview -> Android Lab, then enter the bridge HTTPS URL, SHA-256 TLS certificate fingerprint and pairing token.

## What it does

- Select guest-installed package, install opt-in APK into guest, launch/stop.
- Recent PID logcat, process status and memory map, native debuggerd backtrace.
- JDWP Java debugger: breakpoints and steps only if selected guest process actually exposes JDWP; not guaranteed for arbitrary production APK.
- Create selected-app HPROF heap dump when Android allows it, download through Android system picker. Heap may include sensitive data.
- Guest Wi-Fi/mobile toggles are NOT host-enforced offline isolation; do not test real malware without separate verified firewall/network namespace.
- Root exists only inside the guest emulator, never primary phone.
- No arbitrary adb/host shell command endpoint. Full Android guest is NOT embedded inside APK.

Unit tests: python3 -m unittest discover -s lab/tests -v
Threat model: docs/LAB_THREAT_MODEL.md


## NDK C/C++ native source compilation (v0.9.0)

This bridge also exposes a **strictly allowlisted** native C/C++ source builder
which does not need a running rooted Android Emulator. Set ANDROID_NDK_HOME
to an Android NDK r28 location and install bubblewrap plus prlimit under a
dedicated non-root user. The command-line interface runs only one C/C++
translation unit per target ABI, with no arbitrary build scripts or shell
arguments. See [docs/NATIVE_BUILDER.md](../docs/NATIVE_BUILDER.md) for setup,
Android UI usage, architecture options, .so export and limitations.


## Automated Sandbox Analyzer (v0.10.0)

ASTER's Android Lab UI can stage an APK (without installing), trigger a short
guest-only experiment, show progress, cancel, compare observations, and export
private HTML/JSON reports. The bridge requires a rootable guest with support
for named AVD snapshots. It refuses to install if the checkpoint cannot be
confirmed. Use the repository's updated lab/start_guest.sh launcher.

CRITICAL: Independently configure and test a host-side egress firewall or
isolated namespace BEFORE launching unknown APKs. Only AFTER verification
export ASTER_LAB_EGRESS_ISOLATED=YES_I_VERIFIED_HOST_FIREWALL in the environment
of the Python lab bridge. This is only an operator assertion, not a firewall.
Guest Wi-Fi/data toggles do not provide network containment.

Details: docs/SANDBOX_ANALYZER.md.
