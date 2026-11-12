# ASTER Sandbox Analyzer · v0.10.0

**Scope:** controlled behavioural experiments on a separate, disposable, rootable Android Emulator. All controls and report exports are in ASTER Guard Android Lab. The guest Android system is NOT running inside the phone.

## End-to-end workflow

1. On a dedicated Linux lab host, configure and independently verify network egress isolation for the emulator. The Android Wi-Fi toggle is NOT an egress firewall.
2. Start a rootable Android 7+ x86/x86_64 guest with the repository launcher. Manual emulator snapshots must work. Do not use unknown malware until isolation is verified.
3. AFTER checking the host isolation, start the bridge with environment variable ASTER_LAB_EGRESS_ISOLATED=YES_I_VERIFIED_HOST_FIREWALL. This is only an OPERATOR ASSERTION and does not configure or verify firewall rules. Without it the automatic execution endpoint refuses to run.
4. Pair ASTER on the phone with the host by HTTPS certificate SHA-256 fingerprint and secret token. Open Android Lab → Sandbox Analyzer and select an APK. Staging uploads it privately and NEVER installs or executes it.
5. Confirm analysis and choose 15, 30, 60 or 120 seconds. The bridge automatically:
   - saves and verifies a named clean AVD checkpoint BEFORE installation;
   - captures guest package IDs, data-root directory names, process names, selected settings hashes and network metadata;
   - installs the chosen APK; requires exactly one newly installed user package (does not silently update an existing app);
   - records package permission/AppOps and selected app directory file metadata;
   - launches the guest APK with Android launch intent and samples the PID;
   - takes a bounded logcat excerpt and another state snapshot;
   - compares before-install, after-install and after-run observations;
   - attempts to force-stop the process and restore the clean AVD checkpoint, then verifies the package inventory;
   - generates a local JSON and offline HTML report.
6. ASTER shows progress, bounded event timeline, changed-file/setting counts, restore status and report-export buttons.

## Measured observations versus gaps

- Package inventory: detected new/removed third-party package IDs.
- Files: selected package path, size and modification time, maximum 350 file paths and depth 6. NOT content hashes or every filesystem event.
- Permission/AppOps: selected dumpsys package permission lines and appops state; may be limited on OEMs.
- Process: process-name differences at endpoints and sampled target PID; short-lived processes may be missed.
- Settings: hashes of a small selected list, not all settings or user secrets.
- Network: bounded passive guest-wide TCP/UDP endpoints and table hashes at endpoints, WITHOUT reliable per-process attribution, PCAP or HTTPS decryption.
- Logcat: recent bounded target PID logcat when process survives until capture; not complete live syscall tracing.
- Restore: snapshot load and third-party package set comparison, NOT full byte-for-byte disk/RAM integrity proof.

## Isolation and data security

- Executable runs are blocked unless host operator explicitly states host egress isolation was verified separately. A declaration is NOT proof; use a disposable locked-down lab with real firewall or network namespace.
- Only emulator serials are accepted. The phone's installed apps and primary OS are not debug or execution targets.
- Named checkpoint must be confirmed before any APK installation. On failure or cancellation, the bridge attempts restore.
- Staged files/reports are kept in private lab storage and expire after 45 minutes. HTML has no scripts/external resources.
- JSON/HTML reports may contain sensitive filenames, process metadata and log messages: export only to locations under your control.
- No full guest OS inside phone, no guarantee to track every action, detect all malware, contain VM exploits, or reliably restore if the emulator crashes.
- CI runs pure-data unit tests and Android UI smoke tests; it does NOT run live malicious samples or verify host firewall safety.

See the lab threat model for full security boundaries.