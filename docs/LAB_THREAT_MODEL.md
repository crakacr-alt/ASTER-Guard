# ASTER Guard root guest lab — threat model

All controller actions and reports are inside ASTER Guard Android UI. The guest Android OS and root ADB run on a separate laboratory workstation, NOT inside ASTER's phone APK. Ordinary Android apps cannot guarantee an Android 7+ x86/x86_64 rooted VM on arbitrary phones. Shizuku does not create a VM.

## Actual controls
- Manual HTTPS TLS-cert SHA-256 pin and random pairing token.
- Select an installed user guest app, or opt-in upload APK (up to 96 MiB), install into guest.
- Start/stop package, PID-scoped recent logcat, proc/PID/status, maps, debuggerd backtrace.
- Java JDWP attach, classes, threads, stacks, breakpoints, steps and continue only for guest processes exposing JDWP. Guest root alone cannot ensure all processes are debuggable; LLDB native support is not implemented.
- Attempt guest Android HPROF memory dump from selected process. Download through Android system picker; dumps can hold credentials. Unsupported dumpheap produces an explicit error rather than fake data.
- Guest Wi-Fi/data toggles are only soft radio controls. Emulator NAT may still have egress! For malware, REQUIRE separately verified host-enforced egress blocking and disposable workstation.

## Security boundary
- No generic ADB shell, host shell or URL fetch endpoints.
- Bridge defaults to loopback; remote access explicitly restricted to private network/tunnel plus token/certificate pin.
- Guest serial allowed only as emulator-PORT, never a physical device.
- Raw APK transfer to paired host happens only on explicit user action.
- No unverified claim to track every filesystem operation, API call or syscall; snapshots and logcat are incomplete.
- No Android guest running inside the primary phone, no native LLDB for any arbitrary nondebuggable process, no finished APK repacker/signing system, and no assurance that rooted malware cannot exploit a hypervisor vulnerability.
- Python unit tests test input guards, not a full isolated lab. Physical-host end-to-end sandbox isolation is untested.


## 0.7.1 live trace

Guest bridge additionally supports a bounded in-memory PID-scoped live logcat stream (start/read/stop). This records only logcat and is not complete syscall or file-action tracing. No raw payload is sent to unrelated services.


## v0.7.2 additional safeguards

- Guest launch requires explicit user confirmation and warns about NAT. The bridge never claims root alone guarantees malware containment.
- Host purge timer deletes stored HPROF files after 45 minutes, and again on bridge shutdown. Orphan dumps from crashes are removed when stale. Saving a dump to your phone via SAF remains under your control.
- JDWP step-into and step-over UI commands map to the correct debugger operations. No production signing key created.


## v0.9.0 NDK compilation trust boundary

- Host Android NDK builder accepts *only* user-selected UTF-8 C/C++ source
  up to 64 KiB, fixed 1–4 ABIs, API 24–35, and strictly validated
  libname.so; no arbitrary shell, CMake, Makefile or custom flags.
- Build requires bubblewrap user/mount/net namespace isolation and
  prlimit CPU/address-space/size/file-descriptor caps, with a 45s/ABI
  wall clock timeout. Fail closed if requirements missing.
- Compiled .so files are NEVER executed by the lab host and are removed
  automatically within 45 minutes. Full compiler/kernel exploit
  containment is NOT guaranteed; use a disposable dedicated lab host.
- ELF ABI and SHA-256 checks do not establish that a library loads or
  satisfies missing JNI dependencies. This does not translate
  compiled 32-bit ARM native code into 64-bit binary code.
- Neither Android device privileges nor APK permanent signing key
  is used by the compiler. User-owned app patch keys remain separate.


## v0.10.0 bounded automatic guest sandbox

- Staging selected APK is not installation or execution; running needs a
  separate user confirmation and a fixed duration.
- The bridge blocks automatic execution unless host operator explicitly sets
  ASTER_LAB_EGRESS_ISOLATED=YES_I_VERIFIED_HOST_FIREWALL. That setting is
  only a declaration, not an automatically verified network firewall.
- A named clean AVD checkpoint must be saved and listed before APK install.
  Restore is attempted after completion, cancellation or failure; package
  list equality is not a full disk/RAM integrity verification.
- Reports include bounded app file metadata, package IDs, permission/AppOps,
  process samples and passive guest-wide network data. No full syscall trace,
  raw PCAP, active HTTPS MITM or complete malware detection.
- Temporary staged APKs and sensitive reports expire. HTML is offline,
  escaped and script-free. Test reports are not uploaded to GitHub.
- Android tests check compilation/UI; full host sandbox containment, real
  malicious samples and snapshot restore still need controlled validation.
