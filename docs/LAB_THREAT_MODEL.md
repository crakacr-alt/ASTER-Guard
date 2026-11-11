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
