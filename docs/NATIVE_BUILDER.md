# ASTER NDK Builder — C/C++ source to Android native libraries

All controls are inside **ASTER Guard → Overview → Android Lab → Native C/C++ builder**.
The compiler runs on your separate Linux laboratory computer, **not inside
the phone** and not in the Android guest emulator. A secure paired lab
bridge is required; guest root and running Android emulator are optional.

## Host setup

1. Install Android NDK r28+, Python 3.10+, bubblewrap, and Android SDK
   command-line tools on a dedicated Linux x86_64 host. Enable user namespaces.
   Never run the bridge as root.
2. Run bash lab/setup_ndk.sh with ANDROID_HOME set. It installs NDK
   28.2.13676358, checks bwrap and prints the NDK location.
3. Export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/28.2.13676358
4. Run bash lab/setup.sh to create private TLS pairing credentials.
5. Launch python3 lab/aster_lab_bridge.py --cert lab/private/cert.pem
   --key lab/private/key.pem --token-file lab/private/pairing_token
   (pass all options on one line).
6. In ASTER Guard on your phone, connect to your private HTTPS bridge
   using the manually verified SHA-256 certificate pin and pairing token.
   Open "Проверить готовность NDK и песочницы".
7. Select a C/C++ .c, .cpp, .cc or .cxx UTF-8 file, up to 64 KiB,
   choose Android API 24–35 and either ARM32, ARM64, x86, x86_64, both
   ARM architectures, or all four. Set a library name like libfoo.so.
8. After compilation save one or more built libraries with Android SAF.
   Then open ASTER → File scan → APK Editor → Import ready .so,
   select the newly compiled file, rebuild and sign the APK.

## Scope and security

- The first version compiles **one C/C++ translation unit** using standard
  Android NDK headers and fixed command-line flags. No Makefile, CMake,
  arbitrary shell script, additional flags, or project checkout is executed.
- Generated library code is **never executed** by the builder. ELF bitness,
  e_machine and shared-object type are checked, SHA-256 is included.
- The compiler requires bubblewrap namespaces with no guest network access,
  read-only toolchain, private writable workdir, timeout and resource limits.
  Builds FAIL CLOSED if bwrap/NDK cannot run; do not use a personal computer
  for hostile compiler input. Sandboxing does not guarantee protection
  against all compiler or kernel exploits.
- Cross-compiling real source to a new ABI is NOT converting existing
  32-bit binaries into 64-bit ones.
- ELF validity alone does not prove correct JNI interface, symbol exports,
  transitive dependencies, 16-KiB ELF segment alignment or runtime
  compatibility. The APK Editor and Android installer need separate testing.
- Compiled libraries and HPROF artifacts on the lab host expire after
  45 minutes. User-selected source leaves the phone ONLY after explicit
  upload to the private TLS-pinned lab host.
- The user-owned signing key for modified APKs remains separate from
  ASTER Guard's own application signing key.
