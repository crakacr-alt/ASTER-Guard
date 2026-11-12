#!/usr/bin/env bash
set -euo pipefail
# NDK setup for a dedicated lab host only. Never install APK signing keys here.
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$SDK" ]]; then
  echo "ANDROID_HOME or ANDROID_SDK_ROOT is required" >&2; exit 2
fi
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "Linux x86_64 host is required" >&2; exit 2
fi
MANAGER="$(find "$SDK/cmdline-tools" -type f -name sdkmanager | head -n 1)"
if [[ -z "$MANAGER" ]]; then
  echo "Android sdkmanager unavailable" >&2; exit 2
fi
NDK_VERSION="28.2.13676358"
"$MANAGER" --install "ndk;$NDK_VERSION"
export ANDROID_NDK_HOME="$SDK/ndk/$NDK_VERSION"
if [[ ! -f "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" ]]; then
  echo "NDK clang missing" >&2; exit 1
fi
if ! command -v bwrap >/dev/null; then
  echo "Install bubblewrap (e.g. sudo apt install bubblewrap)." >&2
  echo "Builder refuses compilation if bubblewrap is unavailable." >&2
  exit 1
fi
echo "NDK installed: $ANDROID_NDK_HOME"
echo "Export ANDROID_NDK_HOME before starting lab/aster_lab_bridge.py"
echo "Run bridge as a dedicated non-root account in a private network."
