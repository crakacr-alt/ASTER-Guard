#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "Usage: bash lab/start_guest.sh <API 24-35> <x86|x86_64>" >&2
  exit 2
fi
API="$1"
ABI="$2"
if ! [[ "$API" =~ ^[0-9]+$ ]] || ((API<24||API>35)); then
  echo "Choose API 24-35 (Android 7+)" >&2; exit 2
fi
if [[ "$ABI" != "x86" && "$ABI" != "x86_64" ]]; then
  echo "Choose guest architecture x86 or x86_64" >&2; exit 2
fi
SDK="$(printenv ANDROID_HOME || printenv ANDROID_SDK_ROOT || true)"
if [[ -z "$SDK" ]]; then
  echo "ANDROID_HOME or ANDROID_SDK_ROOT required" >&2; exit 2
fi
export ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK"
export PATH="$SDK/platform-tools:$SDK/emulator:$SDK/cmdline-tools/latest/bin:$PATH"
for cmd in adb emulator avdmanager sdkmanager; do
  command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 2; }
done
IMAGE="system-images;android-$API;default;$ABI"
AVD="$(printf 'aster_lab_api_%s_%s' "$API" "$ABI")"
echo "Install rootable AOSP guest image: $IMAGE"
sdkmanager --install "$IMAGE"
if ! emulator -list-avds | grep -Fxq "$AVD"; then
  printf 'no\n' | avdmanager create avd -n "$AVD" -k "$IMAGE" --force
fi
cat >&2 <<'EOF'
WARNING: Android Emulator NAT may provide Internet access.
Guest Wi-Fi/data/airplane controls are NOT a host firewall.
Never run real malicious APK before verifying host egress isolation.
Root below is requested ONLY inside guest emulator.
EOF
emulator -avd "$AVD" -port 5554 -no-window -no-audio \
  -no-snapshot -wipe-data -no-boot-anim &
GUEST_PID=$!
trap 'kill "$GUEST_PID" 2>/dev/null || true' EXIT
adb -s emulator-5554 wait-for-device
adb -s emulator-5554 root || true
sleep 5
UID_GUEST="$(adb -s emulator-5554 shell id -u | tr -d '\r')"
if [[ "$UID_GUEST" != "0" ]]; then
  echo "This image does not support root adbd; use rootable AOSP image" >&2
  exit 1
fi
echo "Rooted Android guest ready. Start lab/aster_lab_bridge.py separately."
wait "$GUEST_PID"
