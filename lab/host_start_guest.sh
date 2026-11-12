#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 ]]; then echo "Usage: host_start_guest.sh API ABI" >&2;exit 2;fi
API="$1"; ABI="$2"
if ! [[ "$API" =~ ^[0-9]+$ ]] || ((API<24||API>35));then exit 2;fi
if [[ "$ABI" != x86 && "$ABI" != x86_64 ]];then exit 2;fi
SDK="$ANDROID_HOME"
AVD="aster_lab_api_$(printf '%s_%s' "$API" "$ABI")"
export ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK"
export PATH="$SDK/platform-tools:$SDK/emulator:$SDK/cmdline-tools/latest/bin:$PATH"
# Never use -no-snapshot; that would disable the manual checkpoints needed by Analyzer.
"$SDK/emulator/emulator" -avd "$AVD" -port 5554 -no-window -no-audio \
  -gpu swiftshader_indirect -no-snapshot-load -no-snapshot-save \
  -no-boot-anim -wipe-data &
GUEST_PID=$!
trap 'kill "$GUEST_PID" 2>/dev/null || true; wait "$GUEST_PID" 2>/dev/null || true' EXIT
adb -s emulator-5554 wait-for-device
adb -s emulator-5554 root
for i in $(seq 1 40); do
  if [[ "$(adb -s emulator-5554 shell id -u 2>/dev/null | tr -d '\r')" == 0 ]];then
    echo "Rooted guest ready on emulator-5554; sandbox snapshots permitted."
    wait "$GUEST_PID";exit $?
  fi
  sleep 1
done
echo "Guest failed to provide root ADB; check AOSP system image" >&2
exit 1
