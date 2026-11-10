#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports/emulator
echo "== Instrumented test suite =="
gradle --no-daemon connectedDebugAndroidTest --stacktrace
echo "== Cold start and memory snapshot (NOT physical battery/energy) =="
adb shell am force-stop dev.aster.guard || true
adb shell am start -W -n dev.aster.guard/.MainActivity | tee reports/emulator/startup.txt
sleep 3
adb shell dumpsys meminfo dev.aster.guard > reports/emulator/meminfo.txt || true
adb shell dumpsys cpuinfo > reports/emulator/cpuinfo.txt || true
adb shell getprop ro.build.version.release > reports/emulator/android-version.txt
adb shell getprop ro.product.cpu.abi > reports/emulator/device-abi.txt
adb shell screencap -p /sdcard/aster-smoke.png || true
adb pull /sdcard/aster-smoke.png reports/emulator/screenshot.png || true
printf '%s\n' \
  "Metrics are one-off emulator observations only, not controlled energy/battery/FPS benchmarks." \
  "For power on physical devices, see docs/PERFORMANCE_PROTOCOL.md" \
  > reports/emulator/interpretation.txt
