# ASTER Guard performance and battery-validation protocol

## Claims and scope
Do not interpret emulator memory and CPU snapshots as physical-device energy usage, or claim a measurable FPS gain from clearing caches. The APK must remain test-only until tests on real ARMv7 and ARM64 devices pass.

## Automated CI evidence
The emulator smoke job captures API level, ABI, launch timing (\`am start -W\`), process memory (\`dumpsys meminfo\`), CPU snapshot (\`dumpsys cpuinfo\`), and a screenshot as GitHub Actions artifacts. These measure an emulator in a non-representative environment and are *not* physical phone power benchmarks.

## Real-phone controlled experiment
Perform on at least one 32-bit ARMv7 phone and modern ARM64 devices with Android 7, 10, 13, 15, 16 where possible. Record model, firmware, refresh rate, battery condition, security patch, ambient temperature, and charger state. Avoid running an emulator-based power benchmark as a replacement.

1. Charge to 80–90%, unplug charger. Stabilize for 10 minutes, screen and network settings fixed, airplane mode off only if network test requires it.
2. Baseline idle: measure 15 minutes with ASTER force-stopped; save \`adb shell dumpsys batterystats --reset\`, \`dumpsys batterystats --charged\`, CPU, top, and battery level every 5 minutes. Do NOT publish identifiers or unfiltered app data.
3. ASTER idle: launch/leave app in foreground for the same 15 minutes under same conditions. Repeat five times with order randomized AB/BA.
4. Audit test: scan 100+ installed packages 5x, record total milliseconds, peak PSS, CPU time, battery/thermal shifts.
5. On-demand DEX deep scan: use a fixed benign test APK, report duration, peak PSS, and any skipped oversized DEX.
6. Network capture through PCAPdroid: explicit opt-in, compare 5 minutes of predictable TCP/UDP browsing with and without capture, measure packet loss, DNS resolution, TLS handshake success, and throughput. Check stop/revoke and compatibility with existing VPNs (only one Android VPN at a time).
7. Game profile: compare the same game sequence A/B; never infer FPS gains from RAM/cache clearing. Log throttling, FPS trace or built-in game frame timing, and battery loss.

## Pass criteria for a release candidate (provisional engineering gates)
- 100% successful installs and launches across the device matrix.
- No crashes, ANR, or permission abuse; no unexpected data transmission.
- No VPN breakage, hijack or silent CA installation; explicit user consent and clear stop path.
- ASTER idle: no resident scanning loops or network polling. Battery impact statistically evaluated and reported, not guessed.
- Median scan duration / peak memory regression <15% versus previous verified build on the same hardware.
- No unsupported compatibility claim when a physical ABI lacks tests.

All raw measurements, sample size, method, ambient conditions, and deviations must be published before making release-grade performance claims.
