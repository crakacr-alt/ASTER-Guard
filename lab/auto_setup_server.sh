#!/usr/bin/env bash
set -euo pipefail
# Ubuntu/Debian Linux x86_64 only. No APK execution and no signing keys.
if [[ "$(id -u)" != 0 ]];then echo "Run with sudo" >&2;exit 2;fi
BIND=127.0.0.1; API=35; ABI=x86_64
while (( $# > 0 ));do
 case "$1" in
 --bind) BIND="$2";shift 2;;
 --api) API="$2";shift 2;;
 --abi) ABI="$2";shift 2;;
 --help|-h) echo "sudo bash lab/auto_setup_server.sh [--bind PRIVATE_IP] [--api 24..35] [--abi x86|x86_64]";exit 0;;
 *) echo "Unknown option $1" >&2;exit 2;;
 esac
done
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]];then echo "Linux x86_64 required" >&2;exit 2;fi
if ! [[ "$API" =~ ^[0-9]+$ ]] || ((API<24||API>35));then echo "API 24..35 required" >&2;exit 2;fi
if [[ "$ABI" != x86 && "$ABI" != x86_64 ]];then echo "Invalid ABI" >&2;exit 2;fi
if ! python3 - "$BIND" <<'PY'
import sys,ipaddress
try:
 x=ipaddress.ip_address(sys.argv[1])
 if not (x.version==4 and (x.is_loopback or
  (x.is_private and not x.is_unspecified and not x.is_link_local) or
  x in ipaddress.ip_network('100.64.0.0/10'))):raise ValueError()
except ValueError:sys.exit(1)
PY
then echo "--bind must be loopback or private LAN/Tailscale IPv4" >&2;exit 2;fi
if [[ ! -c /dev/kvm ]];then echo "/dev/kvm missing: enable host KVM/nested virtualization" >&2;exit 1;fi
if ! command -v apt-get >/dev/null || ! command -v systemctl >/dev/null;then
 echo "Ubuntu/Debian systemd required" >&2;exit 1
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
if [[ ! -f "$HERE/host_start_guest.sh" || ! -f "$HERE/aster_lab_bridge.py" ]];then
 echo "Use a full ASTER-Guard Git checkout" >&2;exit 1
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
 ca-certificates curl unzip openssl python3 openjdk-17-jdk-headless \
 libgl1 libnss3 libxkbcommon0 libpulse0 libxcomposite1
if ! id asterlab >/dev/null 2>&1;then
 adduser --system --home /var/lib/asterlab --group --disabled-login asterlab
fi
getent group kvm >/dev/null || { echo "KVM group missing" >&2;exit 1; }
usermod -aG kvm asterlab
install -d -o asterlab -g asterlab -m 0750 /var/lib/asterlab /opt/aster-guard/lab
cp -a "$HERE/." /opt/aster-guard/lab/
chown -R asterlab:asterlab /opt/aster-guard/lab
SDK=/var/lib/asterlab/android-sdk
install -d -o asterlab -g asterlab -m 0750 "$SDK/cmdline-tools"
if [[ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]];then
 TMP="$(mktemp -d)"
 trap 'rm -rf "$TMP"' EXIT
 curl -fL --retry 3 --connect-timeout 20 -o "$TMP/sdk.zip" \
 https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip
 echo "4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583  $TMP/sdk.zip" | sha256sum -c --status || {
  echo "Official Android SDK checksum mismatch" >&2;exit 1;
 }
 unzip -q "$TMP/sdk.zip" -d "$TMP/unzip"
 mv "$TMP/unzip/cmdline-tools" "$SDK/cmdline-tools/latest"
 chown -R asterlab:asterlab "$SDK"
 rm -rf "$TMP"
 trap - EXIT
fi
LABPATH="$SDK/cmdline-tools/latest/bin:$SDK/platform-tools:$SDK/emulator:/usr/bin:/bin"
as_lab(){
 runuser -u asterlab -- env HOME=/var/lib/asterlab \
 ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK" PATH="$LABPATH" "$@"
}
echo "Accepting the Android SDK licenses for this laboratory host."
set +o pipefail
yes | as_lab "$SDK/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null
LICENSE_STATUS=$?
set -o pipefail
if ((LICENSE_STATUS!=0));then echo "SDK licenses step failed" >&2;exit 1;fi
IMAGE="system-images;android-$API;default;$ABI"
as_lab "$SDK/cmdline-tools/latest/bin/sdkmanager" --install platform-tools emulator "$IMAGE"
AVD="aster_lab_api_$(printf '%s_%s' "$API" "$ABI")"
if ! as_lab "$SDK/emulator/emulator" -list-avds | grep -Fxq "$AVD";then
 printf 'no\n' | as_lab "$SDK/cmdline-tools/latest/bin/avdmanager" create avd -n "$AVD" -k "$IMAGE" --force
fi
as_lab bash /opt/aster-guard/lab/setup.sh >/dev/null
cat > /etc/systemd/system/aster-guest.service <<EOF
[Unit]
Description=ASTER rootable Android emulator guest
After=network.target
[Service]
Type=simple
User=asterlab
Group=asterlab
SupplementaryGroups=kvm
Environment=HOME=/var/lib/asterlab
Environment=ANDROID_HOME=$SDK
Environment=ANDROID_SDK_ROOT=$SDK
Environment=PATH=$LABPATH
WorkingDirectory=/opt/aster-guard
ExecStart=/opt/aster-guard/lab/host_start_guest.sh $API $ABI
Restart=on-failure
RestartSec=8
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/asterlab /opt/aster-guard/lab
IPAddressDeny=any
IPAddressAllow=localhost
[Install]
WantedBy=multi-user.target
EOF
EXTRA=""
if [[ "$BIND" != 127.0.0.1 ]];then EXTRA="--allow-lan";fi
cat > /etc/systemd/system/aster-bridge.service <<EOF
[Unit]
Description=ASTER private HTTPS guest controller
After=aster-guest.service
Wants=aster-guest.service
[Service]
Type=simple
User=asterlab
Group=asterlab
Environment=HOME=/var/lib/asterlab
Environment=ANDROID_HOME=$SDK
Environment=ANDROID_SDK_ROOT=$SDK
Environment=PATH=$LABPATH
WorkingDirectory=/opt/aster-guard
ExecStart=/usr/bin/python3 /opt/aster-guard/lab/aster_lab_bridge.py --host $BIND --port 8742 $EXTRA --serial emulator-5554 --cert /opt/aster-guard/lab/private/cert.pem --key /opt/aster-guard/lab/private/key.pem --token-file /opt/aster-guard/lab/private/pairing_token --artifact-dir /opt/aster-guard/lab/artifacts
Restart=on-failure
RestartSec=8
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/asterlab /opt/aster-guard/lab
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now aster-guest aster-bridge
echo "HTTPS: https://$BIND:8742"
printf "Certificate SHA-256: "
openssl x509 -in /opt/aster-guard/lab/private/cert.pem -noout -fingerprint -sha256 | sed 's/.*=//'
printf "Pairing token (PRIVATE): "
cat /opt/aster-guard/lab/private/pairing_token
echo "Status: sudo systemctl status aster-guest aster-bridge"
echo "Never expose the bridge publicly. 127.0.0.1 is not reachable from your phone."
echo "The script does NOT assert malware network isolation; verify the host barrier manually."
