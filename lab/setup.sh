#!/usr/bin/env bash
set -euo pipefail
# Creates PRIVATE HTTPS lab transport credentials. NOT an APK signing key.
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/private"
chmod 700 "$HERE/private"
if [[ ! -f "$HERE/private/cert.pem" || ! -f "$HERE/private/key.pem" ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 60 \
    -keyout "$HERE/private/key.pem" \
    -out "$HERE/private/cert.pem" \
    -subj "/CN=aster-lab-private" \
    -addext "subjectAltName=DNS:aster-lab-private,IP:127.0.0.1"
fi
chmod 600 "$HERE/private/cert.pem" "$HERE/private/key.pem"
if [[ ! -f "$HERE/private/pairing_token" ]]; then
  python3 - "$HERE/private/pairing_token" <<'PY'
import pathlib, secrets, sys
p=pathlib.Path(sys.argv[1])
p.write_text(secrets.token_urlsafe(32)+"\n")
p.chmod(0o600)
PY
fi
printf '\nCertificate SHA-256: '
openssl x509 -in "$HERE/private/cert.pem" -noout -fingerprint -sha256 | sed 's/.*=//'
printf 'Pairing token: '
cat "$HERE/private/pairing_token"
echo "Keep the token private. This is NOT Android APK signing material."
