#!/bin/bash
# Generate a self-signed SSL certificate for RiskPatch.
#
# Usage:
#   ./scripts/generate-ssl.sh                       # SAN: 127.0.0.1, 0.0.0.0, first detected IP, localhost
#   ./scripts/generate-ssl.sh <SERVER_IP>          # adds the IP (or hostname) collectors will use
#   ./scripts/generate-ssl.sh <SERVER_IP> riskpatch.example.internal
#
# Every argument becomes a Subject Alternative Name. The first argument is also the CN.
# Output: certs/cert.pem (public certificate) and certs/key.pem (private key, mode 600).
# Existing files are backed up to *.bak-<timestamp> before being replaced.
# Collectors must pass the same certificate with -ca-file, and the URL host must be one of the SANs.

set -euo pipefail

CERT_DIR="certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
STAMP="$(date +%Y%m%d-%H%M%S)"

if [ "$#" -gt 0 ] && [[ "$1" == "-h" || "$1" == "--help" ]]; then
  sed -n '2,12p' "$0"
  exit 0
fi

mkdir -p "$CERT_DIR"

DETECTED_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
DETECTED_IP="${DETECTED_IP:-127.0.0.1}"

SANS=("IP:127.0.0.1" "IP:0.0.0.0" "IP:$DETECTED_IP" "DNS:localhost" "DNS:*.local")
EXTRA=()
for arg in "$@"; do
  if [[ "$arg" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    EXTRA+=("IP:$arg")
  elif [[ "$arg" =~ ^[A-Za-z0-9.*-]+$ ]]; then
    EXTRA+=("DNS:$arg")
  else
    echo "invalid host or IP: $arg" >&2
    exit 2
  fi
done

if [ "${#EXTRA[@]}" -gt 0 ]; then
  SANS+=("${EXTRA[@]}")
fi

CN="${1:-$DETECTED_IP}"

for f in "$CERT_FILE" "$KEY_FILE"; do
  if [ -e "$f" ]; then
    mv "$f" "$f.bak-$STAMP"
    echo "backed up existing $f -> $f.bak-$STAMP"
  fi
done

SAN_LINE="$(IFS=,; echo "${SANS[*]}")"

echo "Generating certificate"
echo "   CN:          $CN"
echo "   SAN:         $SAN_LINE"
echo "   Certificate: $CERT_FILE"
echo "   Private key: $KEY_FILE"

openssl req -x509 \
  -newkey rsa:2048 \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days 365 \
  -nodes \
  -subj "/CN=$CN" \
  -addext "subjectAltName=$SAN_LINE"

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo ""
echo "Certificate generated."
openssl x509 -in "$CERT_FILE" -noout -subject -ext subjectAltName
echo "SHA-256 fingerprint: $(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2)"
echo "Valid until:         $(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2)"

echo ""
echo "Next steps:"
echo "   1. Reload nginx so it serves the new certificate:"
echo "        docker compose up -d --force-recreate nginx"
echo "   2. Copy $CERT_FILE to every collector host and pass it with -ca-file."
echo "      Compare its SHA-256 fingerprint with the value printed above before using it."
