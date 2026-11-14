#!/bin/bash
# Verify certificate matches server
# Usage: ./scripts/verify-cert.sh

CERT_FILE="${1:-.}/stackwatch-cert.pem"

echo "════════════════════════════════════════════════════════════════════"
echo "  Certificate Verification"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# Check file exists
if [ ! -f "$CERT_FILE" ]; then
    echo " Certificate file not found: $CERT_FILE"
    echo ""
    echo "Expected location: ./stackwatch-cert.pem"
    echo "Check with: ls -la stackwatch-cert.pem"
    exit 1
fi

echo " File found: $CERT_FILE"
echo ""

# Get current cert fingerprint
echo " Your Certificate Fingerprint (SHA256):"
openssl x509 -noout -fingerprint -sha256 -in "$CERT_FILE" 2>/dev/null | cut -d= -f2

echo ""
echo " Server Certificate Fingerprint (SHA256):"
echo "E6:49:BD:60:42:4B:E5:FE:AB:89:8F:ED:E1:13:D5:C0:18:70:A2:D3:D7:6C:45:37:74:DA:55:F7:23:13:E6:E4"

echo ""
echo " Certificate Details:"
openssl x509 -in "$CERT_FILE" -noout -subject -dates

echo ""
echo " Valid For (SAN - Subject Alternative Names):"
openssl x509 -in "$CERT_FILE" -noout -text | grep -A5 "Subject Alternative" | grep -E "IP|DNS" | sed 's/^[[:space:]]*//'

echo ""
echo "════════════════════════════════════════════════════════════════════"

# Verify fingerprints match
YOUR_FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
SERVER_FINGERPRINT="E6:49:BD:60:42:4B:E5:FE:AB:89:8F:ED:E1:13:D5:C0:18:70:A2:D3:D7:6C:45:37:74:DA:55:F7:23:13:E6:E4"

if [ "$YOUR_FINGERPRINT" = "$SERVER_FINGERPRINT" ]; then
    echo " Certificate matches server! You can use it."
    echo ""
    echo "Ready to run collector:"
    echo "  ./riskpatch-collector \\"
    echo "    -url https://<LAN_IP>:8443 \\"
    echo "    -asset-id your-server \\"
    echo "    -token-stdin \\"
    echo "    -ca-file ./stackwatch-cert.pem \\"
    echo "    < <(echo \"TOKEN_HERE\")"
else
    echo " Certificate DOES NOT MATCH server!"
    echo ""
    echo "Your fingerprint:   $YOUR_FINGERPRINT"
    echo "Server fingerprint: $SERVER_FINGERPRINT"
    echo ""
    echo " Fix:"
    echo "  1. Ask server operator for latest certificate: certs/cert.pem"
    echo "  2. Save it as: ./stackwatch-cert.pem"
    echo "  3. Run this script again to verify"
    exit 1
fi
