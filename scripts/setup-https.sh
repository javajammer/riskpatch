#!/bin/bash
# Complete HTTPS setup for RiskPatch
# This script:
# 1. Generates SSL certificate (if not exists)
# 2. Starts nginx with HTTPS
# 3. Tests HTTPS connectivity
# 4. Shows configuration details

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERT_FILE="$PROJECT_DIR/certs/cert.pem"
KEY_FILE="$PROJECT_DIR/certs/key.pem"

echo "═══════════════════════════════════════════════════════════════"
echo "  RiskPatch HTTPS Setup"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Step 1: Generate certificate if not exists
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo " Step 1: Generating SSL certificate..."
    "$SCRIPT_DIR/generate-ssl.sh"
else
    echo " Step 1: SSL certificate already exists"
    echo "   Certificate: $CERT_FILE"
    echo "   Valid until: $(openssl x509 -in $CERT_FILE -noout -enddate | cut -d= -f2)"
fi

echo ""
echo " Step 2: Starting Docker services..."
cd "$PROJECT_DIR"

# Ensure API is running
if ! docker compose ps api | grep -q "Up"; then
    echo "   Starting api and worker..."
    docker compose up -d api worker
    sleep 5
fi

# Start nginx
echo "   Starting nginx..."
docker compose up -d nginx
sleep 2

echo ""
echo " Step 3: Testing HTTPS connectivity..."
HEALTH_CHECK=$(curl -sk https://127.0.0.1:8443/api/v1/ready 2>/dev/null || echo "FAILED")

if echo "$HEALTH_CHECK" | grep -q "ready"; then
    echo "    HTTPS working!"
    echo "   Response: $HEALTH_CHECK"
else
    echo "     HTTPS test failed. Checking logs..."
    docker compose logs nginx | tail -20
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "   RiskPatch HTTPS is Ready!"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo " Access Points:"
echo "   • Web UI: https://127.0.0.1:8443/ui (use API token to login)"
echo "   • API: https://127.0.0.1:8443/api/v1"
echo "   • OpenAPI: https://127.0.0.1:8443/api/v1/docs"
echo ""

echo " Your SSL Certificate:"
echo "   • Certificate: $CERT_FILE"
echo "   • Private Key: $KEY_FILE"
echo "   • Valid until: $(openssl x509 -in $CERT_FILE -noout -enddate | cut -d= -f2)"
echo ""

echo " Collector Command (Local Testing):"
echo ""
echo "   TOKEN=\$(docker compose exec api riskpatch token create --name test --scopes ingest | jq -r .token)"
echo ""
echo "   ./collector/bin/riskpatch-collector \\"
echo "     -url https://127.0.0.1:8443 \\"
echo "     -asset-id my-laptop \\"
echo "     -token-stdin \\"
echo "     -ca-file ./certs/cert.pem \\"
echo "     < <(echo \"\$TOKEN\")"
echo ""

echo " Collector Command (Remote Server):"
echo ""
echo "   # Replace YOUR_IP with your server IP"
echo "   ./riskpatch-collector \\"
echo "     -url https://YOUR_IP:8443 \\"
echo "     -asset-id remote-server \\"
echo "     -token-stdin \\"
echo "     -ca-file /path/to/certs/cert.pem \\"
echo "     < <(echo \"YOUR_INGEST_TOKEN\")"
echo ""

echo " Sharing Certificate with Team:"
echo "   scp certs/cert.pem user@remote-server:~/stackwatch-cert.pem"
echo ""

echo " View Logs:"
echo "   docker compose logs -f nginx      # HTTPS proxy logs"
echo "   docker compose logs -f api        # API server logs"
echo ""

echo " Stop Services:"
echo "   docker compose down"
echo ""
