#!/bin/bash
# Display current IP address for team members to connect
# Usage: ./scripts/show-ip.sh
# Supports: Linux (all interfaces), macOS, WSL

set -e

echo "════════════════════════════════════════════════════════════════════"
echo "  RiskPatch Server IP Address Detector"
echo "════════════════════════════════════════════════════════════════════"
echo ""

# Try multiple methods to get primary IP (for compatibility)
PRIMARY_IP=""

# Method 1: hostname -I (Linux)
if command -v hostname &> /dev/null; then
    PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' | grep -v "^$" || true)
fi

# Method 2: ip addr (Linux with iproute2)
if [ -z "$PRIMARY_IP" ] && command -v ip &> /dev/null; then
    # Get first UP interface that's not docker/loopback
    PRIMARY_IP=$(ip -4 addr show 2>/dev/null | \
        grep -E "^\s*inet\s" | \
        grep -v "127.0.0.1" | \
        grep -v "172\." | \
        head -1 | \
        awk '{print $2}' | \
        cut -d'/' -f1 || true)
fi

# Method 3: ifconfig (macOS, older systems)
if [ -z "$PRIMARY_IP" ] && command -v ifconfig &> /dev/null; then
    PRIMARY_IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' || true)
fi

if [ -z "$PRIMARY_IP" ]; then
    echo "  Could not detect IP address automatically"
    echo ""
    echo "Your network interfaces:"
    if command -v ip &> /dev/null; then
        ip -4 addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" || true
    elif command -v ifconfig &> /dev/null; then
        ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" || true
    fi
    echo ""
    echo "Try manually:"
    echo "  Linux:   ip addr show"
    echo "  Linux:   ip addr | grep wlp0s20f3"
    echo "  macOS:   ifconfig | grep 'inet ' | grep -v 127.0.0.1"
    echo "  Windows: ipconfig"
    exit 1
fi

echo " Primary IP Address:"
echo "   $PRIMARY_IP"
echo ""

# Verify service is responding from this IP
echo " Testing connectivity..."
if curl -s http://$PRIMARY_IP:8080/api/v1/ready &>/dev/null; then
    echo "    HTTP is responding on $PRIMARY_IP:8080"
else
    echo "     HTTP might be blocked by firewall on $PRIMARY_IP:8080"
fi

if curl -sk https://$PRIMARY_IP:8443/api/v1/ready &>/dev/null; then
    echo "    HTTPS is responding on $PRIMARY_IP:8443"
else
    echo "     HTTPS might be blocked by firewall on $PRIMARY_IP:8443"
fi
echo ""

echo " Connection Endpoints:"
echo ""
echo "    HTTP (direct API, unencrypted):"
echo "      http://$PRIMARY_IP:8080"
echo "      http://$PRIMARY_IP:8080/api/v1/ready"
echo "      http://$PRIMARY_IP:8080/ui"
echo ""

echo "    HTTPS (recommended, encrypted):"
echo "      https://$PRIMARY_IP:8443"
echo "      https://$PRIMARY_IP:8443/api/v1/ready"
echo "      https://$PRIMARY_IP:8443/ui"
echo ""

echo " For Team Members - Collector Command:"
echo ""
echo "   Ready to copy-paste:"
echo ""
echo "   ./riskpatch-collector \\"
echo "     -url https://$PRIMARY_IP:8443 \\"
echo "     -asset-id my-server \\"
echo "     -token-stdin \\"
echo "     -ca-file ./stackwatch-cert.pem \\"
echo "     < <(echo \"INGEST_TOKEN_HERE\")"
echo ""

echo "════════════════════════════════════════════════════════════════════"
echo ""

echo " Tips:"
echo "   • IP may change (DHCP). Run this script again to check"
echo "   • Firewall might block ports 8080/8443. Check with:"
echo "     netstat -tuln | grep :8080"
echo "     netstat -tuln | grep :8443"
echo "   • Share with team: cert.pem + this IP + ingest token"
echo ""

echo " Detailed Diagnostics:"
echo ""
echo "   API health (localhost test):"
curl -s http://127.0.0.1:8080/api/v1/ready 2>/dev/null | jq . || echo "    API not responding"

echo ""
echo "   All network interfaces (excluding docker):"
if command -v ip &> /dev/null; then
    ip -4 addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print "      " $0}'
else
    ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | awk '{print "      " $0}'
fi

echo ""
echo "   Listening ports:"
if command -v netstat &> /dev/null; then
    netstat -tuln 2>/dev/null | grep -E ":8080|:8443" | awk '{print "      " $0}' || echo "      (netstat not available)"
elif command -v ss &> /dev/null; then
    ss -tuln 2>/dev/null | grep -E ":8080|:8443" | awk '{print "      " $0}' || echo "      (ss not available)"
fi
echo ""
