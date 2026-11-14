#!/bin/bash
# Cleanup stuck/pending assets and optimize for next run
# Usage: ./scripts/cleanup-pending.sh

echo " RiskPatch Cleanup & Optimization Script"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

cd "$(dirname "$0")/.." || exit 1

echo "1⃣  Checking current assets..."
TOKEN=$(grep RISKPATCH_BOOTSTRAP_TOKEN .env | cut -d= -f2)
curl -sk https://127.0.0.1:8443/api/v1/assets \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null | jq '.items[] | {asset_id, latest_snapshot_id, findings_open, first_seen}'

echo ""
echo "2⃣  Checking jobs status..."
curl -sk https://127.0.0.1:8443/api/v1/jobs?limit=10 \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null | jq '.items[] | {id, type, status, finished_at}'

echo ""
echo "3⃣  Database stats..."
docker compose exec api python << 'EOF'
import sqlite3
conn = sqlite3.connect('/data/db/stackwatch.sqlite3')
cursor = conn.cursor()

print("Assets:")
cursor.execute("SELECT COUNT(*) FROM assets")
print(f"  Total: {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM snapshots")
print(f"Snapshots: {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM findings")
print(f"Findings: {cursor.fetchone()[0]}")

cursor.execute("SELECT COUNT(*) FROM jobs WHERE status='success'")
print(f"Jobs (success): {cursor.fetchone()[0]}")

conn.close()
EOF

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo " Cleanup recommendations:"
echo ""
echo "If collector is stuck/timeout, tell team member to:"
echo "  1. Stop collector (Ctrl+C if running)"
echo "  2. Wait 10 seconds"
echo "  3. Retry with increased timeout"
echo ""
echo "Command with longer timeout:"
echo "  timeout 60 ./riskpatch-collector \\"
echo "    -url https://<LAN_IP>:8443 \\"
echo "    -asset-id their-server \\"
echo "    -token-stdin \\"
echo "    -ca-file ./stackwatch-cert.pem \\"
echo "    < <(echo \"TOKEN\")"
echo ""
echo "If still stuck, check network:"
echo "  1. ping <LAN_IP>"
echo "  2. telnet <LAN_IP> 8443"
echo "  3. curl -sk --cacert cert.pem https://<LAN_IP>:8443/api/v1/ready"
echo ""
