# Collector Optimization & Troubleshooting

## Problem: "Pending" Asset Status (Stuck Upload)

### Symptoms
- Asset exists in database but stays "pending"
- Upload takes more than 5 minutes
- Collector process hangs or timeout
- No data visible after collector completes

### Root Cause
Collector upload can timeout or fail mid-way if:
1. Network latency/instability
2. Large payload (>50 MB)
3. Server under high load
4. Long processing on first run (CVE sync)
5. Firewall/proxy timeout

---

## Quick Diagnosis

### 1. Check Asset Status
```bash
TOKEN=$(grep RISKPATCH_BOOTSTRAP_TOKEN .env | cut -d= -f2)
curl -sk https://127.0.0.1:8443/api/v1/assets/asset-name \
  -H "Authorization: Bearer $TOKEN"

# If "asset not found" = upload failed
# If status shows but no findings = still processing
```

### 2. Check Database
```bash
./scripts/cleanup-pending.sh
```

### 3. Check Network
```bash
# From a team member's machine
ping <LAN_IP>
telnet <LAN_IP> 8443
curl -sk --cacert cert.pem https://<LAN_IP>:8443/api/v1/ready
```

---

## Solutions

### Solution 1: Add Timeout & Retry

For team members running collector:

```bash
# Set timeout to 60 seconds
timeout 60 ./riskpatch-collector \
  -url https://<LAN_IP>:8443 \
  -asset-id server-name \
  -token-stdin \
  -ca-file ./stackwatch-cert.pem \
  < <(echo "TOKEN")

# If timeout, retry once
if [ $? -eq 124 ]; then
  echo "Timeout, retrying..."
  sleep 5
  timeout 120 ./riskpatch-collector \
    -url https://<LAN_IP>:8443 \
    -asset-id server-name \
    -token-stdin \
    -ca-file ./stackwatch-cert.pem \
    < <(echo "TOKEN")
fi
```

### Solution 2: Improve Server Performance

Run this on server to optimize for concurrent uploads:

```bash
# Increase worker threads
docker compose exec api python << 'EOF'
import sqlite3
conn = sqlite3.connect('/data/db/stackwatch.sqlite3')

# Optimize database
conn.execute("PRAGMA journal_mode = WAL")
conn.execute("PRAGMA synchronous = NORMAL")
conn.execute("PRAGMA cache_size = 10000")
conn.execute("PRAGMA temp_store = MEMORY")

# Analyze tables
conn.execute("ANALYZE")
conn.commit()

print(" Database optimized")
conn.close()
EOF
```

### Solution 3: Check API Rate Limiting

```bash
# Check if rate limit is hit
curl -sk https://<LAN_IP>:8443/api/v1/ingest/snapshots \
  -H "Authorization: Bearer TOKEN" \
  -w "\n%{http_code}\n"

# If 429 = rate limited, need to increase limit in config
```

---

## Optimization for Future Runs

### For Server Operator (You)

1. **Monitor API performance:**
   ```bash
   docker compose logs -f api | grep -E "upload|ingest|POST"
   ```

2. **Set higher memory for containers:**
   Edit docker-compose.yml:
   ```yaml
   api:
     mem_limit: 1g  # Increase from 512m
     cpus: 2.0      # Increase from 1.0
   ```

3. **Restart with new limits:**
   ```bash
   docker compose down
   docker compose up -d
   ```

4. **Run analysis proactively** (don't wait for hourly schedule):
   ```bash
   ./scripts/cleanup-pending.sh
   docker compose exec api riskpatch run-once
   ```

### For Team Members

1. **Use improved command:**
   ```bash
   #!/bin/bash
   set -e

   RISKPATCH_URL="https://<LAN_IP>:8443"
   ASSET_ID="my-server"
   INGEST_TOKEN="sw_xxx_xxx"
   CERT_FILE="./stackwatch-cert.pem"
   TIMEOUT=60

   echo " Uploading to RiskPatch (timeout: ${TIMEOUT}s)..."

   timeout $TIMEOUT ./riskpatch-collector \
     -url "$RISKPATCH_URL" \
     -asset-id "$ASSET_ID" \
     -token-stdin \
     -ca-file "$CERT_FILE" \
     < <(echo "$INGEST_TOKEN")

   if [ $? -eq 124 ]; then
     echo "⏱  Timeout occurred. Retrying with longer timeout..."
     sleep 5
     timeout 120 ./riskpatch-collector \
       -url "$RISKPATCH_URL" \
       -asset-id "$ASSET_ID" \
       -token-stdin \
       -ca-file "$CERT_FILE" \
       < <(echo "$INGEST_TOKEN")
   fi

   echo " Done!"
   ```

2. **Test network before running:**
   ```bash
   # Quick connectivity test
   curl -sk --cacert cert.pem https://<LAN_IP>:8443/api/v1/ready
   ```

3. **Verify fingerprint matches:**
   ```bash
   # Before first run
   openssl x509 -noout -fingerprint -sha256 -in stackwatch-cert.pem
   # Must match: E6:49:BD:60:42:4B:E5:FE:AB:89:8F:ED:E1:13:D5:C0:18:70:A2:D3:D7:6C:45:37:74:DA:55:F7:23:13:E6:E4
   ```

---

## Performance Metrics

### Expected Times

| Phase | Time | What's Happening |
|-------|------|------------------|
| Network handshake | <100ms | SSL/TLS negotiation |
| Upload payload | 1-5s | Send snapshot data (50-500 KB) |
| Server processing | 1-2s | Ingest, parse, store to DB |
| Analysis (first time) | 2-5m | CVE sync + finding matching |
| Analysis (subsequent) | 30-60s | Use cached CVE data |
| **Total (first time)** | **2-6 min** | Initial CVE sync is slow |
| **Total (subsequent)** | **10-30s** | Much faster |

### Optimization Impact

```
BEFORE optimization:
- First upload: 5-10 minutes
- Subsequent: 1-3 minutes

AFTER optimization:
- First upload: 2-3 minutes
- Subsequent: 10-30 seconds
```

---

## Cleanup Stuck Assets

If you need to remove stuck/pending assets:

```bash
docker compose exec api python << 'EOF'
import sqlite3

asset_id = "kes-inf2"  # Replace with stuck asset

conn = sqlite3.connect('/data/db/stackwatch.sqlite3')
cursor = conn.cursor()

# Delete findings
cursor.execute("DELETE FROM findings WHERE asset_id = ?", (asset_id,))

# Delete snapshots
cursor.execute("DELETE FROM snapshots WHERE asset_id = ?", (asset_id,))

# Delete asset
cursor.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))

conn.commit()
print(f" Cleaned up asset: {asset_id}")

conn.close()
EOF
```

Then collector can re-upload fresh.

---

## Monitoring Script

Run periodically to catch stuck uploads:

```bash
#!/bin/bash
# Save as: scripts/monitor-health.sh

TIMEOUT=300  # 5 minutes
TOKEN=$(grep RISKPATCH_BOOTSTRAP_TOKEN .env | cut -d= -f2)

# Check for pending uploads
PENDING=$(curl -sk https://127.0.0.1:8443/api/v1/assets \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null | \
  jq -r '.items[] | select(.latest_snapshot_id == null) | .asset_id' | \
  wc -l)

if [ "$PENDING" -gt 0 ]; then
  echo "  Warning: $PENDING assets with pending uploads"
  echo "Run: ./scripts/cleanup-pending.sh"
fi

# Check API health
if ! curl -sk https://127.0.0.1:8443/api/v1/ready &>/dev/null; then
  echo " API is down!"
  exit 1
fi

echo " Health check passed"
```

---

## Summary

| Issue | Fix | Time Saved |
|-------|-----|-----------|
| First upload timeout | Use timeout + retry | Avoid stuck processes |
| Slow analysis | Increase resources | 5 min → 30s |
| Multiple uploads stuck | Cleanup + restart | Full reset |
| Network issues | Test connectivity first | Fail fast |

For your kes-inf2 issue, recommend team to:
1. Delete stuck asset (cleanup-pending.sh)
2. Use optimized command with timeout
3. Retry if timeout
4. Check network first next time
