#  Quick Start: Send Data via Collector

**Setup is complete!** The certificate and the HTTPS reverse proxy (`nginx`) are running.

---

##  COMMON ISSUES & FIXES

### Issue 1: "certificate signed by unknown authority"

**Cause:** Missing `-ca-file` flag or wrong certificate file

**Fix:**
```bash
# WRONG
./riskpatch-collector \
  -url https://<LAN_IP>:8443 \
  -asset-id server \
  -token-stdin \
  < <(echo "TOKEN")

# CORRECT  - Add -ca-file flag
./riskpatch-collector \
  -url https://<LAN_IP>:8443 \
  -asset-id server \
  -token-stdin \
  -ca-file ./stackwatch-cert.pem \
  < <(echo "TOKEN")
```

**Verify Certificate:**
```bash
openssl x509 -noout -fingerprint -sha256 -in stackwatch-cert.pem
# Must output: E6:49:BD:60:42:4B:E5:FE:AB:89:8F:ED:E1:13:D5:C0:18:70:A2:D3:D7:6C:45:37:74:DA:55:F7:23:13:E6:E4
```

---

### Issue 2: "HTTP 401: token invalid or missing"

**Cause:** Token not set or wrong token format

**Fix:**
```bash
# WRONG  - Using literal "INGEST_TOKEN"
< <(echo "INGEST_TOKEN")

# CORRECT  - Use real token from operator
TOKEN="<TOKEN>"
< <(echo "$TOKEN")

# Or directly:
< <(echo "<TOKEN>")
```

**Get Token from Operator:**
```bash
# Operator runs:
docker compose exec api riskpatch token create \
  --name "Your Name" \
  --scopes ingest

# Output:
# {
#   "token": "sw_xxx_xxx_xxx",
#   ...
# }
# Copy this token to your team member (SECURELY!)
```

---

## For Team Members (Remote Server)

### Step 1: Get the Files from the Operator

```bash
# Ask for these 3 files:
# 1. riskpatch-collector (binary)
# 2. stackwatch-cert.pem (certificate)
# 3. INGEST_TOKEN (via secure channel)

# Contoh struktur:
~/project/
├── riskpatch-collector
├── stackwatch-cert.pem
└── (save token somewhere safe)
```

### Step 2: Setup di Remote Server

```bash
# 1. Make binary executable
chmod +x riskpatch-collector

# 2. Verify certificate is readable
cat stackwatch-cert.pem | head -5

# 3. Set your variables
RISKPATCH_URL="https://YOUR_SERVER_IP:8443"
ASSET_ID="my-server-name"
INGEST_TOKEN="token_xxx_xxx"
```

### Step 3: Run Collector

```bash
./riskpatch-collector \
  -url "$RISKPATCH_URL" \
  -asset-id "$ASSET_ID" \
  -token-stdin \
  -ca-file ./stackwatch-cert.pem \
  < <(echo "$INGEST_TOKEN")
```

**Expected Output:**
```
accepted snapshot_id=1 asset_id=my-server-name
```

### Step 4: View Results

Team members can check findings in the web UI:
```
https://YOUR_SERVER_IP:8443/ui
(Sign in with your username and password)
```

---

## For You (Server Operator)

### Prepare for a Team Member

```bash
# 1. Generate ingest token
TOKEN=$(docker compose exec api riskpatch token create \
  --name "Team Member's Server" \
  --scopes ingest | jq -r .token)

echo "Share this token securely: $TOKEN"

# 2. Share certificate
cat certs/cert.pem

# 3. Share collector binary
ls -lh collector/bin/riskpatch-collector

# 4. Share server IP
echo "Server IP: $(hostname -I | awk '{print $1}'):8443"
```

### Monitoring

```bash
# Watch incoming collector data
docker compose logs -f nginx | grep "POST /api/v1/ingest"

# View new assets
docker compose exec api riskpatch token list  # verify tokens
curl -k https://127.0.0.1:8443/api/v1/assets \
  -H "Authorization: Bearer YOUR_TOKEN" | jq '.items'

# Check findings
docker compose run --rm api riskpatch run-once
cat reports/latest.md | head -50
```

---

## Testing Locally (Before Sharing)

```bash
# Test locally first
TOKEN=$(docker compose exec api riskpatch token create \
  --name local-test --scopes ingest | jq -r .token)

./collector/bin/riskpatch-collector \
  -url https://127.0.0.1:8443 \
  -asset-id local-machine \
  -token-stdin \
  -ca-file ./certs/cert.pem \
  < <(echo "$TOKEN")

# Verify
curl -k https://127.0.0.1:8443/api/v1/assets/local-machine/findings \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## Troubleshooting

### "certificate verify failed"
```bash
# Make sure cert file is provided:
./riskpatch-collector ... -ca-file ./stackwatch-cert.pem
```

### "connection refused"
```bash
# Check your server IP:
ping YOUR_SERVER_IP
nslookup YOUR_SERVER_IP

# Check firewall:
telnet YOUR_SERVER_IP 8443
```

### "token rejected"
```bash
# Verify token has 'ingest' scope:
docker compose exec api riskpatch token list

# Create new token if needed:
docker compose exec api riskpatch token create --name new --scopes ingest
```

---

## Files You Need to Share

| File | Location | Recipient |
|------|----------|-----------|
| `collector/bin/riskpatch-collector` | Binary | All team members |
| `certs/cert.pem` | Public cert | All team members |
| `INGEST_TOKEN` | Generated token | Each team member (unique) |
| `YOUR_SERVER_IP:8443` | Server info | All team members |

---

## One-Liner for Team Members

If you want to share this as a command:

```bash
export RISKPATCH_URL="https://YOUR_IP:8443"
export ASSET_ID="my-asset"
export INGEST_TOKEN="token_xxx"

./riskpatch-collector \
  -url "$RISKPATCH_URL" \
  -asset-id "$ASSET_ID" \
  -token-stdin \
  -ca-file ./stackwatch-cert.pem \
  < <(echo "$INGEST_TOKEN")
```

---

## What Gets Collected

When collector runs, it gathers:
- OS info (name, version, kernel)
- Hostname
- Installed runtimes (Python, Node, Java, Go)
- System packages (via dpkg, apt, yum)
- Package versions

Then RiskPatch analyzes for CVEs and creates report!

---

See `HTTPS-SETUP.md` for detailed setup guide.
