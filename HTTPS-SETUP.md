# RiskPatch HTTPS Setup Guide

Complete guide for setting up HTTPS/TLS in RiskPatch so that collectors and team members can connect securely.

**Status:**  Setup complete and running
- **HTTPS endpoint:** `https://127.0.0.1:8443`
- **Certificate:** `certs/cert.pem` (valid until Nov 2027)
- **Reverse proxy:** nginx (auto-generated SSL)

---

## Quick Start (Already Running)

The SSL certificate and nginx are already active. To test:

```bash
# Test HTTPS connectivity
curl -k https://127.0.0.1:8443/api/v1/ready

# Output should be:
# {"status":"ready","schema_version":8,"database":"ok"}
```

---

## File Structure

```
riskpatch/
├── certs/                      #  SSL certificate folder
│   ├── cert.pem               # Public certificate (self-signed)
│   └── key.pem                # Private key (DO NOT SHARE)
│
├── scripts/
│   ├── generate-ssl.sh        # Generate certificate
│   └── setup-https.sh         # Complete setup script
│
├── nginx.conf                 # Nginx reverse proxy config
├── docker-compose.yml         # Updated to use certs/ folder
└── README.md                  # (Updated with HTTPS section)
```

---

## Using the Collector to Send Data

### Option 1: Local Testing (Same Machine)

```bash
# 1. Generate API token for collector
TOKEN=$(docker compose exec api riskpatch token create \
  --name collector-test \
  --scopes ingest | jq -r .token)

echo "Token: $TOKEN"

# 2. Run collector locally
./collector/bin/riskpatch-collector \
  -url https://127.0.0.1:8443 \
  -asset-id my-local-machine \
  -token-stdin \
  -ca-file ./certs/cert.pem \
  < <(echo "$TOKEN")

# Output:
# accepted snapshot_id=1 asset_id=my-local-machine
```

### Option 2: Remote Server (Team Member)

**On the RiskPatch server (operator):**

```bash
# 1. Generate ingest token
TOKEN=$(docker compose exec api riskpatch token create \
  --name remote-collector \
  --scopes ingest | jq -r .token)

echo "Token: $TOKEN"

# 2. Share the certificate and token with the team member
scp certs/cert.pem user@remote-server:~/stackwatch-cert.pem
# Then share the TOKEN through a secure channel (1Password, Vault, etc.)
```

**On the remote server (team member):**

```bash
# 1. Copy collector binary
scp user@riskpatch-server:riskpatch/collector/bin/riskpatch-collector ./

# 2. Copy certificate
# Already copied: ~/stackwatch-cert.pem

# 3. Run collector
./riskpatch-collector \
  -url https://RISKPATCH_SERVER_IP:8443 \
  -asset-id remote-server-001 \
  -token-stdin \
  -ca-file ~/stackwatch-cert.pem \
  < <(echo "INGEST_TOKEN_HERE")

# Output:
# accepted snapshot_id=1 asset_id=remote-server-001
```

---

## Certificate Details

### Current Certificate Info

```bash
openssl x509 -in certs/cert.pem -noout -text
```

**Output:**
```
Subject: CN = localhost
Subject Alternative Name:
  IP Address: 127.0.0.1
  IP Address: 0.0.0.0
  DNS: localhost
  DNS: *.local

Valid From: Nov  3 14:36:20 2025 GMT
Valid To:   Nov  3 07:36:20 2027 GMT (1 year from now)
```

### Regenerate the Certificate (If Expired)

```bash
./scripts/generate-ssl.sh
docker compose restart nginx
```

---

## Access Points for Team Members

### Web UI (Dashboard)
```
https://127.0.0.1:8443/ui

Sign in with the username and password of your account.
(API tokens are not accepted by the web UI. Use them for collectors and integrations.)
```

### API Direct
```
GET https://127.0.0.1:8443/api/v1/assets
GET https://127.0.0.1:8443/api/v1/assets/my-local-machine/findings

Header:
  Authorization: Bearer <your_api_token>
```

### OpenAPI/Swagger
```
https://127.0.0.1:8443/api/v1/docs
```

---

## Sharing with the Team

### Preparation Checklist

```bash
# 1. Generate a token for the team member
docker compose exec api riskpatch token create \
  --name "Team Member Name" \
  --scopes read,ingest

# 2. Export the certificate
cat certs/cert.pem

# 3. Share securely:
#    - Token via: 1Password, Vault, private chat
#    - Certificate via: email, GitHub repo, shared folder
#    - API URL: https://YOUR_PUBLIC_IP:8443
```

### Document to Share

Create a file named `COLLECTOR_SETUP.md` for the team:

```markdown
# Collector Setup for RiskPatch

## Prerequisites
- Collector binary: `riskpatch-collector`
- Ingest token: `YOUR_TOKEN` (keep secret!)
- Certificate file: `stackwatch-cert.pem`

## Setup

1. Copy collector binary:
   \`\`\`bash
   chmod +x riskpatch-collector
   \`\`\`

2. Save certificate to file:
   \`\`\`bash
   cat > stackwatch-cert.pem << 'EOF'
   YOUR_CERT_CONTENT_HERE
   EOF
   \`\`\`

3. Run collector:
   \`\`\`bash
   ./riskpatch-collector \
     -url https://YOUR_SERVER_IP:8443 \
     -asset-id my-server-name \
     -token-stdin \
     -ca-file ./stackwatch-cert.pem \
     < <(echo "YOUR_TOKEN")
   \`\`\`

4. If successful, the output is:
   \`\`\`
   accepted snapshot_id=X asset_id=my-server-name
   \`\`\`
```

---

## Troubleshooting

### Issue 1: "certificate verify failed"

**Cause:** Certificate verification failed (self-signed certificate)

**Solution:**
```bash
# Provide the certificate file
./collector/bin/riskpatch-collector \
  -url https://YOUR_IP:8443 \
  -asset-id my-asset \
  -token-stdin \
  -ca-file ./certs/cert.pem  # ← Add this
```

### Issue 2: "connection refused"

**Cause:** nginx is not running, or the port is blocked

**Solution:**
```bash
# Check if nginx is running
docker compose ps | grep nginx

# If it is not running:
docker compose up -d nginx

# Check logs
docker compose logs nginx
```

### Issue 3: "authentication failed"

**Cause:** Invalid token or wrong scope

**Solution:**
```bash
# Verify the token exists and has the ingest scope
docker compose exec api riskpatch token list

# If needed, create a new token
docker compose exec api riskpatch token create \
  --name new-token \
  --scopes ingest
```

### Issue 4: "x509: certificate relies on legacy Common Name field"

**Cause:** Old certificate format

**Solution:**
```bash
# Regenerate the certificate with SAN
./scripts/generate-ssl.sh
docker compose restart nginx
```

---

## Production Considerations

### For a Real Deployment (Not Self-Signed)

1. **Get a proper certificate** (Let's Encrypt, corporate CA)
   ```bash
   # Get cert.pem and key.pem from your provider
   cp /path/to/real-cert.pem certs/cert.pem
   cp /path/to/real-key.pem certs/key.pem
   ```

2. **Update docker-compose.yml** (disable HTTP)
   ```yaml
   api:
     # ... ports only 8080 (internal) ...
     # Remove the 127.0.0.1 binding, use the private network only
   ```

3. **Use a proper reverse proxy** (Nginx, Traefik, HAProxy)
   - Handle TLS termination
   - Rate limiting
   - Auth forwarding

4. **Enable SSL security headers**
   ```nginx
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-Frame-Options "DENY" always;
   ```

### Firewall Setup

```bash
# Allow HTTPS inbound
sudo ufw allow 8443/tcp

# Optional: allow only from known IPs
sudo ufw allow from <LAN_IP>/24 to any port 8443
```

---

## Scripts Reference

### `scripts/generate-ssl.sh`

Generates a self-signed certificate with SAN (Subject Alternative Name).

```bash
./scripts/generate-ssl.sh

# Output:
#  Certificate generated successfully!
#  Certificate valid until: Nov  3 07:36:20 2027 GMT
```

**What it does:**
- Creates the `certs/` folder if it does not exist
- Generates a 2048-bit RSA key
- Creates a self-signed certificate (365 days)
- Adds SAN for localhost, 127.0.0.1, *.local

### `scripts/setup-https.sh`

Complete setup: generate the certificate, start services, test connectivity.

```bash
./scripts/setup-https.sh

# Output:
#  RiskPatch HTTPS is Ready!
# • Web UI: https://127.0.0.1:8443/ui
# • API: https://127.0.0.1:8443/api/v1
```

**What it does:**
1. Check or generate the SSL certificate
2. Start the api, worker, and nginx containers
3. Test the HTTPS endpoint
4. Display the access points and the collector command

---

## Manual HTTPS Test

```bash
# Test HTTPS endpoint
curl -k https://127.0.0.1:8443/api/v1/ready

# Test with certificate validation
curl --cacert certs/cert.pem https://127.0.0.1:8443/api/v1/ready

# View the response
curl -k https://127.0.0.1:8443/api/v1/assets \
  -H "Authorization: Bearer YOUR_TOKEN" | jq .
```

---

## Next Steps

1. **Share with the team:**
   - Upload `certs/cert.pem` to a shared location
   - Share API tokens securely
   - Send `COLLECTOR_SETUP.md`

2. **Monitor connections:**
   ```bash
   docker compose logs -f nginx | grep "POST /api/v1/ingest"
   ```

3. **Track assets:**
   ```bash
   curl -k https://127.0.0.1:8443/api/v1/assets \
     -H "Authorization: Bearer TOKEN" | jq '.items | length'
   ```

4. **View findings:**
   ```bash
   docker compose run --rm api riskpatch run-once
   cat reports/latest.md
   ```

---

## File Locations

| File | Purpose | Shared? |
|------|---------|---------|
| `certs/cert.pem` | Public certificate |  YES (share with the team) |
| `certs/key.pem` | Private key |  NO (keep secret!) |
| `nginx.conf` | Reverse proxy config |  YES (in repo) |
| `scripts/generate-ssl.sh` | Certificate generation |  YES (in repo) |
| `scripts/setup-https.sh` | Setup automation |  YES (in repo) |

---

**Last updated:** 2026-11-03
**Certificate expiry:** 2027-11-03
**Nginx version:** alpine (latest)
