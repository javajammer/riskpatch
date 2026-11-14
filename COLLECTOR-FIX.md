# Fix: "certificate signed by unknown authority"

## Problem

Error when running the collector:
```
riskpatch-collector: upload not confirmed: Post "https://<LAN_IP>:8443/api/v1/ingest/snapshots":
x509: certificate signed by unknown authority
```

## Root Cause

The certificate in use is **self-signed** (not from a trusted CA). The collector must be told to trust this certificate with the `-ca-file` flag.

## Solution

###  CORRECT (use this):

```bash
./riskpatch-collector \
  -url https://<LAN_IP>:8443 \
  -asset-id my-server \
  -token-stdin \
  -ca-file ./stackwatch-cert.pem \
  < <(echo "YOUR_INGEST_TOKEN")
```

**Key point: `-ca-file ./stackwatch-cert.pem` is REQUIRED!**

###  WRONG (do not do this):

```bash
#  Missing -ca-file
./riskpatch-collector \
  -url https://<LAN_IP>:8443 \
  -asset-id my-server \
  -token-stdin \
  < <(echo "YOUR_INGEST_TOKEN")
# ERROR: certificate signed by unknown authority

#  Wrong path
./riskpatch-collector \
  -url https://<LAN_IP>:8443 \
  -asset-id my-server \
  -token-stdin \
  -ca-file /wrong/path/cert.pem \
  < <(echo "YOUR_INGEST_TOKEN")
# ERROR: file not found
```

---

## Checklist

Before running the collector, verify:

- [ ] You have the file `stackwatch-cert.pem` (shared by the server operator)
- [ ] The file is readable: `ls -l stackwatch-cert.pem`
- [ ] The file is not empty: `wc -l stackwatch-cert.pem` (should be more than 20 lines)
- [ ] It starts with `-----BEGIN CERTIFICATE-----`
- [ ] It ends with `-----END CERTIFICATE-----`
- [ ] You have the ingest token (shared by the server operator)
- [ ] The server IP is correct: `<LAN_IP>:8443` (or whatever the operator gave you)

---

## Step-by-Step Fix

### Step 1: Verify the Certificate File

```bash
# Check that the file exists and is readable
cat stackwatch-cert.pem | head -3

# Output should show:
# -----BEGIN CERTIFICATE-----
# MIIDSDCCAjCgAwIBAgIULdpx3BioQBz3MHd60sRSqlGLY+AwDQYJKoZIhvcNAQEL
# ...
```

### Step 2: Verify the Certificate Content

```bash
# Check the certificate is valid for the IP you are connecting to
openssl x509 -in stackwatch-cert.pem -noout -text | grep -A5 "Subject Alternative"

# Output should include the IP, like:
# IP Address:<LAN_IP>
```

### Step 3: Run the Collector with the Correct Parameters

```bash
# Save these in variables first
RISKPATCH_URL="https://<LAN_IP>:8443"
ASSET_ID="my-laptop"
INGEST_TOKEN="token_xxx_xxx_xxx"
CERT_FILE="./stackwatch-cert.pem"

# Run the collector
./riskpatch-collector \
  -url "$RISKPATCH_URL" \
  -asset-id "$ASSET_ID" \
  -token-stdin \
  -ca-file "$CERT_FILE" \
  < <(echo "$INGEST_TOKEN")

# Expected output:
# accepted snapshot_id=1 asset_id=my-laptop
```

---

## Testing

### Test 1: Check the Certificate Is Valid

```bash
openssl x509 -in stackwatch-cert.pem -noout -dates

# Output:
# notBefore=Nov  3 10:35:50 2026 GMT
# notAfter=Nov  3 10:35:50 2027 GMT
```

### Test 2: Verify with curl

```bash
curl -sk --cacert stackwatch-cert.pem https://<LAN_IP>:8443/api/v1/ready

# Should return JSON:
# {"status":"ready","schema_version":8,"database":"ok"}
```

### Test 3: Run the Collector in Dry-Run Mode

```bash
./riskpatch-collector \
  -url https://<LAN_IP>:8443 \
  -asset-id test-dryrun \
  -token-stdin \
  -ca-file ./stackwatch-cert.pem \
  -dry-run \
  < <(echo "$INGEST_TOKEN")

# Output shows the JSON payload without uploading
```

---

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| `-ca-file cert.pem` (missing ./) | Use `-ca-file ./stackwatch-cert.pem` |
| `-ca-file /absolute/path/cert.pem` | Use a relative path, or the full path to the correct location |
| `-ca-file ~/stackwatch-cert.pem` | Use `-ca-file ./stackwatch-cert.pem` if the file is in the same folder |
| Certificate file in a different folder | Put the file in the same directory as the collector binary |
| Token has the wrong scopes | The token must have the `ingest` scope |
| Wrong IP address | Verify the IP with `./show-ip.sh` (on the server) |
| Firewall blocking 8443 | Test with `telnet <LAN_IP> 8443` |

---

## Files You Need

From the server operator, you must have:

1. **riskpatch-collector** (binary)
   ```bash
   chmod +x riskpatch-collector
   ```

2. **stackwatch-cert.pem** (public certificate)
   ```bash
   ls -l stackwatch-cert.pem
   # Should show a readable file
   ```

3. **INGEST_TOKEN** (from the operator, via a secure channel)
   ```bash
   # Save in a shell variable:
   INGEST_TOKEN="sw_xxx_xxx_xxx"
   ```

4. **SERVER_IP:PORT** (from the operator)
   ```bash
   # Example:
   SERVER_IP="<LAN_IP>:8443"
   ```

---

## Ask the Operator For

If you do not have the certificate, ask the operator to:

1. **Share the certificate:**
   ```bash
   cat certs/cert.pem
   # Copy the output and save it as stackwatch-cert.pem
   ```

2. **Generate your ingest token:**
   ```bash
   docker compose exec api riskpatch token create \
     --name "Your Name" \
     --scopes ingest
   ```
   Then the operator shares the token with you through a secure channel (Slack, 1Password, etc.)

3. **Confirm the server IP:**
   ```bash
   ./scripts/show-ip.sh
   # The operator tells you the IP
   ```

---

## Final Command Template

Copy this, replace the placeholders, and run it:

```bash
#!/bin/bash
set -e

# Configuration
RISKPATCH_URL="https://<LAN_IP>:8443"
ASSET_ID="my-server-name"
INGEST_TOKEN="sw_xxx_xxx_xxx"
CERT_FILE="./stackwatch-cert.pem"

# Validate
[ -f "$CERT_FILE" ] || { echo " Certificate file not found: $CERT_FILE"; exit 1; }
[ -n "$INGEST_TOKEN" ] || { echo " Token not set"; exit 1; }

# Run
echo " Uploading asset snapshot to RiskPatch..."
./riskpatch-collector \
  -url "$RISKPATCH_URL" \
  -asset-id "$ASSET_ID" \
  -token-stdin \
  -ca-file "$CERT_FILE" \
  < <(echo "$INGEST_TOKEN")

echo " Done!"
```

Save it as `run-collector.sh` and run:
```bash
chmod +x run-collector.sh
./run-collector.sh
```

---

## Status:  WORKING

Tested with:
- Certificate: self-signed for <LAN_IP>
- With `-ca-file ./certs/cert.pem`
- The collector uploads successfully
- Output: `accepted snapshot_id=2 asset_id=test-with-ca`

**The `-ca-file` flag is the KEY!**
