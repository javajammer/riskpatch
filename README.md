# RiskPatch

**Identify. Prioritize. Remediate.**

Vulnerability & Patch Management Platform. Repository: `github.com/yourorganization/riskpatch` (replace the placeholder with your organisation's path).

RiskPatch was previously called Stackwatch. The command, image, package and collector names changed; see the rename notes in CHANGELOG.md for what existing servers must update.

> **Notes for the repository owner (delete this section before publishing)**
>
> **Sanitized and replaced with placeholders:** `<TOKEN>`, `<PASSWORD>`, `<SERVER_IP>`, `<LAN_IP>`, `<HOME>`, `<EMAIL>`, `<GITHUB_TOKEN>`. The full list and how to fill each one are in `SANITIZED.md`.
>
> **Before publishing:**
> - Replace `github.com/yourorganization/riskpatch` on line 5 with your real repository path.
> - Add a `LICENSE` file. The repository has no license yet, so others have no right to use or modify it.
> - Do not push this folder to the old remote (`thecvewatch`). Its Git history still contains a `sw_…` token and a GitHub PAT. Create a new repository instead.
> - Revoke the leaked `bootstrap-admin` token and the GitHub PAT that was exposed in the old repository, even though this new one is clean.
> - Scan for secrets before the first commit, for example with `gitleaks detect --source .`.
>
> **First-time setup:**
> - `.env`: copy from `.env.example`. Set `RISKPATCH_BOOTSTRAP_ADMIN_USER` and `RISKPATCH_BOOTSTRAP_ADMIN_PASSWORD` (at least 12 characters).
> - `certs/`: create with `./scripts/generate-ssl.sh <SERVER_IP>`. This folder is not included.
> - `inventory/`: only `stack.example.yaml` is included. Copy it to `stack.yaml` and fill in your components. The original `stack.yaml` was not copied.
> - Example asset and host names in the mockups (`example-asset`, `example-host`, `example-user`) replace the original names.
> - `deploy/stackwatch.service.d/override.conf`: replace `<HOME>` in `WorkingDirectory` before installing it as a systemd unit.
> - Collector token: create with `riskpatch token create` or in the Settings UI. Never write a token into any file.
>
> **Not yet verified in this copy:**
> - Tests have not been run in this folder. Run `uv run pytest` once `.env` and `certs/` are in place.
> - `<LAN_IP>` and `<SERVER_IP>` in scripts and documents are examples only. Make sure all of them are replaced before use.
>
> **Deliberately not included:** `.git`, `.env`, databases, `cache/`, `results/`, `reports/`, session transcripts, CVE output, `certs/`, `.venv/`, and screenshots. The full list is in `SANITIZED.md`.

A Docker-based CVE intelligence platform that monitors declared technology stacks in real-time. Automatically fetches CVE data, evaluates component vulnerabilities against runtime context (exposure, authentication, mitigations), and generates prioritized security reports.

**Key Features:**
- Declarative inventory (YAML-based tech stack definition)
- Multi-source CVE intelligence (NVD, CIRCL, OSV, Shodan)
- Context-aware severity (exposure, auth boundaries, mitigations)
- Deterministic analysis (rules-based, no ML unpredictability)
- Distributed collector (Go binary, one-shot asset snapshots)
- REST API + Web UI for asset management and findings
- Automated background worker (CVE sync hourly, analysis every 3h)
- Optional LLM narrative (narrative only, does not affect verdicts)

**What RiskPatch Is NOT:**
- Not a port scanner or package auditor
- Not a SBOM/lock file reader (use SonarQube for that)
- Not an exploitation framework
- Does not verify mitigations or scan filesystems
- Does not create or execute payloads

Python and `uv` only exist inside the Docker image. Host does not need Python installed.

## Comparison with SonarQube and lock files

SonarQube plus dependency plugin (or other SBOM scanner) reads lock files like `composer.lock`, `package-lock.json`, `bun.lock`, or `requirements.txt`. It finds direct and transitive dependencies, matches versions to advisories, and outputs a list of CVEs and CVSS scores. Runtime context is absent: no internet/localhost exposure, no auth, no mitigations counted.

RiskPatch does not read lock files and does not find dependencies you don't explicitly list. It only evaluates declared components, plus exposure, role, and mitigations from YAML. Its severity is actual risk, not a copy of CVSS. Exposure `localhost` lowers severity, does not remove findings.

| | RiskPatch | SonarQube + SBOM |
|---|---|---|
| Input | Manual YAML | Automatic lock file |
| Scope | Only declared components | Direct and transitive |
| Runtime context | Exposure, auth, mitigations | None |
| Deployment target | Production host service, can be offline | CI pipeline, needs online plugin |
| Output | Prioritized follow-up actions | Findings list before deployment |

Use both if possible. Lock file prevents vulnerable dependencies from entering releases. RiskPatch monitors running components and determines which need human review. RiskPatch is not a SBOM replacement: empty or incomplete inventory means CVEs in undocumented dependencies will not appear.

## What is produced

- `reports/latest.md` - report in English
- `reports/latest.json` - same data for machines
- `reports/alerts.jsonl` - alert on new CVE, new KEV, or severity rollup increase
- Optional webhook to `ALERT_WEBHOOK_URL` (only `http` or `https`, redirects not followed)

Level: `critical`, `high`, `medium`, `low`, `informational`, `unverified`.

Action: `immediately`, `schedule`, `document`, `complete data`.

`unverified` does not mean safe. Exposure `unknown` is treated as `internet`. Distro packages that fill `distro_package` are not declared definitely safe, because back.Port has not been verified.

## Requirements

- Docker Engine and Docker Compose v2
- For system service: systemd
- Inventories are filled manually. No package, process, or filesystem scanning

## Quick Start (5 minutes)

### 1. Setup
```bash
# Clone repo and enter directory
cd /path/to/riskpatch

# Copy configuration templates
cp .env.example .env
cp inventory/stack.example.yaml inventory/stack.yaml

# Edit your stack (PHP, nginx, etc. versions)
nano inventory/stack.yaml

# (Optional) Fill in API keys in .env for enhanced features
# NVD_API_KEY, SHODAN_API_KEY, LLM_API_KEY
```

### 2. Run Analysis (One-time)
```bash
# Validate your inventory syntax
docker compose run --rm api riskpatch validate

# Run analysis and generate report
docker compose run --rm api riskpatch run-once

# Read the report
cat reports/latest.md
```

### 3. Start Server (Continuous Monitoring)
```bash
# Start API and Worker in background
docker compose up -d api worker

# View logs
docker compose logs -f worker    # CVE sync & analysis logs
docker compose logs -f api       # API request logs

# Stop services
docker compose down
```

---

## Accounts and roles (web UI)

The web UI signs in with a username and password. API tokens are separate: collectors and integrations keep using `Authorization: Bearer <token>` and are never used to sign in to the UI.

| Role | Can do |
|---|---|
| viewer | Read dashboards, findings, alerts, coverage. Change own password. |
| operator | Everything a viewer can, plus sync CVE, run analysis, acknowledge and close alerts, and queue coverage refreshes. |
| admin | Everything an operator can, plus manage users, API tokens, and background schedules. |

Create the first admin when the server starts for the first time, by setting these in `.env` before `docker compose up`:

```bash
RISKPATCH_BOOTSTRAP_ADMIN_USER=admin
RISKPATCH_BOOTSTRAP_ADMIN_PASSWORD=<at least 12 characters>
```

The admin is created only when no admin account exists yet. Afterwards, manage accounts in **Settings**. If you lose access, create or reset an account from the server:

```bash
docker compose exec api riskpatch user list
docker compose exec api riskpatch user create --username <name> --role admin     # prompts for password
docker compose exec api riskpatch user create --username <name> --role viewer
docker compose exec api riskpatch user reset-password --username <name>          # prompts for password
```

**Settings → API tokens** (admin only) lists every token with its owner, purpose, scopes, creation time, last use, and status. Create a token there by entering a name, purpose, and scopes. The token value is shown once; RiskPatch stores only a hash, so a lost value must be replaced by a new token.

Sign-in is limited to 10 attempts per minute per client address. Failed attempts are recorded in the audit trail.

## Build and run on x86_64 and ARM64 (aarch64) servers

RiskPatch has two parts that depend on CPU architecture:

| Part | What runs where | Architecture rule |
|---|---|---|
| RiskPatch server (API, UI, worker) | Docker container on the RiskPatch host | Image must match the host CPU, or be a multi-arch image |
| Collector (`riskpatch-collector`) | One static binary on every monitored server | Binary must match that server's CPU |

Both are built from this repository. The collector is a static binary (`CGO_ENABLED=0`), so it has no libc or runtime dependency and runs on any Linux distribution of the same architecture.

### 1. Find the architecture of each machine

```bash
uname -m
```

| Output | Architecture | Collector binary | Docker platform |
|---|---|---|---|
| `x86_64` | amd64 | `collector/bin/linux-amd64/riskpatch-collector` | `linux/amd64` |
| `aarch64` | arm64 | `collector/bin/linux-arm64/riskpatch-collector` | `linux/arm64` |

Graviton (AWS), Ampere, and Raspberry Pi 4/5 running a 64-bit OS are `aarch64`. A 32-bit ARM OS (`armv7l`) is not supported.

### 2. Prerequisites

- Linux with Docker Engine 20.10+ and the `docker compose` plugin (for the RiskPatch host).
- Go 1.18 or newer (only on the machine where you build the collector). Install from <https://go.dev/dl/> or your package manager (`sudo apt install golang-go` gives an older Go on some distributions; check with `go version`).
- `git`, `sha256sum` (coreutils), and `file` (optional, for printing the binary type).

### 3. Build the collector for both architectures (from any x86_64 or ARM64 workstation)

The wrapper script builds both targets in one run:

```bash
cd /path/to/phpVuln
scripts/build-collector.sh
```

What it does:

1. Checks that `go` is installed and prints its version.
2. Reads the collector version from `collector/cmd/riskpatch-collector/main.go` and the commit from `git rev-parse --short HEAD`.
3. Runs `go test ./...` in `collector/` (skip with `--no-test`).
4. For each architecture runs:
   `GOOS=linux GOARCH=<arch> CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=... -X main.commit=..."`
5. Writes `collector/bin/linux-<arch>/riskpatch-collector` and a `SHA256SUMS` file next to it.
6. Verifies each checksum with `sha256sum -c`.

Options:

```bash
scripts/build-collector.sh arm64            # only the ARM64 binary
scripts/build-collector.sh amd64 --no-test  # only x86_64, skip tests
VERSION=0.3.0 scripts/build-collector.sh    # override the version string
OUT_ROOT=/tmp/sw scripts/build-collector.sh # write somewhere else
```

Confirm the result:

```bash
file collector/bin/linux-arm64/riskpatch-collector
# ... ELF 64-bit LSB executable, ARM aarch64, ... statically linked ...
file collector/bin/linux-amd64/riskpatch-collector
# ... ELF 64-bit LSB executable, x86-64, ... statically linked ...
cd collector/bin/linux-arm64 && sha256sum -c SHA256SUMS
```

Keep the `SHA256SUMS` value. Ansible checks it before copying the binary to a server (see step 6).

### 4. Build the RiskPatch image on the RiskPatch host

The simplest and most reliable option is to build on the host that will run RiskPatch. Docker then builds for that host's architecture automatically, with no emulation:

```bash
cd /path/to/phpVuln
cp .env.example .env            # first time only; edit values
docker compose build
docker compose up -d
docker compose ps               # api and worker should show "healthy" / "running"
curl -s http://127.0.0.1:8080/api/v1/ready
```

Check which architecture the image was built for:

```bash
docker image inspect riskpatch:0.2.0 --format '{{.Architecture}}'
```

#### Building an ARM64 image from an x86_64 machine (cross-build)

Only needed if you cannot build on the ARM host. It requires QEMU emulation to be registered in the Linux kernel of the build machine:

```bash
# One time per build machine. Registers QEMU handlers for ARM64 (host-wide, needs root/Docker privileges).
docker run --privileged --rm tonistiigi/binfmt --install arm64
docker run --rm --platform linux/arm64 debian:bookworm-slim uname -m    # must print aarch64
```

Then build with the wrapper script:

```bash
# Load into the local Docker daemon (single platform):
scripts/build-image.sh --platform linux/arm64

# Build and push a multi-arch image (one tag serves both architectures):
docker login ghcr.io
scripts/build-image.sh --platform linux/amd64,linux/arm64 --push ghcr.io/<owner>/riskpatch:0.2.0
```

Multi-platform builds cannot be loaded into the local daemon, so they must be pushed. On an ARM host that pulls from a registry, Docker picks the matching architecture from the manifest automatically. If you use a single-platform image, copy it to the target host with `docker save | ssh <host> docker load` and set the image platform in `docker-compose.yml` if needed.

### 5. Run the collector on a server (manual test)

Copy the binary that matches the server's `uname -m`:

```bash
# on your build machine
scp collector/bin/linux-arm64/riskpatch-collector  user@arm-server:/tmp/
# on the server
sudo install -m 0755 /tmp/riskpatch-collector /usr/local/bin/riskpatch-collector
riskpatch-collector --version          # prints: 0.1.0 (<commit>)
```

Collect the facts without uploading anything (safe to run anywhere, no token needed):

```bash
riskpatch-collector -asset-id "$(hostname)" -dry-run | python3 -m json.tool | head -40
```

Upload one snapshot. The token is read from stdin so it never appears in the process list or shell history:

```bash
read -rs -p "RiskPatch token (scope: ingest): " SW_TOKEN; echo
printf '%s' "$SW_TOKEN" | riskpatch-collector \
  -url https://riskpatch.example.com \
  -asset-id "$(hostname)" \
  -token-stdin \
  -ca-file /etc/ssl/certs/riskpatch-ca.pem     # only when the server uses a private CA
unset SW_TOKEN
```

Expected output on success: `accepted snapshot_id=<id> asset_id=<asset>`. Running the same collection again produces the same content hash and the server answers with the existing snapshot, so repeated runs are safe. Then open the Assets page in the UI.

### 6. Roll out to many servers with Ansible (AWX)

`ansible/collect-and-send.yml` picks the binary from the `riskpatch_arch` variable (default `amd64`):

```
collector/bin/linux-{{ riskpatch_arch }}/riskpatch-collector
```

Set the variable per group in the inventory so each server gets the right binary:

```yaml
# inventory/group_vars/x86_servers.yml
riskpatch_arch: amd64
riskpatch_collector_sha256: "<sha256 from collector/bin/linux-amd64/SHA256SUMS>"

# inventory/group_vars/arm_servers.yml
riskpatch_arch: arm64
riskpatch_collector_sha256: "<sha256 from collector/bin/linux-arm64/SHA256SUMS>"
```

Use `ansible_architecture` in a pre-check if you want to fail on a mismatch:

```yaml
- name: Refuse wrong binary for this CPU
  ansible.builtin.assert:
    that:
      - (ansible_architecture == 'x86_64' and riskpatch_arch == 'amd64') or (ansible_architecture == 'aarch64' and riskpatch_arch == 'arm64')
```

Run the job template per group (or with `--limit arm_servers`). Each run is one-shot; schedule it in AWX for periodic collection.

### 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `exec format error` when running an ARM64 binary or container on x86_64 | QEMU handlers not registered | `docker run --privileged --rm tonistiigi/binfmt --install arm64` |
| `Exec format error` when running `riskpatch-collector` on a server | Binary built for the other CPU | Compare `uname -m` with the `file` output; copy the matching binary |
| `go: go.mod requires go >= ...` | Go older than 1.18 | Install Go 1.18 or newer and re-run the script |
| `sha256sum: ... FAILED` | Binary changed after building or copy was corrupted | Rebuild, re-copy, and update the checksum variable |
| `multi-platform builds need --push` | `--platform` lists several architectures without `--push` | Add `--push <registry/image:tag>` |
| Image runs but `docker compose` says `no matching manifest` | Image built only for another architecture | Build on the host or push a multi-arch image |

## Work, Campaigns and Exceptions (remediation workflow)

These menus answer "what do we do about each vulnerability, who owns it, and when is it due". They work on the same open findings as the Findings menu, but group them into decisions people can make.

### Work

One **work item** is one CVE on one package version, with the recommended upstream fix, across every server that runs it. One item covers all those servers, so one decision applies to all of them. This is not one task per alert: a single CVE on a common package can touch many servers, and one server can have many items.

- Items are calculated from open findings. An item without a decision shows as **New**. Making a decision saves a record.
- Decision states: New, Needs validation, Accepted, Scheduled, Mitigated, Verified, Deferred, Not applicable. **Verified cannot be set by hand.** The worker sets it when a newer analysed snapshot shows the affected version gone.
- Every decision records who made it, when, how many servers it covers, and which snapshots were used. The history is kept.
- **Assignee** is chosen from the list of active accounts. Unknown names are refused.
- **Priority** is a score from 0 to 100 with bands P1 to P4. It is built from severity, known exploitation (KEV), internet exposure, server tier, whether a fix is known, age, and whether the data is unverified. Every point is shown as a reason in a tooltip and in Settings.
- **SLA** sets how many hours to acknowledge and how many days to fix, per band, in Settings (admins only). The clock starts from the earliest finding and is not reset when the item is reassigned. Mitigated, Verified, Deferred, and Not applicable pause it.
- Views: All, KEV, Needs validation, No fix known, My work, Past SLA.
- Select up to 200 items and apply one decision, one assignee, and one reason in one step.
- Alerts link to their work item. Closing an alert does not resolve the item.
- RiskPatch does not deploy patches. "No fix known" means the item needs mitigation or an exception, not a patch.

### Campaigns

A campaign groups selected work items into one remediation plan: owner, change window, change or ticket ID, and a backout plan. It needs approval from a different admin than its author, and planning it marks the items Scheduled. Progress is tracked per server, and a server only counts as fixed when newer snapshots show it. The change list can be downloaded as CSV. RiskPatch tracks the plan; it does not run the change.

### Exceptions

An exception is a risk decision with an end date. A deferral is the common case.

- Deferring a work item requires a reason and an expiry date between 1 and 180 days ahead. A compensating control is optional.
- Changing the item's decision later closes the exception.
- Every 5 minutes the worker expires exceptions whose date has passed and reopens the item as **Needs validation**. The SLA clock is not reset, so the item may be overdue immediately.
- Admins can revoke an exception with a reason.
- Views: Active, Expiring within 30 days, and Expired, revoked, or replaced. The Overview shows how many deferrals end within 14 days.

Not built yet: an approver separate from the requester, exceptions limited to some servers, and expiry reminders. These are listed in TODO.md.

## Database: setup, indexes and recreation

The database is SQLite in the Docker volume `stackwatch-db`. It is created and changed only by the numbered migrations in `src/riskpatch/migrations/`. The API and the worker apply pending migrations when they start, and `riskpatch migrate` does the same by hand.

**Indexes are part of the migrations.** Every index the application uses is created by a migration, so a brand-new database gets all of them as soon as migrations run. You do not need to create indexes by hand.

**Statistics are not.** `ANALYZE` results are not created by migrations and are not stored in a new database. Without them, SQLite guesses which index to use, and a list query can sort tens of thousands of rows when a better index exists. The worker collects statistics once a day, and `scripts/setup-db.sh` collects them when you run it.

### Commands

```bash
scripts/setup-db.sh              # existing database: apply migrations, check indexes, collect statistics, restart api and worker
scripts/setup-db.sh --recreate   # copy the current database to the backups volume, then build an empty one (type RECREATE to confirm)
docker compose exec api riskpatch db check     # lists hot indexes that are missing (exit code 1 if any)
docker compose exec api riskpatch db analyze   # collects statistics now
```

### Recreating the database

1. Run `scripts/setup-db.sh --recreate` and type `RECREATE`. The previous database is kept as `riskpatch-before-recreate-<time>.sqlite3` in the `stackwatch-backups` volume.
2. Migrations run in order, so every index is recreated. Check that the output ends with `hot indexes: all present`.
3. Users and tokens are not kept. Recreate the first admin with `RISKPATCH_BOOTSTRAP_ADMIN_USER` and `RISKPATCH_BOOTSTRAP_ADMIN_PASSWORD` in `.env`, or with `riskpatch user create --username <name> --role admin`. Then re-enter any data you need (assets report again on their next collector run).

To restore a backup instead, use `riskpatch restore <file>` (stop `api` and `worker` first). A backup that was taken from a database with statistics keeps them.

## Features & Commands

### Feature 1: Server API + Web UI

**Purpose:** Central repository for assets, findings, and CVE intelligence. Multi-user, token-authenticated, REST API + Web Dashboard.

**Quick Start:**
```bash
docker compose up -d api worker

# Generate API token for automation
docker compose exec api riskpatch token create --name awx --scopes ingest
```

**Access:**
- **Web UI:** http://127.0.0.1:8080/ui (sign in with username and password; see "Accounts and roles")
- **API:** http://127.0.0.1:8080/api/v1/
- **OpenAPI Spec:** http://127.0.0.1:8080/api/v1/openapi.json

**Key Endpoints:**
```bash
# Get all assets
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:8080/api/v1/assets

# Get findings for specific asset
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:8080/api/v1/assets/laptop/findings

# Get reports
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://127.0.0.1:8080/api/v1/reports

# Check API health
curl http://127.0.0.1:8080/api/v1/ready
```

**Token Management:**
```bash
# List tokens
docker compose exec api riskpatch token list

# Create token with specific scopes (read, ingest, operate, admin)
docker compose exec api riskpatch token create --name my-app --scopes read,ingest

# Revoke token
docker compose exec api riskpatch token revoke --name my-app
```

---

### Feature 2: Collector (One-shot Asset Snapshots)

**Purpose:** Lightweight Go binary deployed to servers via Ansible/AWX. Collects OS facts, installed packages, runtimes, and sends to RiskPatch API. One execution, then cleans itself up.

**Setup:**

1. **Build the collector binary:**
   ```bash
   cd collector
   CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/riskpatch-collector ./cmd/riskpatch-collector
   ```

2. **Get an ingest token:**
   ```bash
   docker compose exec api riskpatch token create --name collector --scopes ingest
   ```

3. **Run collector on remote system:**
   ```bash
   # Get collector binary to remote system (via Ansible, SCP, etc.)
   # Then execute:

   ./riskpatch-collector \
     -url https://riskpatch.example.com \
     -asset-id laptop-001 \
     -token-stdin \
     < <(echo "your_ingest_token")

   # Output: accepted snapshot_id=1 asset_id=laptop-001
   ```

4. **Collect from multiple systems (Ansible example):**
   ```bash
   # Use playbook: ansible/collect-and-send.yml
   ansible-playbook ansible/collect-and-send.yml \
     -i inventory/hosts.ini \
     -e riskpatch_url=https://riskpatch.example.com \
     -e riskpatch_token=token_here \
     -e target_hosts=all
   ```

**Collector Features:**
- Gathers: OS (name, version, kernel), hostname, runtimes (Python, Node, Java, Go), system packages (via dpkg, rpm, apt)
- Size: ~5 MB (statically linked, no dependencies)
- Execution: One-shot, self-deletes after success (with `-self-delete` flag)
- Security: Token via stdin (never in argv logs), SHA256 verification

**Common Issues & Fixes:**

If team members get error `certificate signed by unknown authority`:
```bash
# WRONG - Missing -ca-file flag
./riskpatch-collector -url https://... -asset-id server -token-stdin

# CORRECT - Include -ca-file
./riskpatch-collector \
  -url https://<LAN_IP>:8443 \
  -asset-id server \
  -token-stdin \
  -ca-file ./stackwatch-cert.pem \
  < <(echo "TOKEN")
```

If team members get error `HTTP 401: token invalid`:
```bash
# WRONG - Using literal string
< <(echo "INGEST_TOKEN")

# CORRECT - Use real token
< <(echo "sw_xxx_xxx_xxx")
```

To get token:
```bash
docker compose exec api riskpatch token create \
  --name "Team Member Name" \
  --scopes ingest
```

**Certificate Verification:**
```bash
# Team can verify certificate with:
openssl x509 -noout -fingerprint -sha256 -in stackwatch-cert.pem

# Must match:
# E6:49:BD:60:42:4B:E5:FE:AB:89:8F:ED:E1:13:D5:C0:18:70:A2:D3:D7:6C:45:37:74:DA:55:F7:23:13:E6:E4
```

---

### Feature 3: Worker (Background Job Scheduler)

**Purpose:** Runs on server continuously. Executes scheduled jobs: CVE sync (hourly), analysis (every 3 hours). Do NOT scale beyond 1 worker.

**Setup:**
```bash
# Start single worker instance
docker compose up -d worker

# Verify it's running
docker compose logs worker

# Expected output:
# INFO menjalankan job N (cve_sync)
# INFO menjalankan job N (analysis)
```

**Job Types:**
- `cve_sync` - Fetches latest CVEs from NVD, CIRCL, OSV every hour
- `analysis` - Evaluates all assets against CVE data every 3 hours
- `report_export` - Generates latest.md and latest.json

**Configuration:**
All timing controlled in database (`job_schedules` table). Intervals in seconds:
```sql
-- Check current schedules
docker compose exec api sqlite3 /data/db/stackwatch.sqlite3 \
  "SELECT name, interval_seconds FROM job_schedules;"

-- Output:
-- CVE sync|3600
-- Analysis|10800
```

---

### Feature 4: Inventory Management (YAML-based)

**Purpose:** Declare your tech stack explicitly. Not auto-discovered; this is intentional.

**Location:** `inventory/stack.yaml`

**Required Fields Per Component:**
```yaml
meta:
  name: my-stack           # Inventory name for reports
  environment: production  # Label only (prod/staging/dev)

components:
  - id: php-8.2            # Must match: [a-zA-Z0-9._-]+
    name: PHP              # Display name
    version: "8.2.12"      # Exact version (not ranges)
    ecosystem: generic     # See supported list below

    # For ecosystem: generic, provide either:
    cpe: "cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*"
    # OR
    vendor: php
    product: php

    role: runtime          # runtime, webserver, database, library, etc.
    exposure: internet     # internet, localhost, internal, unknown
    auth_boundary: unauthenticated  # authenticated, unauthenticated, unknown
    used_at_runtime: true  # true/false - affects transitive risk
    mitigations: []        # ["reverse proxy", "rate limit", etc.]
    distro_package: "php8.2-fpm"  # Optional: distro package name
    notes: "Custom notes here"
```

**Supported Ecosystems:**
- `generic` - Any software (requires CPE or vendor+product)
- `npm` - Node.js packages
- `PyPI` - Python packages
- `Packagist` - PHP packages
- `Go` - Go modules
- `crates.io` - Rust packages
- `Debian`, `Ubuntu` - Linux distro packages

**Validation:**
```bash
docker compose run --rm api riskpatch validate
```

**Lock File Conversion (Extract names+versions):**
```bash
# From composer.lock (PHP)
python3 scripts/from-composer-lock.py composer.lock >> inventory/stack.yaml

# From package-lock.json (Node.js)
python3 scripts/from-package-lock.py package-lock.json >> inventory/stack.yaml

# From requirements.txt (Python)
python3 scripts/from-requirements.py requirements.txt >> inventory/stack.yaml

# From bun.lock (Bun package manager)
python3 scripts/from-bun-lock.py bun.lock >> inventory/stack.yaml
```

** Important:** Lock file conversion only copies names/versions. You MUST add `role`, `exposure`, `auth_boundary` fields manually based on your runtime context.

---

### Feature 5: Report Generation

**Purpose:** Markdown report with executive summary and CVE details. Can be version-controlled, shared with teams.

**One-time Report:**
```bash
docker compose run --rm api riskpatch run-once
```

**Output Files:**
- `reports/latest.md` - Human-readable report (English)
- `reports/latest.json` - Structured data for machines
- `reports/alerts.jsonl` - Line-delimited alerts (new CVE, KEV, level changes)

**Report Contents:**
1. **Executive Summary** - Critical, High, Medium counts + required actions
2. **What to Do This Week** - Critical & Known Exploited CVEs
3. **Schedule Within 30 Days** - High severity items
4. **Backlog** - Medium/Low (document only)
5. **Component Roll-up** - Per-component summary

**Severity Levels:**
- `critical` - Fix immediately (known exploited, CVSS 9+, internet exposure)
- `high` - Schedule within 30 days
- `medium` - Document and monitor
- `low` - Informational
- `unverified` - Version match uncertain; needs verification
- `informational` - No action required

**Actions:**
- `Fix this week` - Critical/KEV
- `Schedule (30 days)` - High
- `Plan / monitor` - Medium/Low
- `Complete inventory data` - Unverified (needs more info)

---

### Feature 6: Terminal UI (TUI)

**Purpose:** Read-only dashboard for reports. View findings, request refresh. Does NOT edit YAML (edit on host instead).

**Run:**
```bash
docker compose --profile tui run --rm tui
```

**Controls:**
- `r` - Request refresh (triggers analysis job)
- `q` - Quit
- Arrow keys - Navigate

**How it Works:**
TUI monitors `reports/` directory. When you press `r`, it writes `reports/refresh.request` which the worker picks up and triggers analysis.

---

### Feature 7: Offline Mode

**Purpose:** Server without internet access can still analyze using cached CVE data.

**Setup:**

1. **On networked machine, pre-fill cache:**
   ```bash
   # Normal run fetches and caches
   docker compose up -d worker
   docker compose logs worker  # Wait for CVE sync to complete
   docker compose down

   # Copy cache folder
   tar czf cache.tar.gz cache/
   ```

2. **On offline server, restore cache:**
   ```bash
   # Extract cache
   tar xzf cache.tar.gz

   # Enable offline mode
   echo "RISKPATCH_OFFLINE=1" >> .env

   # Run
   docker compose run --rm api riskpatch run-once
   ```

**Report behavior in offline mode:**
- `"stale": true` in latest.json
- Still generates findings, but CVE data may not be current
- Useful for compliance/audit even without internet

---

### Feature 8: Systemd Integration (Production)

**Purpose:** Auto-start RiskPatch service on boot. Managed by systemd, not by docker-compose.

**Install:**
```bash
# Copy service file
sudo cp deploy/riskpatch.service /etc/systemd/system/

# Optional: Override default WorkingDirectory
sudo mkdir -p /etc/systemd/system/riskpatch.service.d
sudo cp deploy/riskpatch.service.d/override.conf /etc/systemd/system/riskpatch.service.d/

# Reload and enable
sudo systemctl daemon-reload
sudo systemctl enable --now riskpatch.service

# Verify
sudo systemctl status riskpatch.service
docker ps | grep riskpatch
```

**Service Behavior:**
- Starts on boot with `Restart=always`
- Drops to non-root user (uid 1000) after initial setup
- Logs via `journalctl -u riskpatch -f`

---

## Configuration

### .env Variables

Copy `.env.example` to `.env` and customize:

| Variable | Default | Purpose |
|----------|---------|---------|
| `NVD_API_KEY` | required | NIST NVD API key (free, requires registration) |
| `SHODAN_API_KEY` | optional | Enrich CVEs with exploit data |
| `LLM_BASE_URL` | https://api.groq.com/openai/v1 | LLM endpoint (OpenAI-compatible) |
| `LLM_API_KEY` | optional | For narrative generation |
| `LLM_MODEL` | qwen/qwen3.8-27b | Model to use |
| `ALERT_WEBHOOK_URL` | optional | Post new findings to Slack/Teams/custom endpoint |
| `RISKPATCH_OFFLINE` | 0 | Set to `1` for offline mode |
| `POLL_INTERVAL_SECONDS` | 21600 | How often to check for inventory changes (6h) |
| `CACHE_TTL_HOURS` | 6 | How long to cache CVE data |
| `RISKPATCH_BOOTSTRAP_TOKEN` | auto-generated | Initial admin token for API |

### Volume Mounts

```yaml
# In docker-compose.yml
volumes:
  stackwatch-db:/data/db           # SQLite database + WAL files
  stackwatch-backups:/data/backups # For backup/restore operations
  ./inventory:/data/inventory:ro   # Read-only YAML inventory
  ./reports:/data/reports          # Generated reports
  ./cache:/data/cache              # CVE data cache
```

On host, paths map to:
- `/data/db/stackwatch.sqlite3` → `./riskpatch.db` in container
- `/data/inventory/stack.yaml` → `./inventory/stack.yaml` on host
- `/data/reports/latest.md` → `./reports/latest.md` on host

---

## Common Tasks

### Task 1: Add a New Asset (Collector)
```bash
# 1. Generate ingest token
TOKEN=$(docker compose exec api riskpatch token create --name asset-x --scopes ingest | jq -r .token)

# 2. Run collector on target system
./riskpatch-collector \
  -url https://riskpatch.example.com \
  -asset-id my-app-server \
  -token-stdin \
  < <(echo "$TOKEN")

# 3. Verify asset appears
curl -H "Authorization: Bearer $TOKEN" https://riskpatch.example.com/api/v1/assets
```

### Task 2: Update Tech Stack
```bash
# Edit inventory
nano inventory/stack.yaml

# Validate
docker compose run --rm api riskpatch validate

# Trigger analysis
docker compose run --rm api riskpatch run-once

# View new report
cat reports/latest.md
```

### Task 3: Backup Database
```bash
docker compose exec api riskpatch backup /data/backups/backup-$(date +%Y%m%d).db
tar czf backups.tar.gz backups/
```

### Task 4: Restore from Backup
```bash
# Stop services
docker compose down

# Restore
docker compose exec api riskpatch restore /data/backups/backup-20261102.db

# Restart
docker compose up -d api worker
```

### Task 5: View Jobs Status
```bash
docker compose exec api python << 'EOF'
import sqlite3
conn = sqlite3.connect('/data/db/stackwatch.sqlite3')
cursor = conn.cursor()
cursor.execute('SELECT id, type, status, finished_at FROM jobs ORDER BY id DESC LIMIT 10')
for row in cursor.fetchall():
    print(f"Job {row[0]}: {row[1]} - {row[2]} ({row[3]})")
conn.close()
EOF
```

### Task 6: Manual CVE Sync (Don't Wait 1h)
```bash
docker compose exec api python << 'EOF'
from riskpatch.cvesync import run_cve_sync
from riskpatch.db import connect
from riskpatch.config import get_settings

settings = get_settings()
conn = connect(settings.db_path)
result = run_cve_sync(conn, settings, log_event=print)
print(f"Result: {result}")
conn.close()
EOF
```

---

## Docker Compose Profiles

### Default (API + Worker)
```bash
docker compose up -d       # Start api + worker
```

### With TUI
```bash
docker compose --profile tui run --rm tui
```

### Watcher (Legacy YAML polling mode - deprecated)
```bash
docker compose --profile legacy up -d watcher
```

### Custom: Just API (no worker)
```bash
docker compose up -d api
# Manual jobs:
docker compose run --rm api riskpatch run-once
```

---

## Troubleshooting

### Issue: "No findings found"
**Cause:** Analysis hasn't run yet or ecosystem/version not recognized.
```bash
# Check inventory is valid
docker compose run --rm api riskpatch validate

# Check assets table
docker compose exec api sqlite3 /data/db/stackwatch.sqlite3 "SELECT * FROM assets;"

# Manually run analysis
docker compose run --rm api riskpatch run-once

# Check findings
docker compose exec api sqlite3 /data/db/stackwatch.sqlite3 \
  "SELECT asset_id, component_name, cve_id FROM findings LIMIT 10;"
```

### Issue: "404 Not Found" on API
**Cause:** Container not started or network issue.
```bash
docker compose ps                # Check container status
docker compose logs api          # View API startup errors
curl http://127.0.0.1:8080/api/v1/ready  # Test connectivity
```

### Issue: "Collector: certificate verification failed"
**Cause:** Self-signed cert or firewall.
```bash
# Development: provide CA file
./riskpatch-collector -url https://localhost:8443 -ca-file /path/to/cert.pem ...

# Production: use proper TLS cert (not self-signed)
```

### Issue: Database locked
**Cause:** Multiple writers (should be only 1 worker).
```bash
docker compose ps
# Kill any extra workers
docker compose down
docker compose up -d api worker  # Only 1 worker
```

---

## Performance

- **Memory:** 512MB per container (configurable in docker-compose.yml)
- **CPU:** 1 core per container
- **Database:** SQLite WAL mode, auto-vacuum enabled
- **Report generation:** <10s for 100 components
- **Collector execution:** <5s per system

For monitoring >500 assets, consider:
- Increase memory/CPU limits
- Run analysis during off-hours
- Archive old findings (via `prune` command)

---

## Security

- **Token scopes:** `read` (view), `ingest` (collector), `operate` (manual jobs), `admin` (full access)
- **Secrets:** Never commit .env to git. Use secret management (Vault, 1Password, etc.)
- **TLS:** Use reverse proxy (Nginx, Traefik) with proper certificates for production
- **Database:** SQLite in volume; add backups to S3/NAS
- **RBAC:** Not yet implemented; tokens are per-integration, not per-user

## Extract lock files to YAML

Lock files are not read directly. Scripts below only copy names and versions. `role`, `exposure`, and `auth_boundary` are set to defaults. Check before using: defaults `internet` and `unauthenticated` create conservative risk assessment, not runtime facts.

`id` must match RiskPatch rules: letters, numbers, dots, underscores, or hyphens, no `..`.

### composer.lock

```bash
python3 scripts/from-composer-lock.py composer.lock >> inventory/stack.yaml
```

### requirements.txt

```bash
python3 scripts/from-requirements.py requirements.txt >> inventory/stack.yaml
```

Lines without `==` are skipped. Remove old `components:` blocks before appending.

### package-lock.json

```bash
python3 scripts/from-package-lock.py package-lock.json >> inventory/stack.yaml
```

Only top-level `dependencies`, not the full transitive tree.

### bun.lock

Bun 1.2+ writes `bun.lock` (text). Binary `bun.lockb` is not supported.

```bash
python3 scripts/from-bun-lock.py bun.lock >> inventory/stack.yaml
```

Then:

```bash
docker compose run --rm watcher riskpatch validate
```

## Offline Mode

Servers without internet cannot reach NVD, OSV, or CIRCL. Pre-fill cache on a networked machine, then copy the `cache/` folder to the server. On the server:

```bash
RISKPATCH_OFFLINE=1
```

In `.env`. This mode uses cache or built-in fixtures (`php`, `nginx`) and marks reports as `stale`. Do not treat offline results as current CVE data.

## Environment

Copy from `.env.example`.

| Variable | Function |
|---|---|
| `NVD_API_KEY` | Used by built-in NVD client. Not via MCP |
| `SHODAN_API_KEY` | Enriches found CVEs: KEV, EPSS, score if missing, exploit count. Not host scanning |
| `ALERT_WEBHOOK_URL` | Optional. Leave empty if not used |
| `LLM_API_KEY` (+ optional `LLM_BASE_URL`, `LLM_MODEL`, `LLM_KILO_MODE`) | Optional. Narrative and AI correlation only. See "LLM / Kilo gateway" |
| `POLL_INTERVAL_SECONDS` | Poll interval, default 21600 (6 hours) |
| `CACHE_TTL_HOURS` | Cache age, default 6 |
| `RISKPATCH_OFFLINE` | `1` to not access network |

Secrets only in `.env`. Do not include in image or reports.

## Systemd

Units are in `deploy/riskpatch.service`. WorkingDirectory defaults to `/opt/riskpatch`. For this repo, install drop-in:

```bash
sudo mkdir -p /etc/systemd/system/riskpatch.service.d
sudo cp deploy/riskpatch.service /etc/systemd/system/riskpatch.service
sudo cp deploy/riskpatch.service.d/override.conf /etc/systemd/system/riskpatch.service.d/override.conf
sudo systemctl daemon-reload
sudo systemctl enable --now riskpatch.service
```

Systemd only manages `docker compose`. Processes inside the container do polling. Entrypoint runs as root briefly to fix volume permissions, then the application drops to user `app` (uid 1000).

## Limitations

- Does not scan hosts or verify mitigations you write in YAML
- Cannot prove reachability from source code
- NVD query currently uses exact CPE if `cpe` is filled. CVEs only recorded as version ranges may be missed when online. Treat online reports as priority help, not complete proof
- Image limited to 512 MB memory and 1 CPU

---

# RiskPatch Server (Phase 1)

CVE intelligence server: FastAPI + SQLite (WAL), one-shot collector ingest, CVE sync every 1 hour, deterministic analysis every 3 hours, web UI, and OpenAPI for Kilo CLI. Deterministic pipeline is used. Phase 2 (Kibana/Loki/DuckDB) not yet available. Orchestration uses your AWX/Tower; this repo only provides collector and example playbooks.

## Run

```bash
cp .env.example .env     # fill RISKPATCH_BOOTSTRAP_TOKEN (random, long) for initial admin token
docker compose up -d api worker     # only ONE worker; do not scale
```

API + UI: `http://127.0.0.1:8080/ui` (sign in with username and password). Install TLS reverse proxy in front for production and set `RISKPATCH_COOKIE_SECURE=1`. OpenAPI: `/api/v1/openapi.json`, Swagger: `/api/v1/docs`.

Token (scopes `read`, `ingest`, `operate`, `admin`; only hash is stored):

```bash
docker compose exec api riskpatch token create --name awx --scopes ingest
docker compose exec api riskpatch token create --name kilo --scopes read,operate
docker compose exec api riskpatch token list|revoke --name kilo
```

Operations: `riskpatch migrate | backup DEST | restore SRC | prune`. Restore: stop api and worker first.

## Collector one-shot (Go, no dependencies)

```bash
cd collector && go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/riskpatch-collector ./cmd/riskpatch-collector
sha256sum bin/riskpatch-collector
```

Token read from stdin (`-token-stdin`) or `RISKPATCH_TOKEN`, not from arguments. URL required `https://` (except `RISKPATCH_ALLOW_HTTP=1` for local testing). Dry-run without upload: `-dry-run`. Collector only runs allowlisted commands (no shell), sanitizes secrets, retries with backoff, exits non-zero if server does not confirm `snapshot_id`. Payload contract: `src/riskpatch/collector_contract.py` (schema_version 1.x, also in OpenAPI).

### Running directly without Ansible

Collector can be run manually on target server. Process runs once, sends one snapshot, prints confirmation `accepted snapshot_id=...`, then terminates.

```bash
# Test collection without upload
./collector/bin/riskpatch-collector \
  -asset-id web-01 \
  -dry-run > snapshot.json

# Direct upload; token does not appear in process arguments
printf '%s\n' "$RISKPATCH_INGEST_TOKEN" | \
  ./collector/bin/riskpatch-collector \
    -url https://riskpatch.example.com \
    -asset-id web-01 \
    -token-stdin \
    -manifests /var/www/app/composer.lock
```

Alternative using environment variable:

```bash
RISKPATCH_TOKEN="$RISKPATCH_INGEST_TOKEN" \
RISKPATCH_EXPOSURE=internet \
RISKPATCH_ENVIRONMENT=production \
./collector/bin/riskpatch-collector \
  -url https://riskpatch.example.com \
  -asset-id web-01
```

For targets with internal CA, use `-ca-file /path/ca-bundle.pem`. For local HTTP testing only, set `RISKPATCH_ALLOW_HTTP=1`; do not use in production. `-self-delete` available if binary is placed as a temporary file and must be deleted after upload.

AWX/Tower: `ansible/collect-and-send.yml` (checksum verification, tempdir 0700, token via stdin + `no_log`, cleanup in `always`). See comments in file for credentials and extra vars.

## Example Kilo CLI / curl

```bash
T="Authorization: Bearer $TOKEN"; B=http://127.0.0.1:8080/api/v1
curl -H "$T" "$B/findings?severity=critical"
curl -H "$T" "$B/search?q=CVE-2024-4577"
curl -H "$T" "$B/aggregations/affected-assets?cve_id=CVE-2024-4577"
curl -H "$T" "$B/aggregations/highest-risk-assets"
curl -H "$T" "$B/changes?since=2026-10-26T00:00:00Z"
curl -XPOST -H "$T" "$B/jobs/analysis/run"      # scope operate
```

## Phase 1 Limitations

- Single node, single SQLite, single worker. PostgreSQL for Phase 3.
- New collector reads `composer.lock` for applications (explicit path); other manifests not yet.
- Collector not yet reading nginx/apache/php-fpm pool configs beyond `php.ini` allowlist directives.
- Binary collector not yet signed; checksum verified by playbook.
- LLM narrative and AI correlation is optional, requires valid Kilo gateway API key, and does not modify verdict. CVE sync requires internet access to NVD/OSV/CISA; without it, data is marked stale.
- Image/SBOM scanning and production host restore testing not yet run.


## LLM / Kilo Gateway and AI Correlation

Optional AI feature and **only for narrative**. Level, action, and status remain from deterministic rules; AI results are never written to `findings` table.

### Required Configuration

You must have a **valid Kilo Gateway API key from your own Kilo account**. This repo does not include keys and has no default keys. Without a valid key, the gateway returns 401 and AI features report `unauthorized` (or `unconfigured` if variable is empty).

Fill in `.env` (see `.env.example`), then restart `api` and `worker`. Key is required only; URL and model have official Kilo Gateway defaults:

```bash
LLM_API_KEY=<Kilo Gateway API key (JWT) from your account>
# defaults, can be overridden:
LLM_BASE_URL=https://ai-gateway.kilo.ai/api/v1
LLM_MODEL=kilo-auto/free
LLM_KILO_MODE=          # optional; sent as x-kilocode-mode header
```

Request: `POST {LLM_BASE_URL}/chat/completions` with `Authorization: Bearer <LLM_API_KEY>`. `GET {LLM_BASE_URL}/models` does not require key. If `LLM_API_KEY` is empty, AI is disabled. Old URL `https://api.kilo.ai/api/gateway` and model `kilo/kilo-auto/free` are wrong and cause 401; remove from `.env`.

Optional: `LLM_CHAT_PATH`, `LLM_TIMEOUT_SECONDS` (default 60), `LLM_MAX_TOKENS` (1500), `LLM_AUTH_HEADER` (`Authorization`), `LLM_AUTH_SCHEME` (`Bearer`).

Safe diagnostics (does not print key): `docker compose exec api riskpatch llm-check` checks `GET /models` and whether model is registered; add `--chat` for a minimal chat request. Exit code 1 on failure.

Error codes are safe: `unauthorized` (401/403), `bad_request` (400/404/422), `payment_required`, `rate_limited`, `timeout`, `network_error`, `redirect`, `bad_response`, `bad_output`. Messages never contain keys or response content; redirects are not followed; 429/5xx/timeout retry once.

### Correlation endpoints

`POST /api/v1/correlations/ai` (scope `operate`, since summary data is sent to third party). Optional body: `{"asset_id": "web-01", "max_findings": 40}`.

```bash
curl -XPOST -H "$T" -H 'Content-Type: application/json' -d '{"asset_id":"web-01"}' "$B/correlations/ai"
```

One request to gateway contains asset, top open findings (highest severity first), and latest report, with reference IDs (`F12` finding, `A1` asset, `R5` report). Response:

- `deterministic`: verdict from DB as-is, CVEs used across multiple assets, and KEV list (calculated in code, not by model).
- `ai.narrative`, `ai.correlations[]` (`claim` + `evidence` with reference IDs), `ai.uncertainty[]`. Claims without valid evidence are dropped (`ai.dropped_claims`).
- `ai.status`: `ok`, `unconfigured`, `error` (with `ai.error.code` and `hint`), or `skipped` (no open findings). `deterministic` section always present.

In UI: **AI Correlation** button on dashboard and asset page. Each call logged in audit (`correlation.ai`, no content). Package names and hostnames from collector treated as untrusted data in prompt, but no guarantee against prompt injection; AI has no path to modify verdict.