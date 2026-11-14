# Changelog

## Unreleased

### Changed: product renamed to RiskPatch (2026-11-13)

Product name: **RiskPatch**. Category: Vulnerability & Patch Management Platform. Tagline: Identify. Prioritize. Remediate.

What changed for existing installations:

- **Command:** `stackwatch` is now `riskpatch` (also inside the containers: `docker compose exec api riskpatch ...`).
- **Image:** `stackwatch:0.2.0` is now `riskpatch:0.2.0`. Rebuild with `docker compose build`.
- **Package:** `src/stackwatch/` is now `src/riskpatch/`. Imports change accordingly.
- **Environment variables:** `RISKPATCH_*` replaces `STACKWATCH_*`. The old names are still read when the new ones are not set, so existing `.env` files keep working. Move them over when convenient.
- **Collector:** `stackwatch-collector` is now `riskpatch-collector`. Rebuild with `scripts/build-collector.sh`. Ansible variables `stackwatch_*` are now `riskpatch_*` (for example `riskpatch_url`, `riskpatch_arch`, `riskpatch_collector_sha256`). Update AWX extra variables and inventory group variables; the playbook does not read the old names.
- **Browser sessions:** the session cookie is now `rp_session`, so users sign in again once after the upgrade. New API tokens start with `rp_`; existing tokens are unaffected.
- **Not renamed on purpose:** the database file `stackwatch.sqlite3` and the volumes `stackwatch-db` and `stackwatch-backups` keep their names, so existing data is found without a copy. Renaming them would need a data migration first.
- **Systemd unit:** `deploy/stackwatch.service` is now `deploy/riskpatch.service`.

Visual identity: sidebar and login page show the RiskPatch mark, wordmark, category and tagline; the browser tab uses the same mark as favicon.

### Added: accounts, roles, and Settings page

- The web UI signs in with a **username and password**. Passwords are hashed with scrypt, and sessions are stored on the server (8 hours). Sign-in attempts are limited to 10 per minute per client address and failures are written to the audit trail.
- Three roles map onto the existing API scopes:
  - `viewer`: read (`read`)
  - `operator`: read and operate (`read`, `operate`)
  - `admin`: all scopes (`read`, `operate`, `ingest`, `admin`)
- **Settings** page (`/ui/settings`):
  - Every user can change their own password. Changing it signs out their other sessions.
  - Admins can create users, change roles, enable or disable accounts, and reset passwords. Admins cannot disable or demote themselves or the last active admin.
  - Admins can create API tokens with a name, a purpose, and scopes. The token value is shown once and never stored in readable form. The token list shows owner, purpose, scopes, creation time, last use, and status, and admins can revoke tokens.
- The first admin is created at startup from `RISKPATCH_BOOTSTRAP_ADMIN_USER` and `RISKPATCH_BOOTSTRAP_ADMIN_PASSWORD`, but only when no admin account exists.
- New CLI command `riskpatch user` with `create`, `list`, and `reset-password`. Passwords are read interactively and never passed as arguments.
- Migration `0012_user_accounts`: adds `users` and `sessions` tables, and `owner_user_id` and `purpose` columns on `api_tokens`. Existing tokens keep working with no owner.

### Added: Coverage, assets, alerts, and remediation (2026-11-12)

- **Coverage & Freshness** page (`/ui/coverage`): cache layers with age against target, state distribution, risk, freshness targets, refresh runs, invalidation triggers, and gaps. Refresh and invalidate actions need operator scope and CSRF. API under `/api/v1/freshness/*`.
- **Background jobs and schedules moved into Coverage** (Technical detail): scheduler status, schedules with Pause, Run now, and Delete (admins), and the job list with pagination and Sync CVE and Run analysis buttons. `/ui/jobs` and `/ui/system` redirect there.
- **Delete assets** (admins only): removes an asset with its snapshots, components, findings, alerts, reports, and coverage state in one transaction. Audited with row counts. Refused while analysis for the asset is queued or running. Available from the Assets list (bulk) and the asset page, and via `POST /api/v1/assets/delete`.
- **Alert Center**: 100 alerts per page with Previous and Next, asset filter, and bulk actions on selected alerts. The dropdown offers Acknowledge (open alerts) and Mark closed (alerts in assessment, one shared evidence note of at least 3 characters). Each action reports how many were skipped.
- **Overview alert metrics** follow the selected period by creation time. Period options added: last 3 months, last 6 months, last 1 year, and all time.
- **Assignee and owner dropdowns** on Work, Campaigns, and asset ownership show active registered accounts. The server refuses names that are not active accounts.
- **Work and Exceptions** are described in README.md ("Work, Campaigns and Exceptions").
- **Collector and image builds for x86_64 and ARM64**: `scripts/build-collector.sh` writes `collector/bin/linux-<arch>/` with checksums. `scripts/build-image.sh` builds the RiskPatch image for one or more platforms. The Ansible playbook picks the binary from `riskpatch_arch`.
- `scripts/generate-ssl.sh` accepts IP addresses and host names as arguments, which become the certificate's Subject Alternative Names. Existing files are backed up first and the key is written with mode 600.
- `riskpatch user` CLI: `create`, `list`, and `reset-password`, for recovery when no admin can sign in.

### Added: database setup and statistics (2026-11-12)

- `scripts/setup-db.sh`: applies migrations, checks the hot indexes, collects statistics, and restarts `api` and `worker`. `--recreate` copies the current database to the backups volume before building an empty one.
- `riskpatch db check` lists hot indexes that are missing. `riskpatch db analyze` collects planner statistics.
- The worker collects planner statistics once a day (first run one day after it starts).

### Fixed (2026-11-12)

- Ingest queued no analysis after a snapshot because it read a settings attribute that does not exist; the error was swallowed. Findings, alerts, and reports now appear after ingest, and failures are logged.
- AI Skills bulk actions (select all, activate, deactivate, delete) did nothing: the inline script was blocked by the Content-Security-Policy. The handlers moved to `app.js`.
- Work table: CVE identifiers wrapped over several lines and made rows very tall. Links in tables no longer wrap.
- Token scope checkboxes stacked vertically when creating a token; they now form a compact row.
- Alert Center was slow on large estates (about 0.6 s on the Open view). The list query sorted every open alert before taking 100; migration `0020_alert_list_index` adds an index that returns them in order. The Open view now takes under a millisecond on the same data.
- Work was slow on the first request after its cache expired (about 1.5 s). The cache now lasts 5 minutes, and the asset count is part of the cache key so deleting an asset still shows at once.
- Login with a token that has no read scope is explained as a scope problem, not as an unknown token. (Token login has since been removed from the web UI; see the accounts section above.)

### Changed

- Web UI sign-in no longer accepts API tokens. Collectors and integrations keep using `Authorization: Bearer <token>` and are not affected.
- Sign-in errors use one generic message ("Invalid username or password") for unknown usernames, wrong passwords, and disabled accounts, so the page does not reveal which usernames exist.

### Upgrade notes

1. Set `RISKPATCH_BOOTSTRAP_ADMIN_USER` and `RISKPATCH_BOOTSTRAP_ADMIN_PASSWORD` in `.env` (password at least 12 characters), or create an admin from the server with `docker compose exec api riskpatch user create --username <name> --role admin`.
2. Rebuild and recreate the `api` container. Migration `0012` runs at startup.
3. Sign in to the UI with the account from step 1. Tokens for collectors do not change.
