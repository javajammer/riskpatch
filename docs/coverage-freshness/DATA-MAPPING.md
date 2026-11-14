# Coverage & Freshness: data mapping

Source mockup: `docs/mockups/cache-management.dc.html`. Every value below must come from the database or from code/config registries. "NEW" marks data that does not exist yet.

Existing tables used (see `src/riskpatch/migrations/0001_init.sql` to `0010`): `assets`, `snapshots`, `snapshot_facts`, `components`, `cves`, `cve_sources`, `provider_status`, `jobs`, `job_events`, `analysis_runs`, `findings`, `alerts` (with `finding_id` from 0010), `job_schedules`, `system_settings`.

## Header and tabs

| Mockup element | Source | Status |
|---|---|---|
| Page title "Cache management" | Page constant (product name "Coverage & Freshness") | Code constant |
| Subtitle "Freshness, progress, and integrity..." | Page constant, spec subtitle "Cache state, scan progress, and result freshness" | Code constant |
| Sidebar "Cache" item | NAV entry in `ui.py`, label "Coverage" after "Jobs" | Code constant |
| "Invalidate stale" button | `POST /api/freshness/invalidate-stale`, enqueues jobs for entries in `stale`/`failed` | NEW endpoint, uses `jobs.enqueue` |
| "Refresh all" button | `POST /api/freshness/refresh`, enqueues one job per layer target | NEW endpoint, uses `jobs.enqueue` |
| Executive / Technical tabs | URL query `?tab=exec|tech` | UI only |
| "Latest snapshot: ... Nd ago · stale" | `MAX(snapshots.collected_at)` per workspace (same value as Overview "Latest snapshot"), age vs inventory layer TTL | Existing data |
| Mockup amber "Mockup" banner | Removed from product | n/a |

## KPI row (both tabs)

| Mockup card | Source | Status |
|---|---|---|
| Cache health: Healthy / Degraded / Critical, "N of M layers within TTL" | Worst state across `cache_entries` per layer (failed > stale > running > pending > success). Critical if any entry is `failed` with retries exhausted. M = number of registered layers | NEW (`cache_layers`, `cache_entries`) |
| Oldest cached data: "5d", "Inventory snapshot · target 24h" | `now - MIN(refreshed_at)` across entries, subtext = layer name and its `ttl_seconds` | NEW |
| Assets reporting: "0 / 1", "Reporting in the last 24h" | Count of `assets` with activity in last 24h / total assets. Same function as Overview `assets_reporting_24h` (see decision D2) | Existing (`snapshots.received_at`); heartbeat NEW in Phase 3 |
| Findings on stale data: "203" | Count of `findings` with status `open` or in-assessment (alert `status='acknowledged'` via `alerts.finding_id`) whose asset has a stale inventory or stale correlation entry | Existing findings + NEW entry state |

## Cache layers card (both tabs)

Each row: name, detail, state pill, refreshed text, age-versus-TTL bar.

| Layer | Name and detail source | Refreshed text, age, TTL source | Status |
|---|---|---|---|
| Threat intel feeds | Name list from the feed registry (`cve_sources.source`, `provider_status.provider`: NVD, CVE.org, CISA KEV, SentinelOne) | `provider_status.last_success_at`; TTL from `cache_layers.ttl_seconds` (default 6h) | Existing data, state NEW |
| CVE catalog index | `COUNT(*) FROM cves` ("14,471 indexed records") | `MAX(cves.updated_at)`; TTL 6h | Existing data, state NEW |
| Asset inventory snapshot | Count of assets; "1 asset · example-asset" uses `assets.hostname` | `assets.latest_snapshot_id` -> `snapshots.collected_at`; TTL 24h | Existing data, state NEW |
| Correlation results | `COUNT(findings)` open, unverified (`level='unverified'`), KEV (`kev=1`) | `MAX(analysis_runs.finished_at)`; stale when `input_fingerprint` differs or inventory entry is stale | Existing data, fingerprint NEW |

Mockup numbers that are placeholders and must not be copied: "2h ago", "Synced 2h ago", "14,471" (real count comes from the query), "5d / 24h" (computed), "Depends on inventory" (computed label).

## State distribution (Executive tab)

| Mockup element | Source | Status |
|---|---|---|
| Stacked bar and legend with all five states (success, running, stale, pending, failed) | `COUNT(*) FROM cache_entries GROUP BY state`, always returns all five keys (zero included) | NEW |
| Lifecycle sentence | Static text from the state engine definition | Code text |

## Risk card (Executive tab)

| Row | Source | Status |
|---|---|---|
| Findings on stale data | Same as KPI card | NEW entry state |
| Open KEV findings on assets with stale data ("cannot be confirmed present or fixed") | `findings` where `status='open' AND kev=1` joined to assets with stale entries | NEW entry state |
| Unverified findings | `COUNT(findings) WHERE status='open' AND level='unverified'` (matches Overview) | Existing |

Risk text uses the computed numbers. The mockup sentence "5-day-old cache" is computed from the oldest entry age.

## Freshness targets table (Executive tab)

| Column | Source | Status |
|---|---|---|
| Layer | `cache_layers.name` | NEW registry |
| Freshness target | `cache_layers.ttl_seconds`, formatted; "Follows its inputs" for correlation (no fixed TTL) | NEW registry |
| Refreshed by | Code registry: one entry per layer, naming the job type (`cve_sync`, `analysis`, collector heartbeat/inventory) | Code registry |
| Marked stale when | Code registry text per layer, combined with the TTL value | Code registry |

## Refresh jobs table (Technical tab)

| Column | Source | Status |
|---|---|---|
| Job id, layer, target, state, started (UTC), duration, retries | `refresh_jobs` (NEW) or existing `jobs` (see decision D3) | Decision needed |
| Progress percent | `progress_done / progress_total`, only when `progress_total > 0`; otherwise "n/a" | NEW columns |

The mockup's job IDs (J-1046 and similar), durations, and retry counts are illustrative and must not be copied.

## Invalidation triggers table (Technical tab)

| Column | Source | Status |
|---|---|---|
| Trigger, scope, status | Code registry (`freshness/triggers.py`). Status values: Built, Detect only, Not built, Proposed. Status must match real behavior | Code registry |

Expected status at the start of Phase 1 (verified by code): TTL expiry = Detect only (sweep marks stale but does not re-enqueue until Phase 1 ships); New KEV entry = Not built; New or updated CVE = Not built; Inventory change = Not built; Manual refresh = Built after the refresh endpoint and tests exist.

## Gaps and next steps (Technical tab)

| Column | Source | Status |
|---|---|---|
| Capability list with priority P1 or P2 | Code registry (`freshness/capabilities.py`). Each capability has `shipped` and `tested` flags. Only false capabilities are shown | Code registry |

## Reconciliation with Overview (rule 3)

These values must come from the same function used by Overview (`dashboard_stats` in `src/riskpatch/api/app.py`), not a second query:

| Figure | Overview source today |
|---|---|
| Assets monitored | `dashboard_stats["assets"]` |
| Reporting in last 24h | `dashboard_stats["assets_reporting_24h"]` |
| Open findings | `dashboard_stats["findings_open"]` |
| Open KEV findings | `dashboard_stats["kev_findings"]` |
| CVE catalog size | `dashboard_stats["cves"]` |
| Unverified count | `dashboard_stats["findings_by_level"]["unverified"]` |
| Latest snapshot | `dashboard_stats["latest_snapshot_received"]` |

Note: Overview's "Latest snapshot" is `MAX(received_at)`, while the mockup uses inventory `collected_at`. Both must be shown with their label, and the reconciliation test compares the same field.

## Data that does not exist yet (flagged)

- `cache_layers`, `cache_entries`, `cache_state_events`, `refresh_jobs`: NEW (Phase 1).
- `assets.agent_id`, `agent_version`, `last_heartbeat_at`, `inventory_collected_at`, `inventory_hash`, `status`: NEW (Phase 1 columns; populated by Phase 3).
- `inventory_snapshots`: NEW (Phase 1 table; populated by Phase 3 ingest).
- Agent enrollment tokens and per-agent credentials: NEW (Phase 3). Today ingest uses shared API tokens with the `ingest` scope.
- Heartbeat endpoint: NEW (Phase 3). Today the only liveness signal is a snapshot upload.
