---
id: REQ-FRESH-001
version: 1.0
status: draft
owner: product
targets:
  - src/riskpatch/freshness.py
  - src/riskpatch/api/app.py
---

# Capability — Coverage & Freshness

## Tujuan

Menampilkan state cache layer (threat intel feeds, CVE catalog index, asset inventory snapshot, correlation results) dan memungkinkan operator refresh / invalidate stale.

## Aktor

- **Operator** — POST /api/freshness/refresh, POST /api/freshness/invalidate-stale.
- **Viewer** — GET /api/freshness/summary, /layers, /jobs, /triggers, /gaps.

## Routes

| Method | Path | Scope | Deskripsi |
|---|---|---|---|
| GET | `/api/v1/freshness/summary` | read | Ringkasan state layer |
| GET | `/api/v1/freshness/layers` | read | Detail layer + state pill |
| GET | `/api/v1/freshness/jobs` | read | Daftar refresh job |
| GET | `/api/v1/freshness/triggers` | read | Trigger invalidation status |
| GET | `/api/v1/freshness/gaps` | read | Gaps dan next steps |
| POST | `/api/v1/freshness/refresh` | operate | Enqueue refresh job |
| POST | `/api/v1/freshness/invalidate-stale` | operate | Enqueue invalidate job |

## Requirement

### REQ-FRESH-001 — Layer registry

**Given** registry di code
**When** `/api/v1/freshness/layers`
**Then** return 4 layer: threat intel feeds, CVE catalog index, asset inventory snapshot, correlation results

Verifikator: `freshness.py` (registry)
Status: draft

### REQ-FRESH-002 — State aggregation

**Given** cache_entries untuk satu layer
**When** aggregate state
**Then** worst state: failed > stale > running > pending > success

Verifikator: `freshness.py`
Status: draft

### REQ-FRESH-003 — Critical state

**Given** entry `failed` dengan retries habis
**When** aggregate
**Then** layer state = critical

Verifikator: `freshness.py`
Status: draft

### REQ-FRESH-004 — Refresh job idempotent

**Given** POST /api/freshness/refresh untuk layer X
**When** dipanggil dua kali
**Then** tidak ada job duplicate untuk target yang sama

Verifikator: `jobs.enqueue` (dedupe)
Status: draft

### REQ-FRESH-005 — Audit event per POST

**Given** POST /api/freshness/refresh
**When** job di-enqueue
**Then** audit event tercatat

Verifikator: `api/app.py` (audit)
Status: draft

### REQ-FRESH-006 — Read-only user dapat baca, tidak bisa POST

**Given** token scope `read`
**When** POST /api/freshness/refresh
**Then** 403

Verifikator: `api/app.py:510` (`require("operate")`)
Status: draft

## Keputusan (lihat ADR)

- ADR-0002 — migrasi D1–D9.
- D2 — `assets_reporting(conn, ws, now)` shared function.
- D3 — `refresh_jobs` table.
- D4 — layer registry + `cache_layers` table.
- D5 — `cache_entries` seeded from registry.
- D6 — injectable clock `now_fn`.
- D7 — retry policy (max 3, backoff 60s * 2^attempt, cap 1h).
- D8 — invalidation triggers.
- D9 — capabilities `shipped` / `tested` flags.