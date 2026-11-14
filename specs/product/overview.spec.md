---
id: REQ-PRODUCT-001
version: 1.0
status: draft
owner: product
targets:
  - README.md
  - src/riskpatch/cli.py
---

# Product — Overview

## Tujuan

RiskPatch adalah platform Vulnerability & Patch Management. Tagline: **Identify. Prioritize. Remediate.**

Melayani operator (admin/operator) dan viewer untuk mengelola asset, snapshot, CVE, finding, alert, dan freshness data.

## Aktor

- **Admin** — semua scope (`read`, `ingest`, `operate`, `admin`). Bisa create user, manage token, delete asset.
- **Operator** — `read`, `operate`. Bisa run job, refresh freshness, patch asset, acknowledge alert.
- **Viewer** — `read`. Bisa baca dashboards, findings, alerts, coverage. Tidak bisa POST.
- **Collector (eksternal)** — `ingest`. Kirim snapshot via POST /api/v1/ingest/snapshots.

## Requirement

### REQ-PRODUCT-001 — Product name dan command

**Given** instalasi baru
**When** `riskpatch --help`
**Then** command `riskpatch` (bukan `stackwatch`), image `riskpatch:0.2.0`, package `src/riskpatch/`

Verifikator: `pyproject.toml` (`riskpatch = "riskpatch.cli:main"`), `CHANGELOG.md`
Status: draft

### REQ-PRODUCT-002 — Environment variable prefix

**Given** `.env` file
**When** settings di-load
**Then** prefix `RISKPATCH_*` (baca `STACKWATCH_*` sebagai fallback)

Verifikator: `src/riskpatch/config.py`
Status: draft

### REQ-PRODUCT-003 — Schema version collector

**Given** payload collector
**When** POST /api/v1/ingest/snapshots
**Then** `schema_version` major harus `1`

Verifikator: `src/riskpatch/collector_contract.py:9` (`SUPPORTED_MAJOR = "1"`)
Status: draft