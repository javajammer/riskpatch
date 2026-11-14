---
id: REQ-FRESHSTATE-001
version: 1.0
status: draft
owner: product
targets:
  - src/riskpatch/freshness.py
---

# Rules — Freshness State Machine

## Jenis aturan

- [x] State machine (TTL/retry/dead-letter)

## Sumber kebenaran

- Kode: `src/riskpatch/freshness.py`
- Test: `tests/test_freshness.py`

## State

`success` → `stale` (TTL expired) → `running` (job di-enqueue) → `success` / `failed` (retry habis → dead-letter)

## Requirement

### REQ-FRESHSTATE-001 — TTL expiry detection

**Given** entry dengan `refreshed_at + ttl < now`
**When** state dihitung
**Then** state = stale

Verifikator: `freshness.py` (TTL comparison)
Status: draft

### REQ-FRESHSTATE-002 — Retry max 3

**Given** job gagal
**When** retry dihitung
**Then** max_retries = 3 (sama dengan `jobs.MAX_ATTEMPTS`)

Verifikator: `freshness.py` (D7)
Status: draft

### REQ-FRESHSTATE-003 — Backoff exponential

**Given** attempt ke-N gagal
**When** backoff dihitung
**Then** `base * 2^attempt`, base = 60s, cap 1h

Verifikator: `freshness.py` (D7)
Status: draft

### REQ-FRESHSTATE-004 — Dead-letter

**Given** retries habis
**When** job selesai
**Then** `dead_lettered = 1`, entry state = failed

Verifikator: `freshness.py` (D7)
Status: draft

### REQ-FRESHSTATE-005 — Injectable clock

**Given** `now_fn` parameter
**When** TTL comparison
**Then** gunakan `now_fn`, bukan `datetime.now()`

Verifikator: `freshness.py` (D6)
Status: draft

### REQ-FRESHSTATE-006 — Test gunakan fake clock

**Given** test freshness
**When** TTL comparison
**Then** gunakan fake clock, tidak bergantung pada real time

Verifikator: `tests/test_freshness.py` (D6)
Status: draft

## Edge case yang diuji

| Input | Ekspektasi | Test |
|---|---|---|
| entry fresh | state = success | `test_freshness.py` |
| entry TTL expired | state = stale | `test_freshness.py` |
| entry running | state = running | `test_freshness.py` |
| entry failed + retries habis | state = failed, dead-lettered | `test_freshness.py` |