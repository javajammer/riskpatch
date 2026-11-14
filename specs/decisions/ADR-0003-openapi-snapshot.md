---
id: ADR-0003
date: 2026-11-14
status: accepted
deciders: <name>
---

# OpenAPI snapshot di `specs/contracts/api-v1.openapi.json`

## Context

API RiskPatch punya ~40 endpoint di `/api/v1`. Kontrak API adalah yang paling rentan terhadap breaking change (client collector, integrasi eksternal). OpenAPI sudah di-host di `/api/v1/openapi.json`, tapi tidak ada snapshot yang di-diff-kan di CI.

## Decision

1. Simpan snapshot OpenAPI di `specs/contracts/api-v1.openapi.json`.
2. CI menjalankan `scripts/openapi_diff.py` — diff snapshot vs hasil generate. Perubahan kontrak → wajib update snapshot di PR yang sama.
3. Perubahan kontrak (schema, route, status code, required field) wajib ADR di `specs/decisions/`.

## Consequences

### Positive
- Breaking change terdeteksi otomatis di CI.
- Kontrak punya versi (snapshot), bisa di-review.
- Client collector (Go) bisa validasi terhadap snapshot.

### Negative / costs
- Snapshot harus di-update setiap perubahan API (overhead kecil).
- Script `openapi_diff.py` perlu maintenance.

### Follow-up
- Fase 2: generate snapshot dari `api/app.py` via `python -c "from riskpatch.api import create_app; ..."`.

## Alternatives

### Tidak ada snapshot
- Kelebihan: tidak ada overhead.
- Kekurangan: breaking change tidak terdeteksi, tidak ada review kontrak.

### Snapshot di CI saja (tanpa commit)
- Kelebihan: tidak ada file snapshot di repo.
- Kekurangan: tidak ada history, tidak bisa di-review di PR.

### Snapshot di repo + diff CI (dipilih)
- Kelebihan: history + review + enforcement.
- Kekurangan: file snapshot di repo (tapi ini adalah kontrak, bukan code).