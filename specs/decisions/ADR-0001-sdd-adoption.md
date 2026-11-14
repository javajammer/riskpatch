---
id: ADR-0001
date: 2026-11-14
status: accepted
deciders: <name>
---

# SDD adoption: spec-anchored brownfield

## Context

Repo RiskPatch sudah jalan: Python/FastAPI + SQLite (20 migrasi), ~50 modul, 19 file test, Go collector, ~40 endpoint REST. Dokumentasi ada tapi ad-hoc (`README.md` 48KB, `TODO.md` 30KB`, `docs/coverage-freshness/PLAN.md` + `DATA-MAPPING.md`).

`docs/coverage-freshness/` sudah pakai pola SDD (keputusan D1–D9, tabel data-mapping, verification plan), tapi pola itu tidak konsisten di seluruh repo. Tanpa standar, spec akan basi dan tidak ada enforcement.

## Decision

Adopsi **spec-anchored SDD** (bukan spec-as-source):

1. Buat `specs/` terpisah dari `docs/` (normatif vs informatif).
2. Setiap spec punya requirement ID stabil (`REQ-<AREA>-<NNN>`), append-only.
3. Setiap REQ wajib punya test yang merujuk ID via `@pytest.mark.req`.
4. Spec adalah gerbang untuk perubahan berikutnya (spec dulu, baru kode).
5. Perubahan kontrak wajib ADR + snapshot OpenAPI.
6. CI: `scripts/spec_check.py`, `scripts/openapi_diff.py`, `scripts/spec_lint.py`.

## Consequences

### Positive
- Traceability REQ → test → code, bisa di-check otomatis.
- Perubahan perilaku harus diff spec → review lebih ketat.
- Onboarding lebih mudan (baca spec, bukan code).
- Pola D1–D9 di `PLAN.md` bisa diformalkan ke `specs/decisions/`.

### Negative / costs
- Overhead menulis spec untuk setiap perubahan.
- Risiko spec basi jika tidak dijaga (dipantau via `Status: implemented` only di PR yang sama dengan code + test).
- Perlu maintenance script CI.

### Follow-up
- Fase 1: P0 spec (collector payload, security, redaction) — sudah dibuat.
- Fase 2: P1 (risk scoring, matching, freshness state, api-v1 snapshot).
- Fase 3: P2 capabilities, `spec_check.py` blocking.
- Fase 4: gerbang penuh, `README.md`/`TODO.md` dipisahkan.

## Alternatives yang dipertimbangkan

### Spec-as-source (generate code dari spec)
- Kelebihan: tidak ada spec basi, code selalu sinkron.
- Kekurangan: terlalu mahal untuk repo yang sudah jalan, tooling berat, collector Go tidak bisa di-generate dari Python spec.

### Dokumentasi biasa (status quo)
- Kelebihan: tidak ada overhead.
- Kekurangan: tidak ada traceability, tidak ada enforcement, spec mudah basi, tidak ada gerbang review.

### Spec-anchored (dipilih)
- Kelebihan: incremental, cocok brownfield, enforcement bisa di-naikkan bertahap.
- Kekurangan: tetap butuh disiplin menjaga spec tetap update.