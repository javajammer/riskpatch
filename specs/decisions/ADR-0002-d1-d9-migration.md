---
id: ADR-0002
date: 2026-11-14
status: accepted
deciders: <name>
---

# Migrasi D1–D9 (Coverage & Freshness) ke `specs/`

## Context

`docs/coverage-freshness/PLAN.md` dan `DATA-MAPPING.md` sudah pakai pola SDD (keputusan D1–D9, tabel traceability, verification plan). Tapi file-file itu di `docs/` (informatif), bukan `specs/` (normatif), dan tidak punya requirement ID yang stabil.

## Decision

Pindahkan D1–D9 ke `specs/decisions/` sebagai ADR, dan buat `specs/capabilities/freshness.spec.md` + `specs/rules/freshness-state.spec.md` dengan requirement ID.

## Consequences

### Positive
- Keputusan D1–D9 punya ID stabil, bisa dirujuk test.
- `PLAN.md` tetap di `docs/` sebagai catatan proyek (informatif), `specs/` yang normatif.
- Pola ini jadi contoh (golden example) cara menulis spec di repo.

### Negative / costs
- Duplikasi kecil antara `PLAN.md` dan `specs/` (dipisahkan: PLAN = catatan proyek, spec = normatif).

### Follow-up
- Fase 2: tambahkan `@pytest.mark.req` ke test freshness yang ada.
- Fase 3: `spec_check.py` memverifikasi REQ freshness punya test.

## Alternatives

### Biarkan di `docs/`
- Kelebihan: tidak ada migrasi.
- Kekurangan: tidak ada requirement ID, tidak ada traceability, tidak ada enforcement.

### Pindahkan semua ke `specs/`
- Kelebihan: konsisten.
- Kekurangan: `PLAN.md` berisi keputusan proyek + rencana fase, bukan spec murni — tetap lebih cocok di `docs/`.

### Pindahkan keputusan ke `specs/`, biarkan rencana di `docs/` (dipilih)
- Kelebihan: keputusan normatif di spec, rencana informatif di docs.
- Kekurangan: sedikit split, perlu dokumentasi batas.