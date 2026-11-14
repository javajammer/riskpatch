# Specs — Spec-Driven Development (SDD)

`specs/` adalah **sumber kebenaran normatif** untuk RiskPatch. Setiap perilaku, kontrak, dan aturan non-fungsional harus punya spec di sini sebelum (atau bersamaan dengan) implementasinya.

## Prinsip

1. **Spec-anchored (brownfield).** Spec ditulis dari perilaku yang sudah ada, lalu menjadi gerbang untuk perubahan berikutnya. Tidak ada "spec-as-source" (generate code dari spec) — terlalu mahal untuk repo yang sudah jalan.
2. **Requirement stabil.** ID `REQ-<AREA>-<NNN>` adalah append-only. Pensiunkan dengan `Status: retired`, bukan reuse ID.
3. **Traceability wajib.** Setiap REQ punya minimal satu test yang merujuk ID-nya via `@pytest.mark.req("REQ-...")`. Tanpa test, REQ tidak boleh `Status: implemented`.
4. **Spec hidup bersama kode.** Perubahan perilaku wajib menyertakan diff spec. Perubahan kontrak wajib menyertakan ADR + snapshot OpenAPI.
5. **Normatif vs informatif.** `specs/` normatif. `docs/` informatif (tutorial, mockup, catatan teknis). Jangan duplikat.

## Struktur

```
specs/
  _templates/     template spec (capability, contract, rule, nfr)
  product/        overview, glossary
  capabilities/   satu file per kemampuan
  contracts/      antarmuka yang tidak boleh breaking
  rules/          logika bisnis yang sulit di-reverse-engineer
  nfr/            non-fungsional (security, retention, performance)
  decisions/      ADR
```

## Format requirement

Lihat `specs/_templates/`. Setiap spec punya header YAML:

```yaml
---
id: REQ-<AREA>-<NNN>      # area: product, contract, rule, nfr, capability
version: 1.0
status: implemented       # draft | implemented | retired
owner: <name or team>
targets:                 # file/fungsi/endpoint yang diuji
  - src/riskpatch/collector_contract.py
---
```

## Cara kerja di PR

1. Tulis/ubah spec dulu.
2. Tandai test yang ada dengan `@pytest.mark.req("REQ-...")`, atau tambahkan test baru.
3. Jika kontrak berubah: tambahkan `specs/decisions/ADR-XXXX-*.md` dan perbarui snapshot OpenAPI di `specs/contracts/api-v1.openapi.json`.
4. CI menjalankan `scripts/spec_check.py` (traceability), `scripts/openapi_diff.py` (kontrak), `scripts/spec_lint.py` (format). PR ditolak jika gagal.

## Tools

- `scripts/spec_check.py` — cek traceability REQ ↔ test.
- `scripts/openapi_diff.py` — diff snapshot OpenAPI vs hasil generate.
- `scripts/spec_lint.py` — validasi format spec (header, status, REQ).

## Status awal

| Area | Status |
|---|---|
| `contracts/collector-payload` | implemented (P0) |
| `nfr/security` | implemented (P0) |
| `rules/redaction` | implemented (P0) |
| `contracts/api-v1` | implemented (P1, snapshot) |
| `rules/freshness-state` | implemented (P1) |
| `rules/risk-scoring` | implemented (P1) |
| `rules/matching` | implemented (P1) |
| `capabilities/*` | draft (P2) |
| `nfr/retention`, `nfr/performance` | draft (P3) |
| `decisions/` | implemented (P0, migrasi D1–D9) |