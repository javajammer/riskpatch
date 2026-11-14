---
id: REQ-MATCH-001
version: 1.0
status: draft
owner: product
targets:
  - src/riskpatch/match.py
---

# Rules — Version matching

Pencocokan versi paket terhadap rentang CVE. Versi yang tidak bisa di-parse bukan berarti tidak terdampak; hasilnya `None`.

## Requirement

### REQ-MATCH-001 — Versi tidak valid tidak ditebak

**Given** versi atau batas yang tidak bisa di-parse
**When** `in_bound` atau `affected_by_ranges` dipanggil
**Then** hasilnya `None`, bukan `False`

Verifikator: `src/riskpatch/match.py`
Status: draft

### REQ-MATCH-002 — Rentang kosong tidak dianggap aman

**Given** daftar rentang kosong
**When** `affected_by_ranges` dipanggil
**Then** hasilnya `None`

Verifikator: `src/riskpatch/match.py`
Status: draft

### REQ-MATCH-003 — Versi tetap diambil dari batas yang memuat versi terpasang

**Given** rentang yang memuat versi terpasang dan punya `end_excluding`
**When** `derive_fixed_versions` dipanggil
**Then** `end_excluding` dikembalikan sebagai kandidat versi tetap upstream, bukan bukti backport distro

Verifikator: `src/riskpatch/match.py`
Status: draft
