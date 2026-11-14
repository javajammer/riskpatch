---
id: REQ-RETENTION-001
version: 1.0
status: draft
owner: product
targets:
  - src/riskpatch/config.py
  - src/riskpatch/jobs.py
---

# NFR — Retention

Data mentah snapshot tidak disimpan selamanya. Nilai default ada di konfigurasi, bukan di kode halaman.

## Requirement

### REQ-RETENTION-001 — Retensi mentah punya default dan bisa diubah

**Given** `RAW_RETENTION_DAYS` tidak di-set
**When** settings dimuat
**Then** `raw_retention_days` adalah 90

Verifikator: `src/riskpatch/config.py`
Status: draft

### REQ-RETENTION-002 — Data lebih tua dari retensi boleh dipangkas

**Given** snapshot mentah lebih tua dari `raw_retention_days`
**When** job retensi berjalan
**Then** data itu tidak lagi dianggap wajib disimpan

Verifikator: `src/riskpatch/jobs.py`
Status: draft
