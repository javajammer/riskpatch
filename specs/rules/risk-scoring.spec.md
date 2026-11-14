---
id: REQ-RISK-001
version: 1.0
status: draft
owner: product
targets:
  - src/riskpatch/risk.py
---

# Rules — Risk scoring

Skor prioritas adalah jumlah alasan yang terlihat, bukan angka tersembunyi. Bukan CVSS saja. Bobot hanya boleh diubah bersama `RISK_VERSION`.

## Requirement

### REQ-RISK-001 — Setiap poin punya label

**Given** sebuah finding dengan level, KEV, exposure, tier, fix, umur, dan status verifikasi
**When** `risk.score` dipanggil
**Then** hasil berisi `points`, `band`, dan `reasons` yang menjelaskan setiap poin

Verifikator: `src/riskpatch/risk.py`
Status: draft

### REQ-RISK-002 — Band mengikuti ambang

**Given** total poin setelah clamp 0–100
**When** band dipilih
**Then** P1 jika >= 80, P2 jika >= 60, P3 jika >= 35, selain itu P4

Verifikator: `src/riskpatch/risk.py`
Status: draft

### REQ-RISK-003 — Versi skor ikut hasil

**Given** skor dihitung
**When** hasil dikembalikan
**Then** `version` sama dengan `RISK_VERSION` saat ini (`1`)

Verifikator: `src/riskpatch/risk.py`
Status: draft
