---
id: REQ-<RULE>-000
version: 1.0
status: draft
owner: <team>
targets:
  - src/riskpatch/<module>.py
---

# <Rule Name>

## Jenis aturan

- [ ] Prediksi/scoring
- [ ] Penggabungan/matching
- [ ] Redaction/privasi
- [ ] State machine (TTL/retry/dead-letter)

## Sumber kebenaran

- Kode: `src/riskpatch/<module>.py::<fungsi>`
- Test: `tests/<file>.py`
- Kontrak output: `contracts/<file>.spec.md`

## Requirement

### REQ-<RULE>-001 — <Judul>

**Given** <input>
**When** <fungsi dipanggil>
**Then** <output>

Verifikasi: tests/<file>.py::<test_name>
Status: <draft|implemented|retired>

## Edge case yang diuji

| Input | Ekspektasi | Test |
|---|---|---|
| ... | ... | ... |

## Keputusan (lihat ADR)

- ADR-XXXX-...