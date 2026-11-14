---
id: REQ-<CAPABILITY>-000
version: 1.0
status: draft
owner: <team>
targets:
  - src/riskpatch/<module>.py
---

# <Capability Name>

## Tujuan

Satu paragraf: kemampuan ini melayani aktor mana, dengan alur apa.

## Aktor

- **<Aktor>** — bisa/kapan
- **<Aktor>** — tidak bisa/kapan

## Requirement

### REQ-<CAPABILITY>-001 — <Judul>

**Given** <keadaan awal>
**When** <tindakan>
**Then** <ekspektasi>

Verifikasi: tests/<file>.py::<test_name>
Status: <draft|implemented|retired>

### REQ-<CAPABILITY>-002 — <Judul>

...

## Kontrak yang dipengaruhi

- `contracts/<file>.spec.md` (REQ-...)
- `contracts/api-v1.spec.md` (REQ-...)

## Keputusan (lihat ADR)

- ADR-XXXX-...