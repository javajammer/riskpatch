---
id: REQ-<CONTRACT>-000
version: 1.0
status: draft
owner: <team>
targets:
  - src/riskpatch/<module>.py
---

# <Contract Name>

## Jenis kontrak

- [ ] Payload collector (eksternal, breaking = collector mati)
- [ ] API response/request (OpenAPI di `/api/v1/openapi.json`)
- [ ] Data schema (DB, file, env)
- [ ] Kompatibilitas versi

## Versi

- **Saat ini:** `<version>`
- **Mayor yang didukung:** `<major>`
- **Aturan kompatibilitas:**
  - **Additive:** tambah field opsional → minor bump, tidak breaking.
  - **Breaking:** hapus/ubah field wajib, ubah tipe, ubah makna → major bump + ADR + snapshot baru.
  - Field opsional yang diabaikan (`extra="ignore"`) bisa dihapus tanpa breaking.

## Skema

```yaml
# contoh
field: type  # constraint
```

## Requirement

### REQ-<CONTRACT>-001 — <Judul>

**Given** ...
**When** ...
**Then** ...

Verifikasi: tests/<file>.py::<test_name>
Status: <draft|implemented|retired>

## Snapshot

Jika kontrak punya snapshot (misalnya OpenAPI), simpan di `specs/contracts/<name>.<ext>` dan diff-kan di CI via `scripts/openapi_diff.py`.