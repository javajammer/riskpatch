---
id: REQ-CONTRACT-001
version: 1.0
status: draft
owner: security
targets:
  - src/riskpatch/collector_contract.py
  - collector/internal/collect/collect.go
---

# Kontrak Payload Collector — `schema_version` 1.x

## Jenis kontrak

- [x] Payload collector (eksternal, breaking = collector mati)
- [ ] API response/request
- [ ] Data schema
- [ ] Kompatibilitas versi

## Versi

- **Saat ini:** `1.x` (`SUPPORTED_MAJOR = "1"`)
- **Major yang didukung:** `1`
- **Aturan kompatibilitas:**
  - **Additive:** tambah field opsional → minor bump, tidak breaking.
  - **Breaking:** hapus/ubah field wajib, ubah tipe, ubah makna → major bump + ADR + snapshot baru.
  - Field opsional yang diabaikan (`extra="ignore"`) bisa dihapus tanpa breaking.

## Skema

```yaml
schema_version: str          # wajib, max 16 char, major == "1"
asset_id: str                # wajib, regex [A-Za-z0-9][A-Za-z0-9._-]{0,127}, tanpa ".."
collected_at: datetime       # wajib, wajib punya tzinfo (UTC setelah normalize)
collector_version: str       # opsional, max 64
facts:
  os:
    name: str               # default ""
    version: str            # default ""
    id_like: str            # default ""
    kernel: str             # default ""
    arch: str               # default ""
  hostname: str            # default "", max 253
  runtimes: list[Runtime]  # max 500
  packages: list[Package]  # max 30000
  services: list[Service]  # max 2000
  listening_ports: list[Listener]  # max 2000
  modules: list[str]       # max 2000
  config_facts: list[ConfigFact]  # max 5000
  applications: list[Application]  # max 20000
  exposure:
    exposure: str           # enum internet|internal|vpn|localhost|unknown, default unknown
    environment: str        # default unknown, max 32
    auth_boundary: str      # enum unauthenticated|authenticated|admin|unknown, default unknown
    mitigations: list[str]  # max 50
    labels: dict[str,str]
errors: list[str]            # max 200
```

## Requirement

### REQ-CONTRACT-001 — Major version harus didukung

**Given** payload dengan `schema_version = "2.0.0"`
**When** POST /api/v1/ingest/snapshots
**Then** respons 422 dengan `schema_version unsupported, need 1.x`

Verifikator: `collector_contract.py:96` (`SnapshotIn.major`)
Status: draft

### REQ-CONTRACT-002 — asset_id harus valid

**Given** payload dengan `asset_id = "..evil"` atau `asset_id = "-bad"`
**When** POST /api/v1/ingest/snapshots
**Then** respons 422, `asset_id only letters, digits, dot, underscore, or hyphen`

Verifikator: `collector_contract.py:103` (`SnapshotIn.asset`)
Status: draft

### REQ-CONTRACT-003 — collected_at harus berzona

**Given** payload dengan `collected_at` tanpa tzinfo
**When** POST /api/v1/ingest/snapshots
**Then** respons 422, `collected_at must use timezone`; jika ada tzinfo, di-normalize ke UTC

Verifikator: `collector_contract.py:110` (`SnapshotIn.utc`)
Status: draft

### REQ-CONTRACT-004 — Field tidak dikenal diabaikan

**Given** payload dengan field tambahan `{"_hacked": true}`
**When** payload divalidasi
**Then** field diabaikan, tidak ada error 422

Verifikator: `collector_contract.py:15` (`_Base.model_config = ConfigDict(extra="ignore")`)
Status: draft

### REQ-CONTRACT-005 — Payload dengan field wajib kosong ditolak

**Given** payload tanpa `asset_id` atau `collected_at`
**When** POST /api/v1/ingest/snapshots
**Then** respons 422 (Pydantic required)

Verifikator: `collector_contract.py:88` (`SnapshotIn`)
Status: draft

## Snapshot

Tidak ada snapshot (kontrak tidak punya file statis). Sumber kebenaran: `collector_contract.py` + OpenAPI `/api/v1/openapi.json` (route `/api/v1/ingest/snapshots`).