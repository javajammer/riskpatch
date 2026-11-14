---
id: REQ-REDACT-001
version: 1.0
status: draft
owner: security
targets:
  - src/riskpatch/redact.py
  - collector/internal/collect/redact.go
---

# Rules — Redaction (Privasi)

## Jenis aturan

- [x] Redaction/privasi

## Sumber kebenaran

- Kode: `src/riskpatch/redact.py` (Python), `collector/internal/collect/redact.go` (Go).
- Test: `tests/test_safety.py`, `collector/internal/collect/collect_test.go`.

## Pola yang di-redact

```regex
-----BEGIN [A-Z ]*PRIVATE KEY-----   # private key blocks
AKIA[0-9A-Z]{16}                    # AWS access key
ghp_[A-Za-z0-9]{20,}                # GitHub PAT
xox[baprs]-[A-Za-z0-9-]{10,}        # Slack token
sw_[A-Za-z0-9_-]{20,}               # RiskPatch ingest token
eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}  # JWT
```

## Requirement

### REQ-REDACT-001 — Private key di-redact

**Given** teks mengandung `-----BEGIN RSA PRIVATE KEY----- ... END`
**When** `RedactText` dipanggil
**Then** bagian key diganti `[REDACTED]`, tidak ada isi key yang tersisa

Verifikator: `redact.py`, `redact.go`
Status: draft

### REQ-REDACT-002 — AWS access key di-redact

**Given** teks mengandung `AKIAABCDEFGHIJKLMNOP`
**When** `RedactText` dipanggil
**Then** di-redact, tidak ada `AKIA` yang tersisa

Verifikator: `collect_test.go:14` (`AKIAABCDEFGHIJKLMNOP`)
Status: draft

### REQ-REDACT-003 — Connection string password di-redact

**Given** teks mengandung `mysql://root:pw@host/db`
**When** `RedactText` dipanggil
**Then** `pw@` di-redact, tidak ada password yang tersisa

Verifikator: `collect_test.go:14` (`mysql://root:pw@host/db`)
Status: draft

### REQ-REDACT-004 — api_key= di-redact

**Given** teks mengandung `api_key=abcdef`
**When** `RedactText` dipanggil
**Then** `abcdef` di-redact

Verifikator: `collect_test.go:14` (`api_key=abcdef`)
Status: draft

### REQ-REDACT-005 — Tidak ada leak pada test fixture

**Given** test fixture `mysql://root:pw@host/db`, `api_key=abcdef`, `AKIAABCDEFGHIJKLMNOP`
**When** `RedactText` dipanggil
**Then** tidak ada `pw@`, `abcdef`, atau `AKIA` dalam output

Verifikator: `collect_test.go:15` (`t.Fatalf("leak: %s", out)`)
Status: draft

## Edge case yang diuji

| Input | Ekspektasi | Test |
|---|---|---|
| `mysql://root:pw@host/db` | password di-redact | `collect_test.go:14` |
| `api_key=abcdef` | value di-redact | `collect_test.go:14` |
| `AKIAABCDEFGHIJKLMNOP` | di-redact | `collect_test.go:14` |
| teks normal (tanpa credential) | tidak berubah | (implied) |