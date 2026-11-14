---
id: REQ-SEC-001
version: 1.0
status: draft
owner: security
targets:
  - src/riskpatch/auth.py
  - src/riskpatch/api/app.py
---

# Security — Auth, Token, Session, CSRF

## Area

- [x] Security (auth, token, hashing, CSRF, redaction)

## Skema kekuasaan

### Scopes (token API)

`SCOPES = ("read", "ingest", "operate", "admin")`

`IMPLIES`:
- `admin` → semua scope
- `operate` → `operate`, `read`
- `read` → `read`
- `ingest` → `ingest`

### Roles (user UI)

`ROLE_SCOPES`:
- `viewer` → `read`
- `operator` → `read`, `operate`
- `admin` → `read`, `operate`, `admin`

### Session

- Cookie `rp_session`, durasi `SESSION_HOURS = 8`.
- Secret format `rpu_` + 32 byte urlsafe.
- Hash SHA-256 di DB, bukan plaintext.

### Password

- `MIN_PASSWORD_LENGTH = 12`.
- Hash scrypt: `n=2**14, r=8, p=1`, salt 16 byte, dklen 32.
- `_DUMMY_HASH` untuk timing-safe gagal login.

## Requirement

### REQ-SEC-001 — Token tidak bisa dipakai untuk login UI

**Given** token API (kind="token")
**When** request ke route UI
**Then** 401 / redirect login

Verifikator: `auth.py:167` (`authenticate_session` — hanya session, bukan token)
Status: draft

### REQ-SEC-002 — Scope tidak diabaikan

**Given** token dengan scope `read`
**When** POST /api/v1/ingest/snapshots (butuh `ingest`)
**Then** respons 403

Verifikator: `api/app.py:214` (`require("ingest")`)
Status: draft

### REQ-SEC-003 — Admin tidak bisa di-non-aktifkan oleh dirinya sendiri — RETIRED

**Given** admin terakhir yang aktif, mencoba disable dirinya
**When** `set_user_disabled(self, disabled=True)`
**Then** tidak ada penolakan eksplisit di auth.py (tidak ada guard) — **celah, lihat ADR-0004**

Verifikator: `auth.py:208`
Status: retired

> Alasan retired: guard tidak diimplementasikan. Lihat `REQ-SEC-011` untuk rencana implementasi.

### REQ-SEC-004 — Password di-hash, bukan plaintext

**Given** password baru
**When** `create_user` / `set_password`
**Then** `password_hash` berformat `scrypt$N$r$p$<salt_hex>$<digest_hex>`, bukan plaintext

Verifikator: `auth.py:92` (`hash_password`)
Status: draft

### REQ-SEC-005 — Token di-hash di DB

**Given** token plaintext
**When** disimpan
**Then** DB menyimpan `sha256(token)`, bukan plaintext

Verifikator: `auth.py:37` (`hash_token`)
Status: draft

### REQ-SEC-006 — Expired token ditolak

**Given** token dengan `expires_at < now`
**When** `authenticate`
**Then** return None (401)

Verifikator: `auth.py:73`
Status: draft

### REQ-SEC-007 — Revoked token ditolak

**Given** token dengan `revoked_at` di-set
**When** `authenticate`
**Then** return None (401)

Verifikator: `auth.py:71`
Status: draft

### REQ-SEC-008 — Gagal login tidak bocorkan username

**Given** username tidak dikenal
**When** `authenticate_password`
**Then** gunakan `_DUMMY_HASH`, return None, tidak ada perbedaan timing

Verifikator: `auth.py:147` (`_DUMMY_HASH`)
Status: draft

### REQ-SEC-009 — CSRF token di-generate dari session

**Given** session secret
**When** `csrf_for(secret)`
**Then** return HMAC-SHA256(secret_hash, "riskpatch-csrf")[:32], deterministic

Verifikator: `auth.py:41`
Status: draft

### REQ-SEC-010 — Password minimal 12 karakter

**Given** password 11 karakter
**When** `check_password_policy`
**Then** return pesan error, tidak raise

Verifikator: `auth.py:110`
Status: draft

### REQ-SEC-011 — Admin terakhir tidak bisa disable dirinya

**Given** admin terakhir yang aktif
**When** `set_user_disabled(self, disabled=True)`
**Then** raise / 403, tidak ada admin yang di-disable

Verifikator: `auth.py:217` (`active_admin_count`), `tests/test_accounts.py::test_admin_cannot_disable_self_and_reset_signs_out_target`
Status: implemented

> Tautan: ADR-0004. Guard diimplementasikan melalui `active_admin_count`.

## Keputusan (lihat ADR)

- ADR-0004 — Admin self-disable guard (REQ-SEC-003) — **tidak diimplementasikan, perlu keputusan**.