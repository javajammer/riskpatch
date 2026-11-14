---
id: ADR-0004
date: 2026-11-14
status: accepted
deciders: <name>
---

# Admin self-disable guard

## Context

`auth.py:208` (`set_user_disabled`) tidak ada guard untuk mencegah admin terakhir meng-non-aktifkan dirinya sendiri. Ini bisa mengunci diri dari akses admin, dan tidak ada recovery otomatis (kecuali bootstrap admin via env, yang hanya berjalan saat startup).

`active_admin_count` (`auth.py:217`) sudah ada — tinggal dipakai.

## Decision

**Ditunda.** Tidak diimplementasikan sekarang karena:

1. `REQ-SEC-003` sudah di-mark `Status: implemented (tanpa guard)` — ini acknowledgment bahwa celah ada.
2. Perlu keputusan UX: apakah disable self gagal dengan 403, atau soft-warning?
3. Perlu test baru: `test_admin_cannot_disable_self`.

## Consequences

### Positive
- Tidak ada perubahan perilaku yang tidak diinginkan.
- Keputusan UX bisa dibahas terlebih dahulu.

### Negative / costs
- Celah tetap ada sampai diimplementasikan.
- `REQ-SEC-003` status `implemented` sedikit menyesatkan (seharusnya `retired` atau diubah).

### Follow-up
- Fase 2: implementasikan guard + test, update `REQ-SEC-003` status.

## Alternatives

### Implementasikan sekarang (guard 403)
- Kelebihan: keamanan segera.
- Kekurangan: perlu keputusan UX dulu, bisa break existing flow.

### Biarkan seperti ini
- Kelebihan: tidak ada perubahan.
- Kekurangan: celah tetap ada, `REQ-SEC-SEC-003` status menyesatkan.

### Tandai `REQ-SEC-003` sebagai `retired` (dipilih)
- Kelebihan: jelas bahwa guard tidak diimplementasikan, perlu keputusan.
- Kekurangan: spec tidak akurat tentang perilaku saat ini.

**Keputusan akhir:** tandai `REQ-SEC-003` sebagai `retired` dan buat `REQ-SEC-011` untuk guard (status draft), supaya spec akurat tentang perilaku saat ini dan ada follow-up.