---
id: REQ-GLOSSARY-001
version: 1.0
status: draft
owner: product
targets:
  - README.md
---

# Product — Glossary

## Istilah

| Istilah | Arti |
|---|---|
| **Asset** | Server/host yang dipantau (asset_id, hostname, environment, exposure). |
| **Snapshot** | Hasil collector satu kali jalan (facts: os, packages, services, listeners, applications, exposure). |
| **Finding** | Hasil analisis snapshot vs rules (CVE, severity, action). |
| **Alert** | Finding yang di-highlight (status: open, acknowledged, closed). |
| **Campaign** | Kelompok finding terkait (misalnya exploit kit). |
| **Work item** | Tugas manual/operator (create, assign, complete). |
| **Coverage / Freshness** | Keadaan cache layer (TTL, state, retry). Lihat `specs/capabilities/freshness.spec.md`. |
| **Layer** | Sumber data yang di-cache (threat intel feeds, CVE catalog index, asset inventory snapshot, correlation results). |
| **Scope** | Hak akses token API: `read`, `ingest`, `operate`, `admin`. |
| **Role** | Hak akses user UI: `viewer`, `operator`, `admin`. |
| **Session** | Login UI (cookie `rp_session`, 8 jam). |
| **Token** | API token (prefix `rp_`), hash SHA-256 di DB. |
| **Bootstrap admin** | Admin pertama dibuat dari env `RISKPATCH_BOOTSTRAP_ADMIN_USER` + `PASSWORD`. |

Istilah di atas adalah definisi, bukan requirement. Requirement produk ada di `overview.spec.md`.