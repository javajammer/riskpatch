# Sanitization notes

This copy was prepared for publication. Sensitive values from the working repository were replaced with the placeholders below.

| Placeholder | Meaning | What you need to fill in |
|---|---|---|
| `<TOKEN>` | API token (`rp_…` / `sw_…`) | Create a new one in Settings → API tokens, or with `riskpatch token create` |
| `<PASSWORD>` | Account password | Your own password, or `riskpatch user reset-password` |
| `<SERVER_IP>` | RiskPatch server IP | Your server's IP, for example `192.168.1.10` |
| `<LAN_IP>` | Another IP on the local network | Same as `<SERVER_IP>` if it is the same server |
| `<HOME>` | User home folder | For example `/home/your-user` |
| `<EMAIL>` | Owner email | Your email |
| `<GITHUB_TOKEN>` | GitHub PAT | Do not put it in a file. Use SSH or a credential helper |

## Deliberately not included

- `certs/`: certificates and private keys. Generate your own with `./scripts/generate-ssl.sh <SERVER_IP>` (see `certs/README.md`).
- `.env`, `cookies.txt`: contain credentials. Copy from `.env.example` and set your own values.
- Databases (`*.db`, `*.sqlite3`), `cache/`, `results/`, `reports/`: test results and operational data.
- Session transcripts (`session-*.md`, `2026-*.txt`) and CVE output (`cve-*.txt`, `result.md`).
- `.kilo/`, `.tgrep/`: local editor and tool settings.
- `ubuntu-vuln.sh` and `scripts/collwrap.sh`: scripts that contained tokens or personal paths.
- The old Git history: this copy starts a new repository without `.git`, so tokens that were committed before are not included.

## Before use

- `deploy/stackwatch.service.d/override.conf` uses `<HOME>` in `WorkingDirectory`. Replace it before installing the systemd unit.
- Scripts and documents that mention `<LAN_IP>` are examples only. Replace them with your own IPs.
- Tests have not been run on this copy. Run `uv run pytest` after creating `.env` and `certs/`.

## Additional changes

- The real `inventory/stack.yaml` is not included. Use `stack.example.yaml` as the starting point.
- Personal asset and host names in the mockups were replaced with generic example names (`example-asset`, `example-host`, `example-user`).
