#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def safe_id(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in name.lower())
    cleaned = cleaned.strip("-.")
    return cleaned[:64] or "pkg"


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "composer.lock")
    data = json.loads(path.read_text(encoding="utf-8"))
    packages = data.get("packages") or data.get("installed") or []
    for item in packages:
        name = item.get("name")
        version = str(item.get("version") or "").lstrip("v")
        if not name or not version:
            continue
        print(
            f"""  - id: {safe_id(name)}
    name: {name}
    version: "{version}"
    ecosystem: Packagist
    product: {name}
    role: library
    exposure: unknown
    auth_boundary: unknown
    used_at_runtime: true
    mitigations: []
    distro_package: ""
    notes: "dari composer.lock; periksa exposure dan auth"
"""
        )


if __name__ == "__main__":
    main()
