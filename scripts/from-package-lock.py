#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def safe_id(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in name.lower())
    return cleaned.strip("-.")[:64] or "pkg"


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "package-lock.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    deps = data.get("dependencies") or {}
    if not deps and "packages" in data:
        deps = {
            key.removeprefix("node_modules/"): value
            for key, value in data["packages"].items()
            if key.startswith("node_modules/") and key.count("node_modules/") == 1 and isinstance(value, dict)
        }
    for name, item in deps.items():
        if not isinstance(item, dict):
            continue
        version = str(item.get("version") or "")
        if not name or not version or name.startswith("node_modules/"):
            continue
        print(
            f"""  - id: {safe_id(name)}
    name: {name}
    version: "{version}"
    ecosystem: npm
    product: {name}
    role: library
    exposure: unknown
    auth_boundary: unknown
    used_at_runtime: true
    mitigations: []
    distro_package: ""
    notes: "dari package-lock.json; periksa exposure dan auth"
"""
        )


if __name__ == "__main__":
    main()
