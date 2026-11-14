#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def safe_id(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in name.lower())
    return cleaned.strip("-.")[:64] or "pkg"


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "bun.lock")
    if path.suffix == ".lockb":
        raise SystemExit("bun.lockb biner tidak didukung; pakai bun.lock")
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        data = json.loads(text[start:])
    packages = data.get("packages") or data.get("dependencies") or {}
    if isinstance(packages, dict):
        items = packages.items()
    else:
        items = []
    for name, item in items:
        version = ""
        if isinstance(item, str):
            version = item
        elif isinstance(item, list) and item:
            version = str(item[0])
        elif isinstance(item, dict):
            version = str(item.get("version") or "")
        version = version.lstrip("v").split("@")[-1] if version.startswith("npm:") else version.lstrip("v")
        if not name or not version or name in {".", ""}:
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
    notes: "dari bun.lock; periksa exposure dan auth"
"""
        )


if __name__ == "__main__":
    main()
