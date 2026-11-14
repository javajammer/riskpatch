#!/usr/bin/env python3
import sys
from pathlib import Path


def safe_id(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in name.lower())
    return cleaned.strip("-.")[:64] or "pkg"


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "requirements.txt")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if "==" not in line:
            continue
        name, version = line.split("==", 1)
        name = name.strip()
        version = version.strip().split(";")[0].strip()
        if not name or not version:
            continue
        print(
            f"""  - id: {safe_id(name)}
    name: {name}
    version: "{version}"
    ecosystem: PyPI
    product: {name}
    role: library
    exposure: unknown
    auth_boundary: unknown
    used_at_runtime: true
    mitigations: []
    distro_package: ""
    notes: "dari requirements.txt; periksa exposure dan auth"
"""
        )


if __name__ == "__main__":
    main()
