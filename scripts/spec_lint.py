#!/usr/bin/env python3
"""Spec lint: validate format of every spec file.

Checks:
1. Every .spec.md has a YAML front-matter with id, version, status, owner.
2. status is one of: draft, implemented, retired.
3. Every REQ-* block has a Verifikator line.
4. No duplicate REQ IDs across specs.

Exit non-zero on failure.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPECS = ROOT / "specs"

ID_RE = re.compile(r"^id:\s*(REQ-[A-Z]+-\d+)\s*$", re.MULTILINE)
STATUS_RE = re.compile(r"^status:\s*(\w+)\s*$", re.MULTILINE)
OWNER_RE = re.compile(r"^owner:\s*(\S+)\s*$", re.MULTILINE)
VERSION_RE = re.compile(r"^version:\s*(\S+)\s*$", re.MULTILINE)
VALID_STATUS = {"draft", "implemented", "retired"}
REQ_HEADER_RE = re.compile(r"^### (REQ-[A-Z]+-\d+)\s", re.MULTILINE)
VERIF_RE = re.compile(r"^Verifikator:", re.MULTILINE)


def lint_file(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")

    # Skip templates and ADRs (different format)
    if path.name.startswith("_") or path.parent.name == "decisions":
        return errors

    # Skip templates (path contains _templates)
    if "_templates" in path.parts:
        return errors

    m = ID_RE.search(text)
    if not m:
        errors.append(f"{path}: missing 'id:' in front-matter")
        return errors

    m = STATUS_RE.search(text)
    if not m or m.group(1) not in VALID_STATUS:
        errors.append(f"{path}: invalid or missing 'status:' ({m.group(1) if m else None})")

    if not OWNER_RE.search(text):
        errors.append(f"{path}: missing 'owner:'")

    if not VERSION_RE.search(text):
        errors.append(f"{path}: missing 'version:'")

    # Every REQ header must have a Verifikator line
    for req_match in REQ_HEADER_RE.finditer(text):
        req = req_match.group(1)
        # Look for Verifikator after this REQ header until next REQ header or EOF
        rest = text[req_match.end():]
        next_req = REQ_HEADER_RE.search(rest)
        block = rest[: next_req.start()] if next_req else rest
        if not VERIF_RE.search(block):
            errors.append(f"{path}: {req} missing 'Verifikator:' line")

    return errors


def main() -> int:
    all_errors: list[str] = []
    seen_ids: dict[str, str] = {}

    for path in sorted(SPECS.rglob("*.spec.md")):
        errs = lint_file(path)
        all_errors.extend(errs)
        # Track duplicates
        text = path.read_text(encoding="utf-8")
        for m in ID_RE.finditer(text):
            rid = m.group(1)
            if rid in seen_ids:
                all_errors.append(
                    f"{path}: duplicate REQ id {rid} (also in {seen_ids[rid]})"
                )
            seen_ids[rid] = str(path)

    if all_errors:
        print("FAIL spec lint:")
        for e in all_errors:
            print(f"  - {e}")
        return 1

    print(f"OK: {len(list(SPECS.rglob('*.spec.md')))} spec file(s) linted")
    return 0


if __name__ == "__main__":
    sys.exit(main())