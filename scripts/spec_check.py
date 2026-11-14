#!/usr/bin/env python3
"""Traceability gate: every REQ must have a test that references it.

Checks:
1. Every REQ-* ID declared in specs/ must be referenced by at least one
   @pytest.mark.req("REQ-...") marker in tests/.
2. Every @pytest.mark.req marker must reference an ID that exists in specs/.
3. No REQ with Status: implemented may lack a test.

Exit non-zero on failure.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPECS = ROOT / "specs"
TESTS = ROOT / "tests"

HEADING_RE = re.compile(r"^### (REQ-[A-Z0-9]+-\d+)\b.*$", re.MULTILINE)
STATUS_LINE_RE = re.compile(r"^Status:\s*(\w+)", re.MULTILINE)
MARKER_RE = re.compile(r'@pytest\.mark\.req\(\s*"([^"]+)"')
MARKER_RE2 = re.compile(r'@pytest\.mark\.req\(\s*\'([^\']+)\'')
PY_RE = re.compile(r"@pytest\.mark\.req")


def load_specs() -> tuple[dict[str, str], list[str]]:
    """Return {req_id: status} from each ### REQ heading, plus duplicate errors."""
    ids: dict[str, str] = {}
    errors: list[str] = []
    for path in SPECS.rglob("*.spec.md"):
        if "_templates" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        matches = list(HEADING_RE.finditer(text))
        for index, match in enumerate(matches):
            req = match.group(1)
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            block = text[match.end():end]
            status_match = STATUS_LINE_RE.search(block)
            status = status_match.group(1) if status_match else "draft"
            if req in ids:
                errors.append(f"{req}: declared in more than one spec")
                continue
            ids[req] = status
    return ids, errors


def load_markers() -> set[str]:
    """Return set of REQ IDs referenced by @pytest.mark.req in tests/."""
    refs: set[str] = set()
    for path in TESTS.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for m in MARKER_RE.findall(text):
            refs.add(m)
        for m in MARKER_RE2.findall(text):
            refs.add(m)
    return refs


def main() -> int:
    specs, errors = load_specs()
    refs = load_markers()

    # REQ without test
    for req, status in sorted(specs.items()):
        if req not in refs:
            if status == "implemented":
                errors.append(f"{req}: Status=implemented but no @pytest.mark.req test")
            else:
                print(f"WARN {req}: Status={status}, no test yet (OK until implemented)")

    # Marker without spec
    for ref in sorted(refs):
        if ref not in specs:
            errors.append(f"Marker references unknown REQ: {ref}")

    if errors:
        print("FAIL traceability:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"OK: {len(specs)} REQ(s) in specs, {len(refs)} referenced by tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())