#!/usr/bin/env python3
"""OpenAPI snapshot diff gate.

Compares the committed snapshot at specs/contracts/api-v1.openapi.json with the
live OpenAPI generated from the FastAPI app. Exit non-zero on diff.

Usage:
  python scripts/openapi_diff.py            # check
  python scripts/openapi_diff.py --update   # regenerate snapshot
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "specs" / "contracts" / "api-v1.openapi.json"


def generate() -> dict:
    """Generate live OpenAPI from the FastAPI app."""
    import riskpatch.api  # noqa: F401  (registers lifespan)
    from riskpatch.api import create_app
    from riskpatch.config import get_settings

    app = create_app(get_settings())
    return app.openapi()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true", help="regenerate snapshot")
    args = ap.parse_args()

    live = generate()

    if args.update:
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(live, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Updated {SNAPSHOT}")
        return 0

    if not SNAPSHOT.exists():
        print(f"Snapshot missing: {SNAPSHOT}. Run with --update.")
        return 1

    committed = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    if committed == live:
        print("OK: OpenAPI snapshot matches live app")
        return 0

    print("FAIL: OpenAPI snapshot differs from live app")
    print(f"  committed: {SNAPSHOT}")
    print("  Update with: python scripts/openapi_diff.py --update")
    # Show a compact summary of changed paths
    committed_paths = set((p.get("path"), tuple(sorted(p.get("methods", []))))
                          for p in committed.get("paths", {}).items())
    live_paths = set((p.get("path"), tuple(sorted(p.get("methods", []))))
                     for p in live.get("paths", {}).items())
    only_committed = committed_paths - live_paths
    only_live = live_paths - committed_paths
    if only_committed:
        print(f"  Removed in live: {sorted(only_committed)}")
    if only_live:
        print(f"  Added in live: {sorted(only_live)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())