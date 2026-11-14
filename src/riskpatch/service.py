from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

from pydantic import ValidationError

from riskpatch.pipeline import run_once, webhook_url
from riskpatch.report import StackReport, now_iso

log = logging.getLogger("riskpatch")


def paths() -> tuple[Path, Path, Path]:
    inventory = Path(os.environ.get("RISKPATCH_INVENTORY", "/data/inventory/stack.yaml"))
    reports = Path(os.environ.get("RISKPATCH_REPORTS", "/data/reports"))
    cache = Path(os.environ.get("RISKPATCH_CACHE", "/data/cache"))
    return inventory, reports, cache


def ttl_hours() -> float:
    return float(os.environ.get("CACHE_TTL_HOURS", "6"))


def poll_seconds() -> int:
    return int(os.environ.get("POLL_INTERVAL_SECONDS", "21600"))


def cache_fresh(cache: Path, inventory_mtime: float, ttl: float) -> bool:
    marker = cache / ".fetched_at"
    if not marker.exists():
        return False
    age = time.time() - marker.stat().st_mtime
    return age < ttl * 3600 and marker.stat().st_mtime >= inventory_mtime


def mark_fetched(cache: Path) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    (cache / ".fetched_at").write_text(str(time.time()), encoding="utf-8")


def should_mark_fetched(report: StackReport) -> bool:
    return not report.errors and not report.stale


def serve() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    inventory, reports, cache = paths()
    interval = poll_seconds()
    while True:
        started = time.time()
        refresh = reports / "refresh.request"
        try:
            if not inventory.exists():
                log.error("inventory missing: %s", inventory)
                _invalid_alert(reports, str(inventory))
            else:
                fresh = cache_fresh(cache, inventory.stat().st_mtime, ttl_hours()) and not refresh.exists()
                report = run_once(inventory, reports, cache, webhook_url(), ttl_ok=fresh)
                if should_mark_fetched(report):
                    mark_fetched(cache)
                if refresh.exists():
                    refresh.unlink()
                log.info("report written to %s", reports / "latest.md")
        except (ValueError, ValidationError):
            log.exception("inventory invalid, preserving last report")
            _invalid_alert(reports, str(inventory))
        except Exception:
            log.exception("cycle failed, last report preserved")
        elapsed = time.time() - started
        sleep_for = max(1, interval - int(elapsed))
        deadline = time.time() + sleep_for
        while time.time() < deadline:
            if refresh.exists() or (inventory.exists() and inventory.stat().st_mtime > started):
                break
            time.sleep(min(5, deadline - time.time()))


def _invalid_alert(reports: Path, inventory: str) -> None:
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / "alerts.jsonl"
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if "inventory_invalid" in existing.splitlines()[-1:]:
        return
    line = json.dumps({"at": now_iso(), "reasons": ["inventory_invalid"], "inventory": inventory})
    path.write_text(existing + line + "\n", encoding="utf-8")
