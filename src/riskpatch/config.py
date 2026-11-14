from __future__ import annotations

import os

def _env(name: str, default: str | None = None) -> str | None:
    """RISKPATCH_<name> wins; the old STACKWATCH_<name> is still read so existing .env files keep working."""
    return os.environ.get(f"RISKPATCH_{name}") or os.environ.get(f"STACKWATCH_{name}") or default
from dataclasses import dataclass
from pathlib import Path

APP_VERSION = "0.2.0"
RULESET_VERSION = "rules-2026.10.1"


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    db_path: Path
    reports_dir: Path
    cache_dir: Path
    max_body_bytes: int
    ingest_max_age_seconds: int
    rate_limit_per_minute: int
    cve_sync_interval: int
    analysis_interval: int
    lease_seconds: int
    raw_retention_days: int
    nvd_backfill_days: int
    nvd_max_pages: int
    nvd_delay: float
    targeted_ttl_hours: int
    package_watch: frozenset[str]
    cookie_secure: bool
    offline: bool
    report_keep_per_asset: int = 3


def get_settings() -> Settings:
    watch = _env("PACKAGE_WATCH", "")
    return Settings(
        db_path=Path(_env("DB", "/data/db/stackwatch.sqlite3")),
        reports_dir=Path(_env("REPORTS", "/data/reports")),
        cache_dir=Path(_env("CACHE", "/data/cache")),
        max_body_bytes=_int("RISKPATCH_MAX_BODY_BYTES", 8 * 1024 * 1024),
        ingest_max_age_seconds=_int("RISKPATCH_INGEST_MAX_AGE_SECONDS", 2 * 86400),
        rate_limit_per_minute=_int("RISKPATCH_RATE_LIMIT_PER_MINUTE", 600),
        cve_sync_interval=_int("CVE_SYNC_INTERVAL_SECONDS", 3600),
        analysis_interval=_int("ANALYSIS_INTERVAL_SECONDS", 10800),
        lease_seconds=_int("RISKPATCH_LEASE_SECONDS", 900),
        raw_retention_days=_int("RAW_RETENTION_DAYS", 90),
        nvd_backfill_days=_int("NVD_BACKFILL_DAYS", 3),
        nvd_max_pages=_int("NVD_MAX_PAGES", 5),
        nvd_delay=float(os.environ.get("NVD_REQUEST_DELAY", "0" if os.environ.get("NVD_API_KEY") else "6")),
        targeted_ttl_hours=_int("CACHE_TTL_HOURS", 6),
        package_watch=frozenset(item.strip() for item in watch.split(",") if item.strip()),
        cookie_secure=_env("COOKIE_SECURE", "0") == "1",
        offline=_env("OFFLINE", "0") == "1",
        report_keep_per_asset=max(1, _int("REPORT_KEEP_PER_ASSET", 3)),
    )
