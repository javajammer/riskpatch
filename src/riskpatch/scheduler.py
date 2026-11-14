from __future__ import annotations

import logging
import signal
import sqlite3
import time

from riskpatch.config import Settings, get_settings
from riskpatch.db import analyze, checkpoint_wal, connect, get_setting, migrate
from riskpatch.freshness import requeue_due, sweep_all, utc_now
from riskpatch.campaigns import auto_progress
from riskpatch.work import expire_exceptions, verify_mitigated
from riskpatch.jobs import backfill_fixed_from_ranges, backfill_fixed_versions, claim, enqueue, run_job

log = logging.getLogger("riskpatch.scheduler")
VERIFY_SECONDS = 300  # confirm mitigated work against fresh snapshots
WAL_CHECKPOINT_SECONDS = 900  # keep the write-ahead log small so reads do not slow down
STATS_SECONDS = 24 * 3600  # planner statistics; first run one day after start so a restart does not hold the write lock


def _resolve_settings(conn: sqlite3.Connection, base: Settings) -> Settings:
    cve = get_setting(conn, "cve_sync_interval_seconds")
    analysis = get_setting(conn, "analysis_interval_seconds")
    return Settings(
        db_path=base.db_path,
        reports_dir=base.reports_dir,
        cache_dir=base.cache_dir,
        max_body_bytes=base.max_body_bytes,
        ingest_max_age_seconds=base.ingest_max_age_seconds,
        rate_limit_per_minute=base.rate_limit_per_minute,
        cve_sync_interval=int(cve) if cve and cve.isdigit() else base.cve_sync_interval,
        analysis_interval=int(analysis) if analysis and analysis.isdigit() else base.analysis_interval,
        lease_seconds=base.lease_seconds,
        raw_retention_days=base.raw_retention_days,
        nvd_backfill_days=base.nvd_backfill_days,
        nvd_max_pages=base.nvd_max_pages,
        nvd_delay=base.nvd_delay,
        targeted_ttl_hours=base.targeted_ttl_hours,
        package_watch=base.package_watch,
        cookie_secure=base.cookie_secure,
        offline=base.offline,
        report_keep_per_asset=base.report_keep_per_asset,
    )


def scheduler_enabled(conn: sqlite3.Connection) -> bool:
    return get_setting(conn, "worker_enabled", "1") == "1"


def load_schedules(conn: sqlite3.Connection) -> list[dict]:
    """Fetch active job schedules from system_settings / job_schedules."""
    rows = conn.execute(
        "SELECT id, name, job_type, interval_seconds, enabled FROM job_schedules ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


def tick(conn: sqlite3.Connection, settings: Settings, now: float | None = None) -> list[int]:
    """Enqueue due scheduled jobs based on DB list (not hardcoded)."""
    now = time.time() if now is None else now
    created: list[int] = []
    for sched in load_schedules(conn):
        if not sched["enabled"]:
            continue
        job_type = sched["job_type"]
        interval = int(sched["interval_seconds"] or 3600)
        bucket = int(now // interval)
        dedupe_key = f"schedule:{sched['id']}:{job_type}:{interval}:{bucket}"
        job_id, new = enqueue(conn, job_type, "schedule", dedupe_key=dedupe_key)
        if new:
            created.append(job_id)
    return created


def run_pending(conn: sqlite3.Connection, settings: Settings) -> int:
    done = 0
    while (job := claim(conn, settings)) is not None:
        log.info("menjalankan job %s (%s)", job["id"], job["type"])
        run_job(conn, settings, job)
        done += 1
    return done


def worker(poll_seconds: float = 5.0) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    base = get_settings()
    conn = connect(base.db_path)
    migrate(conn)
    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    log.info("worker mulai")
    try:
        filled = backfill_fixed_versions(conn)
        if filled:
            log.info("fixed_version backfill: %d findings", filled)
        derived = backfill_fixed_from_ranges(conn)
        if derived:
            log.info("fixed_version from affected ranges: %d findings", derived)
    except Exception:
        log.exception("fixed_version backfill failed")
    last_checkpoint = 0.0
    last_verify = 0.0
    last_stats = time.monotonic()
    while not stop["flag"]:
        if time.monotonic() - last_checkpoint >= WAL_CHECKPOINT_SECONDS:
            last_checkpoint = time.monotonic()
            try:
                log.info("wal checkpoint: %s", checkpoint_wal(conn))
            except Exception:
                log.exception("wal checkpoint failed")
        if time.monotonic() - last_stats >= STATS_SECONDS:
            last_stats = time.monotonic()
            try:
                log.info("statistics: analyzed in %.1fs", analyze(conn))
            except Exception:
                log.exception("statistics update failed")
        if time.monotonic() - last_verify >= VERIFY_SECONDS:
            last_verify = time.monotonic()
            try:
                for ws in [r["id"] for r in conn.execute("SELECT id FROM workspaces")]:
                    expired = expire_exceptions(conn, ws)
                    if expired:
                        log.info("exceptions expired: %d item(s) reopened", expired)
                    auto = auto_progress(conn, ws)
                    if auto["items_verified"] or auto["campaigns_completed"]:
                        log.info("campaigns: %d item(s) verified, %d campaign(s) completed", auto["items_verified"], auto["campaigns_completed"])
                    promoted = verify_mitigated(conn, ws)
                    if promoted:
                        log.info("work verification: %d item(s) verified", promoted)
            except Exception:
                log.exception("work verification failed")
        try:
            settings = _resolve_settings(conn, base)
            if scheduler_enabled(conn):
                tick(conn, settings)
            now = utc_now()
            sweep_all(conn, now)
            requeue_due(conn, now)
            run_pending(conn, settings)
        except Exception:
            log.exception("worker cycle failed")
        time.sleep(poll_seconds)
