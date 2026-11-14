from __future__ import annotations

import json
import logging
import os
import socket
import sqlite3
from datetime import datetime, timedelta, timezone

from riskpatch.config import APP_VERSION, RULESET_VERSION, Settings
from riskpatch.db import now_iso, tx

log = logging.getLogger("riskpatch.jobs")
JOB_TYPES = {"cve_sync", "analysis", "manual_analysis", "manual_cve_sync", "report_export", "freshness_refresh"}
MAX_ATTEMPTS = 3
OWNER = f"{socket.gethostname()}:{os.getpid()}"


def _later(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def enqueue(conn: sqlite3.Connection, job_type: str, trigger: str, scope: dict | None = None, workspace_id: int = 1, dedupe_key: str | None = None) -> tuple[int, bool]:
    """Returns (job_id, created). A manual request while the same kind is queued/running returns that job."""
    if job_type not in JOB_TYPES:
        raise ValueError(f"unknown job type: {job_type}")
    scope = scope or {}
    ts = now_iso()
    with tx(conn):
        if dedupe_key is None:
            active = conn.execute(
                "SELECT id FROM jobs WHERE workspace_id=? AND type=? AND status IN ('queued','running') AND scope_json=? ORDER BY id LIMIT 1",
                (workspace_id, job_type, json.dumps(scope, sort_keys=True)),
            ).fetchone()
            if active:
                return active["id"], False
        cur = conn.execute(
            """INSERT OR IGNORE INTO jobs (workspace_id, type, trigger_source, scope_json, dedupe_key, queued_at, app_version, ruleset_version, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (workspace_id, job_type, trigger, json.dumps(scope, sort_keys=True), dedupe_key, ts, APP_VERSION, RULESET_VERSION, ts),
        )
        if cur.rowcount == 0:
            row = conn.execute("SELECT id FROM jobs WHERE dedupe_key=?", (dedupe_key,)).fetchone()
            return row["id"], False
        job_id = cur.lastrowid
        _event(conn, job_id, "info", f"queued via {trigger}")
    return job_id, True


def _event(conn: sqlite3.Connection, job_id: int, level: str, message: str) -> None:
    conn.execute("INSERT INTO job_events (job_id, at, level, message) VALUES (?,?,?,?)", (job_id, now_iso(), level, message[:1000]))


def claim(conn: sqlite3.Connection, settings: Settings) -> sqlite3.Row | None:
    """Atomically take the oldest queued job, or a running one whose lease expired (crash recovery)."""
    ts = now_iso()
    with tx(conn):
        row = conn.execute(
            """SELECT * FROM jobs WHERE status='queued' OR (status='running' AND lease_expires_at < ?) ORDER BY queued_at, id LIMIT 1""", (ts,)
        ).fetchone()
        if row is None:
            return None
        if row["attempts"] >= MAX_ATTEMPTS:
            conn.execute("UPDATE jobs SET status='failed', finished_at=?, error=?, updated_at=? WHERE id=?",
                         (ts, "melebihi batas percobaan (lease habis berulang)", ts, row["id"]))
            _event(conn, row["id"], "error", "gave up after repeated lease expiry")
            return None
        conn.execute(
            "UPDATE jobs SET status='running', started_at=COALESCE(started_at, ?), attempts=attempts+1, lease_owner=?, lease_expires_at=?, updated_at=? WHERE id=?",
            (ts, OWNER, _later(settings.lease_seconds), ts, row["id"]),
        )
        if row["status"] == "running":
            _event(conn, row["id"], "warning", "lease expired; resuming job")
        return conn.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()


def run_job(conn: sqlite3.Connection, settings: Settings, job: sqlite3.Row) -> str:
    from riskpatch.analysis import run_analysis
    from riskpatch.cvesync import run_cve_sync

    job_id = job["id"]

    def heartbeat() -> None:
        conn.execute("UPDATE jobs SET lease_expires_at=?, updated_at=? WHERE id=? AND lease_owner=?", (_later(settings.lease_seconds), now_iso(), job_id, OWNER))

    def log_event(level: str, message: str) -> None:
        _event(conn, job_id, level, message)

    scope = json.loads(job["scope_json"] or "{}")
    status, error, counts, providers = "success", None, {}, {}
    try:
        if job["type"] in {"cve_sync", "manual_cve_sync"}:
            result = run_cve_sync(conn, settings, log_event=log_event)
            counts, providers = result["counts"], result["providers"]
            if not result["ok"]:
                failed = [k for k, v in providers.items() if not v["ok"]]
                status = "failed" if len(failed) == len(providers) else "partial"
                error = "provider failed: " + ", ".join(failed)
            prune(conn, settings)
        elif job["type"] in {"analysis", "manual_analysis"}:
            counts = run_analysis(conn, settings, job["workspace_id"], scope, job_id, heartbeat, log_event)
            if counts["failed"]:
                status, error = "partial", f"{counts['failed']} asset failed analysis"
        elif job["type"] == "freshness_refresh":
            from riskpatch.freshness import run_refresh
            counts = run_refresh(conn, settings, job, log_event, heartbeat)
        else:
            status, error = "failed", f"no handler for {job['type']}"
    except Exception as exc:
        log.exception("job %s failed", job_id)
        status, error = "failed", f"{type(exc).__name__}: {exc}"[:500]
    with tx(conn):
        conn.execute(
            """UPDATE jobs SET status=?, finished_at=?, error=?, counts_json=?, provider_status_json=?, lease_owner=NULL,
               lease_expires_at=NULL, updated_at=? WHERE id=?""",
            (status, now_iso(), error, json.dumps(counts), json.dumps(providers), now_iso(), job_id),
        )
        _event(conn, job_id, "info" if status == "success" else "error", f"finished: {status}")
    if job["type"] == "freshness_refresh":
        from riskpatch.freshness import complete_refresh, utc_now
        complete_refresh(conn, job, status, error, utc_now())
    if job["type"] in {"cve_sync", "manual_cve_sync"} and status != "failed":
        queue_followup_analysis(conn, job["workspace_id"])
    return status


def queue_followup_analysis(conn: sqlite3.Connection, workspace_id: int) -> None:
    """A CVE sync changes the catalog, so queue one analysis: it re-checks only assets the new CVEs can affect and
    confirms the rest, instead of leaving every correlation result 'stale' until the next scheduled run."""
    try:
        enqueue(conn, "analysis", "cve_sync.followup", workspace_id=workspace_id)  # identical queued/running job is reused
    except Exception:
        log.exception("could not queue analysis after cve sync")


def prune(conn: sqlite3.Connection, settings: Settings) -> dict:
    """Retention: raw snapshot payloads and provider responses are nulled; normalized rows stay."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=settings.raw_retention_days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    with tx(conn):
        a = conn.execute("UPDATE snapshot_facts SET payload_json=NULL WHERE payload_json IS NOT NULL AND snapshot_id IN "
                         "(SELECT id FROM snapshots WHERE received_at < ? AND id NOT IN (SELECT latest_snapshot_id FROM assets WHERE latest_snapshot_id IS NOT NULL))", (cutoff,)).rowcount
        b = conn.execute("UPDATE cve_sources SET raw_json=NULL WHERE raw_json IS NOT NULL AND fetched_at < ?", (cutoff,)).rowcount
    return {"snapshots_pruned": a, "provider_responses_pruned": b, "reports_pruned": prune_reports(conn, settings.report_keep_per_asset)}


def prune_reports(conn: sqlite3.Connection, keep: int = 3, batch: int = 10) -> int:
    """Each analysis stores a ~3.4 MB report. Keep the full content of the newest `keep` reports per asset and empty
    `content_json` of older ones; their Markdown stays, and the newest report (read by analysis) is never touched.
    Rows are updated in small batches so the write lock is held only briefly."""
    keep = max(1, keep)
    old_ids = [r[0] for r in conn.execute(
        """SELECT id FROM (SELECT id, content_json != '{}' AS full, ROW_NUMBER() OVER (PARTITION BY asset_pk ORDER BY id DESC) AS rn FROM reports)
           WHERE rn > ? AND full""", (keep,))]
    for i in range(0, len(old_ids), batch):
        chunk = old_ids[i:i + batch]
        with tx(conn):
            conn.execute(f"UPDATE reports SET content_json='{{}}' WHERE id IN ({','.join('?' * len(chunk))})", chunk)
    return len(old_ids)


def backfill_fixed_versions(conn: sqlite3.Connection, batch: int = 2000) -> int:
    """One-time fill of findings.fixed_version from verdict_json for rows analyzed before the column existed.
    Works through the primary key in small transactions so ingest and the API are never blocked for long. Returns rows filled."""
    filled, last = 0, 0
    while True:
        window = conn.execute("SELECT MIN(id), MAX(id) FROM (SELECT id FROM findings WHERE id>? ORDER BY id LIMIT ?)", (last, batch)).fetchone()
        if window[0] is None:
            return filled
        with tx(conn):
            filled += conn.execute(
                "UPDATE findings SET fixed_version=COALESCE(json_extract(verdict_json,'$.min_safe_target'),'') WHERE id BETWEEN ? AND ? AND fixed_version IS NULL",
                (window[0], window[1])).rowcount
        last = window[1]


FIXED_FROM_RANGES_MARKER = "fixed_version_from_ranges_v1"


def backfill_fixed_from_ranges(conn: sqlite3.Connection, batch: int = 1000) -> int:
    """One-time: findings analyzed before ranges were used as a fallback have no fixed_version although their stored
    affected_range evidence names one. Recompute it (and the verdict's min_safe_target) from that evidence, in small transactions."""
    from riskpatch.analysis import min_safe_target
    from riskpatch.db import get_setting, set_setting
    from riskpatch.facts import VersionBound
    from riskpatch.match import derive_fixed_versions

    if get_setting(conn, FIXED_FROM_RANGES_MARKER) == "done":
        return 0
    updated, last = 0, 0
    while True:
        rows = conn.execute("SELECT id, component_version FROM findings WHERE id>? AND fixed_version='' ORDER BY id LIMIT ?", (last, batch)).fetchall()
        if not rows:
            break
        last = rows[-1]["id"]
        changes = []
        for r in rows:
            ev = conn.execute("SELECT detail FROM finding_evidence WHERE finding_id=? AND kind='affected_range' LIMIT 1", (r["id"],)).fetchone()
            if ev is None:
                continue
            try:
                ranges = [VersionBound(**{k: v for k, v in b.items() if k in VersionBound.model_fields}) for b in json.loads(ev["detail"]).get("ranges", [])]
            except (ValueError, TypeError, AttributeError):
                continue
            fix = min_safe_target(r["component_version"], derive_fixed_versions(r["component_version"], ranges))
            if fix:
                changes.append((fix, fix, r["id"]))
        if changes:
            with tx(conn):
                conn.executemany("UPDATE findings SET fixed_version=?, verdict_json=json_set(verdict_json,'$.min_safe_target',?) WHERE id=?", changes)
            updated += len(changes)
    set_setting(conn, FIXED_FROM_RANGES_MARKER, "done")
    return updated
