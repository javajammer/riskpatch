from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

MIGRATIONS = Path(__file__).parent / "migrations"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-32768")  # 32 MiB per connection; the default (2 MiB) re-read pages through syscalls on every scan
    conn.execute("PRAGMA mmap_size=1073741824")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA journal_size_limit=67108864")  # after a checkpoint resets the WAL, shrink the file to at most 64 MiB
    return conn


def checkpoint_wal(conn: sqlite3.Connection) -> dict:
    """Fold the WAL into the main database and truncate it. Readers that are still active make it only partial
    (busy=1); that is harmless and simply retried on the next call."""
    busy, log_frames, checkpointed = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    return {"busy": bool(busy), "wal_frames": log_frames, "checkpointed_frames": checkpointed}


@contextmanager
def tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Short write transaction. BEGIN IMMEDIATE avoids upgrade deadlocks."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def _migration_files() -> list[tuple[int, Path]]:
    return sorted((int(p.name.split("_", 1)[0]), p) for p in MIGRATIONS.glob("*.sql"))


def schema_version(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    return row["v"] or 0


def latest_version() -> int:
    return _migration_files()[-1][0]


def migrate(conn: sqlite3.Connection) -> int:
    current = schema_version(conn)
    for version, path in _migration_files():
        if version <= current:
            continue
        script = path.read_text(encoding="utf-8")
        conn.execute("BEGIN IMMEDIATE")
        try:
            # executescript would COMMIT implicitly; split on statement boundaries instead.
            for statement in _statements(script):
                conn.execute(statement)
            conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (version, now_iso()))
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
    return schema_version(conn)


def _statements(script: str) -> list[str]:
    out: list[str] = []
    buf: list[str] = []
    for line in script.splitlines():
        buf.append(line)
        candidate = "\n".join(buf).strip()
        if candidate.endswith(";") and sqlite3.complete_statement(candidate):
            out.append(candidate)
            buf = []
    if "\n".join(buf).strip():
        out.append("\n".join(buf).strip())
    return out


def audit(conn: sqlite3.Connection, actor: str, action: str, target: str | None = None, detail: dict | None = None, workspace_id: int = 1) -> None:
    conn.execute(
        "INSERT INTO audit_events (workspace_id, at, actor, action, target, detail) VALUES (?,?,?,?,?,?)",
        (workspace_id, now_iso(), actor, action, target, json.dumps(detail or {}, default=str)),
    )


def backup(conn: sqlite3.Connection, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise FileExistsError(f"{dest} already exists")
    target = sqlite3.connect(dest)
    try:
        conn.backup(target)
    finally:
        target.close()


def restore(source: Path, dest: Path) -> None:
    check = sqlite3.connect(source)
    try:
        result = check.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        check.close()
    if result != "ok":
        raise ValueError(f"integrity_check failed: {result}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(str(dest) + suffix).unlink(missing_ok=True)
    src = sqlite3.connect(source)
    out = sqlite3.connect(dest)
    try:
        src.backup(out)
    finally:
        src.close()
        out.close()


def index_text(conn: sqlite3.Connection, kind: str, ref: str, title: str, body: str) -> None:
    # kind/ref are UNINDEXED in the FTS table, so deleting by them scans everything; search_map gives the rowid instead.
    known = conn.execute("SELECT rid FROM search_map WHERE kind=? AND ref=?", (kind, ref)).fetchone()
    if known:
        conn.execute("DELETE FROM search_index WHERE rowid=? AND kind=? AND ref=?", (known[0], kind, ref))
    rid = conn.execute("INSERT INTO search_index (kind, ref, title, body) VALUES (?,?,?,?)", (kind, ref, title, body)).lastrowid
    conn.execute("INSERT OR REPLACE INTO search_map (kind, ref, rid) VALUES (?,?,?)", (kind, ref, rid))


def get_setting(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM system_settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    with tx(conn):
        conn.execute(
            """INSERT INTO system_settings (key, value, updated_at) VALUES (?,?,?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
            (key, value, now_iso()),
        )


def scheduler_enabled(conn: sqlite3.Connection) -> bool:
    return get_setting(conn, "worker_enabled", "1") == "1"


# ---- job schedules (managed from UI /ui/system) ----
def list_job_schedules(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT id, name, job_type, interval_seconds, enabled, last_run_at, created_at, updated_at "
        "FROM job_schedules ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


def get_job_schedule(conn: sqlite3.Connection, sid: int) -> dict | None:
    row = conn.execute(
        "SELECT id, name, job_type, interval_seconds, enabled, last_run_at, created_at, updated_at "
        "FROM job_schedules WHERE id=?", (sid,)
    ).fetchone()
    return dict(row) if row else None


def create_job_schedule(conn: sqlite3.Connection, name: str, job_type: str, interval_seconds: int,
                        enabled: bool = True) -> int:
    ts = now_iso()
    with tx(conn):
        cur = conn.execute(
            "INSERT INTO job_schedules (name, job_type, interval_seconds, enabled, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (name, job_type, interval_seconds, 1 if enabled else 0, ts, ts),
        )
        job_id = cur.lastrowid
        if job_id is None:
            raise RuntimeError("failed to insert job schedule")
        return job_id


def update_job_schedule(conn: sqlite3.Connection, sid: int, name: str, job_type: str,
                        interval_seconds: int, enabled: bool) -> None:
    ts = now_iso()
    with tx(conn):
        conn.execute(
            "UPDATE job_schedules SET name=?, job_type=?, interval_seconds=?, enabled=?, updated_at=? WHERE id=?",
            (name, job_type, interval_seconds, 1 if enabled else 0, ts, sid),
        )


def delete_job_schedule(conn: sqlite3.Connection, sid: int) -> None:
    with tx(conn):
        conn.execute("DELETE FROM job_schedules WHERE id=?", (sid,))


def set_job_schedule_enabled(conn: sqlite3.Connection, sid: int, enabled: bool) -> None:
    ts = now_iso()
    with tx(conn):
        conn.execute("UPDATE job_schedules SET enabled=?, updated_at=? WHERE id=?", (1 if enabled else 0, ts, sid))


def set_job_schedule_last_run(conn: sqlite3.Connection, sid: int, at: str) -> None:
    with tx(conn):
        conn.execute("UPDATE job_schedules SET last_run_at=?, updated_at=? WHERE id=?", (at, at, sid))


# ---- skills / context snippets (fed to LLM during AI correlation) ----
def list_skills(conn: sqlite3.Connection, active_only: bool = False) -> list[dict]:
    where, params = ("WHERE active=1", []) if active_only else ("", [])
    rows = conn.execute(
        f"SELECT id, name, content, active, created_at, updated_at FROM skills {where} ORDER BY name", params
    ).fetchall()
    return [dict(r) for r in rows]


def list_active_skills(conn: sqlite3.Connection) -> str:
    """Return concatenated content of all active skills, separated by double newlines."""
    rows = conn.execute(
        "SELECT content FROM skills WHERE active=1 ORDER BY name"
    ).fetchall()
    return "\n\n".join(r["content"] for r in rows if r["content"])


def get_skill(conn: sqlite3.Connection, sid: int) -> dict | None:
    row = conn.execute(
        "SELECT id, name, content, active, created_at, updated_at FROM skills WHERE id=?", (sid,)
    ).fetchone()
    return dict(row) if row else None


def create_skill(conn: sqlite3.Connection, name: str, content: str, active: bool = True) -> int:
    ts = now_iso()
    with tx(conn):
        cur = conn.execute(
            "INSERT INTO skills (name, content, active, created_at, updated_at) VALUES (?,?,?,?,?)",
            (name, content, 1 if active else 0, ts, ts),
        )
        job_id = cur.lastrowid
        if job_id is None:
            raise RuntimeError("failed to insert skill")
        return job_id


def update_skill(conn: sqlite3.Connection, sid: int, name: str, content: str, active: bool = True) -> None:
    ts = now_iso()
    with tx(conn):
        conn.execute(
            "UPDATE skills SET name=?, content=?, active=?, updated_at=? WHERE id=?",
            (name, content, 1 if active else 0, ts, sid),
        )


def delete_skill(conn: sqlite3.Connection, sid: int) -> None:
    with tx(conn):
        conn.execute("DELETE FROM skills WHERE id=?", (sid,))


def toggle_skill_active(conn: sqlite3.Connection, sid: int, active: bool) -> None:
    ts = now_iso()
    with tx(conn):
        conn.execute("UPDATE skills SET active=?, updated_at=? WHERE id=?", (1 if active else 0, ts, sid))


# Tables that hold business data. Kept: schema_migrations, workspaces, api_tokens (schema + auth).
_RESET_TABLES = [
    "search_index", "search_map", "campaign_events", "campaign_targets", "campaign_servers", "campaign_items", "campaigns", "work_exceptions", "work_events", "work_items", "job_events", "analysis_runs", "jobs", "alerts", "reports",
    "finding_evidence", "findings", "components", "snapshot_facts", "snapshots",
    "assets", "cve_revisions", "cve_sources", "cve_affected", "cves",
    "provider_status", "provider_queries", "audit_events",
    "skills", "skill_uses",
]


def reset(conn: sqlite3.Connection) -> dict[str, int]:
    """Wipe all business data, keeping schema, workspaces, and api_tokens.

    audit_events is append-only via triggers, so they are dropped temporarily.
    """
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.execute("DROP TRIGGER IF EXISTS audit_no_delete")
        conn.execute("DROP TRIGGER IF EXISTS audit_no_update")
        counts: dict[str, int] = {}
        with tx(conn):
            for table in _RESET_TABLES:
                cur = conn.execute(f"DELETE FROM {table}")
                counts[table] = cur.rowcount
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence'").fetchone():
                conn.execute("DELETE FROM sqlite_sequence")
        conn.execute(
            "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END"
        )
        conn.execute(
            "CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END"
        )
    finally:
        conn.execute("PRAGMA foreign_keys=ON")
    return counts


# Indexes the hot list and dashboard queries depend on. Every one is created by a migration, so a freshly built
# database has them as long as migrations ran; `riskpatch db check` reports any that are missing.
HOT_INDEXES = ("idx_alerts_ws_status_id", "idx_alerts_ws_closed", "idx_alerts_ws_asset", "idx_findings_updated", "idx_work_items_state")


def missing_indexes(conn: sqlite3.Connection) -> list[str]:
    have = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    return [name for name in HOT_INDEXES if name not in have]


def analyze(conn: sqlite3.Connection) -> float:
    """Collect table and index statistics so the planner stops guessing. Returns the seconds it took."""
    started = time.monotonic()
    conn.execute("ANALYZE")
    conn.commit()
    return time.monotonic() - started
