from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from riskpatch.db import audit, now_iso, tx
from riskpatch.jobs import enqueue

JOB_TYPE = "freshness_refresh"
CATALOG_SCOPE = "cve_catalog"
DEFAULT_MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 60
BACKOFF_CAP_SECONDS = 3600
COVERAGE_PAGE = {
    "path": "/ui/coverage",
    "label": "Coverage",
    "title": "Coverage & Freshness",
    "subtitle": "Cache state, scan progress, and result freshness",
}
STATES = ("success", "running", "stale", "pending", "failed")
WORST_FIRST = ("failed", "stale", "running", "pending", "success")
REPORTING_WINDOW = timedelta(hours=24)


@dataclass(frozen=True)
class Layer:
    key: str
    name: str
    kind: str
    ttl_seconds: int | None
    refreshed_by: str
    stale_when: str
    refreshable: bool


LAYERS = (
    Layer("feed", "Threat intel feeds", "feed", 6 * 3600, "Scheduled CVE sync per source", "TTL expires or a sync fails", True),
    Layer("index", "CVE catalog index", "index", 6 * 3600, "Runs after each feed sync", "TTL expires or feed content changes", True),
    Layer("inventory", "Asset inventory snapshot", "inventory", 24 * 3600, "Collector run on each server (Ansible/AWX)", "No snapshot within TTL", False),
    Layer("correlation", "Correlation results", "correlation", None, "Analysis of the asset after new inventory, CVE, or KEV data",
          "Inventory hash, catalog, or KEV version changes, or inventory is stale", True),
)
LAYER_BY_KEY = {layer.key: layer for layer in LAYERS}

TRIGGERS = (
    {"name": "TTL expiry", "scope": "Every layer", "status": "Detect only"},
    {"name": "New KEV entry", "scope": "Correlation for matching packages", "status": "Not built"},
    {"name": "New or updated CVE", "scope": "Catalog index and affected assets", "status": "Not built"},
    {"name": "Inventory change (package hash differs)", "scope": "Correlation for that asset", "status": "Not built"},
    {"name": "Manual refresh", "scope": "Any layer or asset", "status": "Built"},
)

CAPABILITIES = (
    {"key": "heartbeat_alert", "priority": "P1", "shipped": False, "tested": False,
     "title": "Agent heartbeat and stale alert", "note": "Alert when an asset has not reported for more than 24h; today the only signal is the snapshot-age banner."},
    {"key": "retry_dead_letter", "priority": "P1", "shipped": True, "tested": True,
     "title": "Retry and dead-letter queue", "note": "Failed refresh jobs retry with backoff, then stop as failed with the error recorded."},
    {"key": "event_invalidation", "priority": "P1", "shipped": False, "tested": False,
     "title": "Event-driven invalidation", "note": "New KEV or CVE marks only the affected correlation results stale, without a full rescan."},
    {"key": "state_history", "priority": "P2", "shipped": True, "tested": True,
     "title": "State history per entry", "note": "Every cache state change is recorded with its reason and job."},
    {"key": "jobs_status_links", "priority": "P2", "shipped": False, "tested": False,
     "title": "Link to Jobs and Status pages", "note": "One place to see progress and results instead of two."},
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def fmt(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def backoff_seconds(attempt: int) -> int:
    return min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * 2 ** max(attempt - 1, 0))


def ensure_registry(conn: sqlite3.Connection, now: datetime) -> None:
    with tx(conn):
        for layer in LAYERS:
            conn.execute(
                "INSERT OR IGNORE INTO cache_layers (key, ttl_seconds, updated_at) VALUES (?,?,?)",
                (layer.key, layer.ttl_seconds, fmt(now)),
            )


def layer_ttl(conn: sqlite3.Connection, key: str) -> int | None:
    row = conn.execute("SELECT ttl_seconds FROM cache_layers WHERE key=?", (key,)).fetchone()
    return row["ttl_seconds"] if row else LAYER_BY_KEY[key].ttl_seconds


def _catalog_version(latest: str | None, kev: int | None) -> str:
    return f"{latest or ''}|{kev or 0}"


def _correlation_fingerprint(inventory_hash: str, catalog_version: str) -> str:
    return hashlib.sha256(f"{inventory_hash}|{catalog_version}".encode()).hexdigest()


def mark_correlation_current(conn: sqlite3.Connection, ws: int, now: datetime, asset_ids: list[str] | None = None,
                             exclude: frozenset[str] = frozenset()) -> int:
    """Record that findings were checked against the current inventory and CVE catalog.

    Analysis only re-runs assets that the changed CVEs can affect; every other analyzed asset is still correct
    against the new catalog. Without this, each CVE sync made all correlation entries look stale until someone
    pressed Refresh. asset_ids=None means every analyzed asset in the workspace; `exclude` skips assets whose analysis failed.
    """
    cat = conn.execute("SELECT MAX(updated_at) latest, SUM(CASE WHEN kev=1 THEN 1 ELSE 0 END) kev FROM cves").fetchone()
    version = _catalog_version(cat["latest"], cat["kev"])
    sql = ("SELECT a.asset_id, s.payload_hash FROM assets a JOIN snapshots s ON s.id=a.latest_snapshot_id "
           "WHERE a.workspace_id=? AND s.analysis_status='analyzed'")
    params: list = [ws]
    if asset_ids is not None:
        if not asset_ids:
            return 0
        sql += f" AND a.asset_id IN ({','.join('?' * len(asset_ids))})"
        params += asset_ids
    rows = [r for r in conn.execute(sql, params).fetchall() if r["asset_id"] not in exclude]
    ts = fmt(now)
    changed = 0
    with tx(conn):
        for r in rows:
            fingerprint = _correlation_fingerprint(r["payload_hash"] or "", version)
            changed += conn.execute(
                "UPDATE cache_entries SET input_fingerprint=?, updated_at=? WHERE workspace_id=? AND layer_key='correlation' AND scope_id=? AND input_fingerprint!=?",
                (fingerprint, ts, ws, r["asset_id"], fingerprint)).rowcount
    sweep(conn, ws, now)
    return changed


def _observations(conn: sqlite3.Connection, ws: int) -> list[dict]:
    out: list[dict] = []
    cat = conn.execute("SELECT COUNT(*) n, MAX(updated_at) latest, SUM(CASE WHEN kev=1 THEN 1 ELSE 0 END) kev FROM cves").fetchone()
    for row in conn.execute("SELECT provider, last_success_at, records_last_run FROM provider_status ORDER BY provider"):
        out.append({"layer": "feed", "scope_type": "source", "scope_id": row["provider"], "refreshed_at": row["last_success_at"],
                    "record_count": row["records_last_run"], "fingerprint": ""})
    out.append({"layer": "index", "scope_type": "global", "scope_id": CATALOG_SCOPE, "refreshed_at": cat["latest"],
                "record_count": cat["n"], "fingerprint": ""})
    catalog_version = _catalog_version(cat["latest"], cat["kev"])
    for asset in conn.execute(
        """SELECT a.id, a.asset_id, s.collected_at, s.payload_hash,
                  (SELECT COUNT(*) FROM components c WHERE c.snapshot_id=a.latest_snapshot_id) components,
                  (SELECT MAX(r.generated_at) FROM reports r WHERE r.asset_pk=a.id) reported_at,
                  (SELECT COUNT(*) FROM findings f WHERE f.asset_pk=a.id AND f.status='open') open_findings
           FROM assets a LEFT JOIN snapshots s ON s.id=a.latest_snapshot_id
           WHERE a.workspace_id=? ORDER BY a.asset_id""",
        (ws,),
    ):
        inv_hash = asset["payload_hash"] or ""
        out.append({"layer": "inventory", "scope_type": "asset", "scope_id": asset["asset_id"], "refreshed_at": asset["collected_at"],
                    "record_count": asset["components"] or 0, "fingerprint": inv_hash})
        fingerprint = _correlation_fingerprint(inv_hash, catalog_version)
        out.append({"layer": "correlation", "scope_type": "asset", "scope_id": asset["asset_id"], "refreshed_at": asset["reported_at"],
                    "record_count": asset["open_findings"] or 0, "fingerprint": fingerprint})
    return out


def sweep(conn: sqlite3.Connection, ws: int, now: datetime) -> dict:
    ensure_registry(conn, now)
    ts = fmt(now)
    observations = _observations(conn, ws)
    with tx(conn):
        for o in observations:
            ttl = layer_ttl(conn, o["layer"]) if o["layer"] != "correlation" else None
            conn.execute(
                """INSERT INTO cache_entries (workspace_id, layer_key, scope_type, scope_id, state, refreshed_at, ttl_seconds,
                       input_fingerprint, record_count, updated_at)
                   VALUES (?,?,?,?,'pending',?,?,?,?,?)
                   ON CONFLICT (workspace_id, layer_key, scope_type, scope_id) DO UPDATE SET
                       refreshed_at=excluded.refreshed_at, ttl_seconds=excluded.ttl_seconds, record_count=excluded.record_count,
                       input_fingerprint=CASE WHEN cache_entries.input_fingerprint='' THEN excluded.input_fingerprint
                                              ELSE cache_entries.input_fingerprint END,
                       updated_at=excluded.updated_at""",
                (ws, o["layer"], o["scope_type"], o["scope_id"], o["refreshed_at"], ttl, o["fingerprint"], o["record_count"], ts),
            )
        current = {(o["layer"], o["scope_id"]): o["fingerprint"] for o in observations}
        entries = conn.execute("SELECT * FROM cache_entries WHERE workspace_id=? ORDER BY id", (ws,)).fetchall()
        decided: dict[tuple[str, str], str] = {}
        changed = 0
        for layer_key in ("feed", "index", "inventory", "correlation"):
            for e in (x for x in entries if x["layer_key"] == layer_key):
                new = _decide(e, now, decided, current)
                decided[(layer_key, e["scope_id"])] = new
                if new != e["state"]:
                    _set_state(conn, e["id"], e["state"], new, "state recomputed from TTL and inputs", None, ts)
                    changed += 1
    return {"entries": len(entries), "changed": changed}


def _decide(e: sqlite3.Row, now: datetime, decided: dict, current: dict) -> str:
    if e["state"] in ("running", "failed"):
        return e["state"]
    if e["refreshed_at"] is None:
        return "pending"
    if e["last_error"]:
        return "stale"
    if e["layer_key"] == "correlation":
        if decided.get(("inventory", e["scope_id"])) == "stale":
            return "stale"
        if e["input_fingerprint"] and e["input_fingerprint"] != current.get(("correlation", e["scope_id"])):
            return "stale"
        return "success"
    if e["ttl_seconds"] and now > parse(e["refreshed_at"]) + timedelta(seconds=e["ttl_seconds"]):
        return "stale"
    return "success"


def _set_state(conn: sqlite3.Connection, entry_id: int, old: str | None, new: str, reason: str, job_id: int | None, ts: str) -> None:
    conn.execute("UPDATE cache_entries SET state=?, updated_at=? WHERE id=?", (new, ts, entry_id))
    conn.execute(
        "INSERT INTO cache_state_events (entry_id, from_state, to_state, reason, job_id, at) VALUES (?,?,?,?,?,?)",
        (entry_id, old, new, reason, job_id, ts),
    )


def sweep_all(conn: sqlite3.Connection, now: datetime) -> dict:
    total = {"entries": 0, "changed": 0}
    for ws in conn.execute("SELECT id FROM workspaces ORDER BY id").fetchall():
        result = sweep(conn, ws["id"], now)
        total["entries"] += result["entries"]
        total["changed"] += result["changed"]
    return total


def assets_reporting(conn: sqlite3.Connection, ws: int, now: datetime) -> int:
    since = fmt(now - REPORTING_WINDOW)
    return conn.execute(
        """SELECT COUNT(*) FROM assets a
           WHERE a.workspace_id=? AND (COALESCE(a.last_heartbeat_at, '') >= ?
                 OR EXISTS (SELECT 1 FROM snapshots s WHERE s.asset_pk=a.id AND s.received_at>=?))""",
        (ws, since, since),
    ).fetchone()[0]


def _targets(conn: sqlite3.Connection, ws: int, layer: str | None, asset_id: str | None) -> list[tuple[str, str]]:
    if layer is not None and layer not in LAYER_BY_KEY:
        raise ValueError(f"unknown layer: {layer}")
    if layer:
        keys = [layer]
    elif asset_id:
        keys = ["correlation"]
    else:
        keys = ["feed", "index", "correlation"]
    out: list[tuple[str, str]] = []
    for key in keys:
        if key == "feed":
            out.append(("feed", "all"))
        elif key == "index":
            out.append(("index", CATALOG_SCOPE))
        elif key == "inventory":
            out.append(("inventory", asset_id or "all"))
        elif key == "correlation":
            if asset_id:
                out.append(("correlation", asset_id))
            else:
                out.extend(("correlation", r["asset_id"]) for r in conn.execute("SELECT asset_id FROM assets WHERE workspace_id=? ORDER BY asset_id", (ws,)))
    return out


def enqueue_targets(conn: sqlite3.Connection, ws: int, actor: str, targets: list[tuple[str, str]], trigger: str) -> list[dict]:
    ensure_registry(conn, utc_now())
    results: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for layer_key, target in targets:
        if (layer_key, target) in seen:
            continue
        seen.add((layer_key, target))
        if not LAYER_BY_KEY[layer_key].refreshable:
            results.append({"layer": layer_key, "target": target, "status": "skipped",
                            "reason": "collector-driven: run the collector on the host"})
            continue
        active = conn.execute(
            "SELECT id, job_id FROM refresh_jobs WHERE workspace_id=? AND layer_key=? AND target=? AND state IN ('queued','running','retry_wait') ORDER BY id DESC LIMIT 1",
            (ws, layer_key, target),
        ).fetchone()
        if active:
            results.append({"layer": layer_key, "target": target, "status": "already_queued", "refresh_id": active["id"], "job_id": active["job_id"]})
            continue
        job_id, created = enqueue(conn, JOB_TYPE, trigger, {"layer": layer_key, "target": target}, ws)
        ts = now_iso()
        with tx(conn):
            cur = conn.execute(
                """INSERT INTO refresh_jobs (workspace_id, layer_key, target, trigger_source, state, job_id, queued_at, updated_at)
                   VALUES (?,?,?,?,'queued',?,?,?)""",
                (ws, layer_key, target, trigger, job_id, ts, ts),
            )
            audit(conn, actor, "freshness.refresh", f"{layer_key}:{target}", {"job_id": job_id, "new": created}, ws)
        results.append({"layer": layer_key, "target": target, "status": "queued", "refresh_id": cur.lastrowid, "job_id": job_id})
    return results


def request_refresh(conn: sqlite3.Connection, ws: int, actor: str, layer: str | None = None, asset_id: str | None = None,
                    trigger: str = "manual") -> list[dict]:
    return enqueue_targets(conn, ws, actor, _targets(conn, ws, layer, asset_id), trigger)


def invalidate_stale(conn: sqlite3.Connection, ws: int, actor: str, now: datetime) -> list[dict]:
    sweep(conn, ws, now)
    targets: list[tuple[str, str]] = []
    for e in conn.execute("SELECT layer_key, scope_id FROM cache_entries WHERE workspace_id=? AND state='stale' ORDER BY id", (ws,)):
        if e["layer_key"] == "feed":
            targets.append(("feed", "all"))
        elif e["layer_key"] == "index":
            targets.append(("index", CATALOG_SCOPE))
        else:
            targets.append((e["layer_key"], e["scope_id"]))
    return enqueue_targets(conn, ws, actor, targets, "ttl")


def run_refresh(conn: sqlite3.Connection, settings, job: sqlite3.Row, log_event, heartbeat) -> dict:
    from riskpatch.analysis import run_analysis
    from riskpatch.cvesync import run_cve_sync

    scope = json.loads(job["scope_json"] or "{}")
    layer, target = scope.get("layer"), scope.get("target")
    _mark_entries(conn, job["workspace_id"], layer, target, "running", "refresh started", job["id"], fmt(utc_now()))
    if layer in ("feed", "index"):
        result = run_cve_sync(conn, settings, log_event=log_event)
        if not result["ok"]:
            failed = [k for k, v in result["providers"].items() if not v["ok"]]
            raise RuntimeError("provider failed: " + ", ".join(failed))
        return result["counts"]
    if layer == "correlation":
        counts = run_analysis(conn, settings, job["workspace_id"], {"asset_id": target}, job["id"], heartbeat, log_event)
        if counts["failed"]:
            raise RuntimeError(f"{counts['failed']} asset failed analysis")
        return counts
    raise RuntimeError(f"layer {layer} cannot be refreshed server-side")


def _entry_filter(layer: str, target: str) -> tuple[str, list]:
    if layer == "feed":
        return "layer_key='feed'", []
    if layer == "index":
        return "layer_key='index' AND scope_id=?", [CATALOG_SCOPE]
    return "layer_key=? AND scope_id=?", [layer, target]


def _mark_entries(conn: sqlite3.Connection, ws: int, layer: str, target: str, state: str, reason: str, job_id: int, ts: str) -> None:
    where, params = _entry_filter(layer, target)
    with tx(conn):
        for e in conn.execute(f"SELECT id, state FROM cache_entries WHERE workspace_id=? AND {where}", [ws, *params]).fetchall():
            if e["state"] != state:
                _set_state(conn, e["id"], e["state"], state, reason, job_id, ts)


def complete_refresh(conn: sqlite3.Connection, job: sqlite3.Row, status: str, error: str | None, now: datetime) -> None:
    rj = conn.execute("SELECT * FROM refresh_jobs WHERE job_id=? ORDER BY id DESC LIMIT 1", (job["id"],)).fetchone()
    if rj is None:
        return
    ts = fmt(now)
    where, params = _entry_filter(rj["layer_key"], rj["target"])
    if status == "success":
        with tx(conn):
            conn.execute("UPDATE refresh_jobs SET state='success', finished_at=?, error=NULL, updated_at=? WHERE id=?", (ts, ts, rj["id"]))
            conn.execute(f"""UPDATE cache_entries SET last_error=NULL, last_job_id=?, updated_at=?,
                                 state=CASE WHEN state IN ('running','failed') THEN 'pending' ELSE state END
                             WHERE workspace_id=? AND {where}""",
                         [job["id"], ts, rj["workspace_id"], *params])
            if rj["layer_key"] == "correlation":
                fingerprint = next((o["fingerprint"] for o in _observations(conn, rj["workspace_id"])
                                    if o["layer"] == "correlation" and o["scope_id"] == rj["target"]), "")
                conn.execute("UPDATE cache_entries SET input_fingerprint=? WHERE workspace_id=? AND layer_key='correlation' AND scope_id=?",
                             (fingerprint, rj["workspace_id"], rj["target"]))
        sweep(conn, rj["workspace_id"], now)
        return
    retries = rj["retries"] + 1
    if retries >= rj["max_retries"]:
        with tx(conn):
            conn.execute("UPDATE refresh_jobs SET state='failed', dead_lettered=1, retries=?, finished_at=?, error=?, updated_at=? WHERE id=?",
                         (retries, ts, error, ts, rj["id"]))
            conn.execute(f"UPDATE cache_entries SET last_error=?, updated_at=? WHERE workspace_id=? AND {where}",
                         [error, ts, rj["workspace_id"], *params])
            for e in conn.execute(f"SELECT id, state FROM cache_entries WHERE workspace_id=? AND {where}", [rj["workspace_id"], *params]).fetchall():
                if e["state"] != "failed":
                    _set_state(conn, e["id"], e["state"], "failed", f"retries exhausted after {retries} attempts", job["id"], ts)
        return
    next_at = fmt(now + timedelta(seconds=backoff_seconds(retries)))
    with tx(conn):
        conn.execute("UPDATE refresh_jobs SET state='retry_wait', retries=?, next_attempt_at=?, finished_at=?, error=?, updated_at=? WHERE id=?",
                     (retries, next_at, ts, error, ts, rj["id"]))
        conn.execute(f"""UPDATE cache_entries SET last_error=?, last_job_id=?, updated_at=?,
                             state=CASE WHEN state='running' THEN 'pending' ELSE state END
                         WHERE workspace_id=? AND {where}""",
                     [error, job["id"], ts, rj["workspace_id"], *params])
    sweep(conn, rj["workspace_id"], now)


def requeue_due(conn: sqlite3.Connection, now: datetime) -> int:
    count = 0
    for rj in conn.execute("SELECT * FROM refresh_jobs WHERE state='retry_wait' AND next_attempt_at<=? ORDER BY id", (fmt(now),)).fetchall():
        job_id, _ = enqueue(conn, JOB_TYPE, "retry", {"layer": rj["layer_key"], "target": rj["target"]}, rj["workspace_id"])
        ts = fmt(now)
        with tx(conn):
            conn.execute("UPDATE refresh_jobs SET state='queued', job_id=?, next_attempt_at=NULL, updated_at=? WHERE id=?", (job_id, ts, rj["id"]))
        count += 1
    return count


def layer_views(conn: sqlite3.Connection, ws: int, now: datetime) -> list[dict]:
    entries = conn.execute("SELECT * FROM cache_entries WHERE workspace_id=?", (ws,)).fetchall()
    views = []
    for layer in LAYERS:
        mine = [e for e in entries if e["layer_key"] == layer.key]
        ttl = layer_ttl(conn, layer.key)
        worst = next((s for s in WORST_FIRST if any(e["state"] == s for e in mine)), "pending")
        refreshed = [parse(e["refreshed_at"]) for e in mine if e["refreshed_at"]]
        oldest = min(refreshed) if refreshed else None
        views.append({
            "key": layer.key, "name": layer.name, "kind": layer.kind, "state": worst if mine else "pending",
            "entries": len(mine), "stale_entries": sum(1 for e in mine if e["state"] == "stale"), "ttl_seconds": ttl, "refreshed_at": fmt(oldest) if oldest else None,
            "age_seconds": int((now - oldest).total_seconds()) if oldest else None,
            "record_count": sum(e["record_count"] for e in mine), "refreshed_by": layer.refreshed_by,
            "stale_when": layer.stale_when, "refreshable": layer.refreshable,
            "detail": "No data yet" if not mine else f"{len(mine)} entr{'y' if len(mine) == 1 else 'ies'}",
        })
    return views


def asset_freshness(conn: sqlite3.Connection, ws: int, asset_ids: list[str]) -> dict[str, tuple[str, bool]]:
    """Per server: (worst cache state of its inventory and correlation, whether a refresh is queued or retrying).
    A server with no cache entries yet is 'pending' (not verified)."""
    ids = sorted(set(asset_ids))
    if not ids:
        return {}
    marks = ",".join("?" * len(ids))
    worst: dict[str, str] = {}
    for r in conn.execute(
        f"SELECT scope_id, state FROM cache_entries WHERE workspace_id=? AND scope_type='asset' AND layer_key IN ('inventory','correlation') AND scope_id IN ({marks})",
        [ws, *ids]):
        cur = worst.get(r["scope_id"])
        if cur is None or WORST_FIRST.index(r["state"]) < WORST_FIRST.index(cur):
            worst[r["scope_id"]] = r["state"]
    queued = {r["target"] for r in conn.execute(
        f"SELECT DISTINCT target FROM refresh_jobs WHERE workspace_id=? AND state IN ('queued','retry_wait') AND target IN ({marks})", [ws, *ids])}
    return {a: (worst.get(a, "pending"), a in queued) for a in ids}


def refresh_status(conn: sqlite3.Connection, ws: int, asset_ids: list[str]) -> dict[str, dict]:
    """Most recent refresh attempt per server: state, when it was last active, and the error if it failed."""
    ids = sorted(set(asset_ids))
    if not ids:
        return {}
    marks = ",".join("?" * len(ids))
    rows = conn.execute(
        f"""SELECT target, state, retries, next_attempt_at, error, COALESCE(finished_at, started_at, queued_at) AS at FROM refresh_jobs
            WHERE workspace_id=? AND layer_key='correlation' AND id IN
              (SELECT MAX(id) FROM refresh_jobs WHERE workspace_id=? AND layer_key='correlation' AND target IN ({marks}) GROUP BY target)""",
        [ws, ws, *ids]).fetchall()
    return {r["target"]: dict(r) for r in rows}


def attention_assets(conn: sqlite3.Connection, ws: int, limit: int = 20) -> tuple[list[dict], int]:
    """Servers whose inventory or correlation is stale/failed, worst first (inventory problems before re-checks, oldest first)."""
    bad = "('stale','failed')"
    base = f"""FROM assets a
        LEFT JOIN cache_entries inv ON inv.workspace_id=a.workspace_id AND inv.layer_key='inventory' AND inv.scope_id=a.asset_id
        LEFT JOIN cache_entries cor ON cor.workspace_id=a.workspace_id AND cor.layer_key='correlation' AND cor.scope_id=a.asset_id
        WHERE a.workspace_id=? AND (inv.state IN {bad} OR cor.state IN {bad})"""
    total = conn.execute(f"SELECT COUNT(*) {base}", (ws,)).fetchone()[0]
    rows = conn.execute(
        f"""SELECT a.id, a.asset_id, a.collector_version, inv.state inv_state, inv.refreshed_at inv_at, inv.ttl_seconds inv_ttl,
                   inv.last_error inv_error, cor.state cor_state, cor.last_error cor_error,
                   (SELECT COUNT(*) FROM findings f WHERE f.asset_pk=a.id AND f.status='open') open_findings
            {base} ORDER BY (inv.state IN {bad}) DESC, inv.refreshed_at IS NULL DESC, inv.refreshed_at ASC, a.asset_id LIMIT ?""",
        (ws, limit)).fetchall()
    out = []
    for r in rows:
        if r["inv_state"] == "failed":
            why, error = "Inventory refresh failed", r["inv_error"]
        elif r["inv_state"] == "stale":
            why, error = "No snapshot within the target", r["inv_error"]
        elif r["cor_state"] == "failed":
            why, error = "Findings re-check failed", r["cor_error"]
        else:
            why, error = "Findings need a re-check", r["cor_error"]
        out.append({"asset_id": r["asset_id"], "why": why, "error": error, "last_snapshot": r["inv_at"], "target_seconds": r["inv_ttl"],
                    "collector_version": r["collector_version"], "open_findings": r["open_findings"],
                    "inventory_problem": r["inv_state"] in ("stale", "failed")})
    attempts = refresh_status(conn, ws, [o["asset_id"] for o in out])
    for o in out:
        o["refresh"] = attempts.get(o["asset_id"])
    return out, total


def summary(conn: sqlite3.Connection, ws: int, now: datetime) -> dict:
    layers = layer_views(conn, ws, now)
    have_entries = any(v["entries"] for v in layers)
    within = sum(1 for v in layers if v["state"] == "success" and v["entries"])
    if not have_entries:
        health = None
    elif any(v["state"] == "failed" for v in layers):
        health = "Critical"
    elif all(v["state"] == "success" for v in layers):
        health = "Healthy"
    else:
        health = "Degraded"
    aged = [v for v in layers if v["age_seconds"] is not None]
    oldest = max(aged, key=lambda v: v["age_seconds"]) if aged else None
    dist = {s: 0 for s in STATES}
    for row in conn.execute("SELECT state, COUNT(*) n FROM cache_entries WHERE workspace_id=? GROUP BY state", (ws,)):
        dist[row["state"]] = row["n"]
    stale_assets = {r["scope_id"] for r in conn.execute(
        "SELECT scope_id FROM cache_entries WHERE workspace_id=? AND scope_type='asset' AND layer_key IN ('inventory','correlation') AND state='stale'", (ws,))}
    old_assets = {r["scope_id"] for r in conn.execute(
        "SELECT scope_id FROM cache_entries WHERE workspace_id=? AND scope_type='asset' AND layer_key IN ('inventory','correlation') AND state IN ('stale','failed')", (ws,))}
    # confirmed = both the inventory and the correlation of the server are currently up to date
    confirmed_assets = {r["scope_id"] for r in conn.execute(
        """SELECT scope_id FROM cache_entries WHERE workspace_id=? AND scope_type='asset' AND layer_key IN ('inventory','correlation')
           GROUP BY scope_id HAVING COUNT(*)=2 AND SUM(state='success')=2""", (ws,))}
    on_stale_n = on_stale_kev = open_total = confirmed_n = old_n = 0
    for r in conn.execute(
        """SELECT a.asset_id, COUNT(*) n, SUM(f.kev) kev FROM findings f JOIN assets a ON a.id=f.asset_pk
           WHERE f.workspace_id=? AND f.status='open' GROUP BY f.asset_pk""", (ws,)):
        open_total += r["n"]
        if r["asset_id"] in confirmed_assets:
            confirmed_n += r["n"]
        if r["asset_id"] in old_assets:
            old_n += r["n"]
        if r["asset_id"] in stale_assets:
            on_stale_n += r["n"]
            on_stale_kev += r["kev"] or 0
    latest = conn.execute("SELECT MAX(collected_at) FROM snapshots WHERE workspace_id=?", (ws,)).fetchone()[0]
    inv_ttl = layer_ttl(conn, "inventory")
    latest_age = int((now - parse(latest)).total_seconds()) if latest else None
    return {
        "health": health,
        "layers_within_ttl": within,
        "layers_total": len(LAYERS),
        "oldest": {"layer": oldest["name"], "age_seconds": oldest["age_seconds"], "ttl_seconds": oldest["ttl_seconds"]} if oldest else None,
        "assets_reporting": {"reporting": assets_reporting(conn, ws, now),
                             "total": conn.execute("SELECT COUNT(*) FROM assets WHERE workspace_id=?", (ws,)).fetchone()[0]},
        "findings_on_stale": on_stale_n,
        "findings_open_total": open_total,
        "findings_confirmed": confirmed_n,
        "findings_old_data": old_n,
        "kev_on_stale": on_stale_kev,
        "unverified": conn.execute("SELECT COUNT(*) FROM findings WHERE workspace_id=? AND status='open' AND level='unverified'", (ws,)).fetchone()[0],
        "distribution": dist,
        "latest_inventory": {"collected_at": latest, "age_seconds": latest_age,
                             "stale": bool(latest_age is not None and inv_ttl and latest_age > inv_ttl)},
        "layers": layers,
    }


def list_jobs(conn: sqlite3.Connection, ws: int, limit: int, state: str | None) -> list[dict]:
    sql = "SELECT * FROM refresh_jobs WHERE workspace_id=?"
    params: list = [ws]
    if state:
        sql += " AND state=?"
        params.append(state)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    return [dict(r) for r in conn.execute(sql, params).fetchall()]
