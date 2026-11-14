from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import httpx

from riskpatch.config import Settings
from riskpatch.cvestore import mark_kev, upsert_record
from riskpatch.db import now_iso, tx
from riskpatch.facts import VulnFact
from riskpatch.providers import CveQuery, CveRecord, kev
from riskpatch.providers.circl import CirclProvider
from riskpatch.providers.nvd import NvdProvider
from riskpatch.providers.osv import OsvProvider
from riskpatch.sources import bundled_fixture_by_product

log = logging.getLogger("riskpatch.cvesync")
NVD_FMT = "%Y-%m-%dT%H:%M:%S.000"
OSV_ECOSYSTEMS = {"Packagist", "PyPI", "npm", "Go", "crates.io"}


def _status(conn: sqlite3.Connection, provider: str) -> dict:
    conn.execute("INSERT OR IGNORE INTO provider_status (provider) VALUES (?)", (provider,))
    row = conn.execute("SELECT * FROM provider_status WHERE provider=?", (provider,)).fetchone()
    return {**dict(row), "cursor": json.loads(row["cursor_json"] or "{}")}


def _record(conn: sqlite3.Connection, provider: str, ok: bool, error: str, cursor: dict | None, count: int) -> None:
    """A failed attempt keeps the old data and flips stale; it never deletes anything."""
    ts = now_iso()
    row = _status(conn, provider)
    stale = 0 if ok else 1
    conn.execute(
        "UPDATE provider_status SET last_attempt_at=?, last_success_at=?, last_error=?, stale=?, cursor_json=?, records_last_run=? WHERE provider=?",
        (ts, ts if ok else row["last_success_at"], None if ok else error[:500], stale,
         json.dumps(cursor if cursor is not None else row["cursor"]), count, provider),
    )


def tracked_components(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT DISTINCT c.match_key, c.ecosystem, c.vendor, c.product, c.name, c.version
           FROM components c JOIN assets a ON a.latest_snapshot_id=c.snapshot_id ORDER BY c.match_key, c.version"""
    ).fetchall()


def _write(conn: sqlite3.Connection, records: list[CveRecord], counts: dict) -> None:
    with tx(conn):
        for rec in records:
            counts[upsert_record(conn, rec)] += 1


def sync_kev(conn: sqlite3.Connection, client: httpx.Client, counts: dict) -> int:
    st = _status(conn, "kev")
    ids, etag, modified = kev.fetch(client, st["cursor"].get("etag", ""))
    changed = 0
    if modified:
        with tx(conn):
            changed = mark_kev(conn, ids)
    counts["kev_new"] += changed
    return changed


def sync_nvd_feed(conn: sqlite3.Connection, nvd: NvdProvider, settings: Settings, counts: dict) -> int:
    """Modified-since feed. A page cap bounds one run; progress persists in the cursor so the next run resumes."""
    st = _status(conn, "nvd")
    cursor = st["cursor"]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    pending = cursor.get("pending")
    if not pending:
        since = cursor.get("since")
        start = datetime.fromisoformat(since) if since else now - timedelta(days=settings.nvd_backfill_days)
        start = max(start, now - timedelta(days=119))
        pending = {"start": start.strftime(NVD_FMT), "end": now.strftime(NVD_FMT), "index": 0}
    fetched = 0
    for _ in range(settings.nvd_max_pages):
        records, total = nvd.modified(pending["start"], pending["end"], pending["index"])
        _write(conn, records, counts)
        fetched += len(records)
        pending["index"] += len(records)
        if not records or pending["index"] >= total:
            done = datetime.strptime(pending["end"], NVD_FMT).replace(tzinfo=timezone.utc)
            with tx(conn):
                _record(conn, "nvd", True, "", {"since": done.isoformat(), "pending": None}, fetched)
            return fetched
        with tx(conn):  # persist partial progress
            conn.execute("UPDATE provider_status SET cursor_json=? WHERE provider='nvd'", (json.dumps({**cursor, "pending": pending}),))
    with tx(conn):
        _record(conn, "nvd", True, "", {**cursor, "pending": pending}, fetched)
    return fetched


def _fresh(conn: sqlite3.Connection, provider: str, key: str, ttl_hours: int) -> bool:
    row = conn.execute("SELECT queried_at FROM provider_queries WHERE provider=? AND query_key=?", (provider, key)).fetchone()
    if row is None:
        return False
    return datetime.fromisoformat(row["queried_at"].replace("Z", "+00:00")) > datetime.now(timezone.utc) - timedelta(hours=ttl_hours)


def _mark_query(conn: sqlite3.Connection, provider: str, key: str) -> None:
    conn.execute(
        "INSERT INTO provider_queries (provider, query_key, queried_at) VALUES (?,?,?) ON CONFLICT(provider, query_key) DO UPDATE SET queried_at=excluded.queried_at",
        (provider, key, now_iso()),
    )


def sync_targeted(conn: sqlite3.Connection, nvd: NvdProvider, osv: OsvProvider, settings: Settings, counts: dict, errors: dict) -> None:
    """Per-component lookups for what the fleet actually runs (NVD by CPE, OSV by package)."""
    queried = {"nvd": 0, "osv": 0}
    for comp in tracked_components(conn):
        if comp["ecosystem"] == "generic":
            provider, query = "nvd", CveQuery(vendor=comp["vendor"], product=comp["product"], version=comp["version"])
            client = nvd
        elif comp["ecosystem"] in OSV_ECOSYSTEMS:
            provider, query = "osv", CveQuery(ecosystem=comp["ecosystem"], name=comp["name"], version=comp["version"])
            client = osv
        else:
            continue
        if provider == "osv" and comp["ecosystem"] not in OSV_ECOSYSTEMS:
            continue
        key = f"{comp['match_key']}@{comp['version']}"
        if _fresh(conn, provider, key, settings.targeted_ttl_hours):
            continue
        try:
            records = client.search(query)
        except Exception as exc:
            errors[provider] = f"{key}: {exc}"[:300]
            continue
        _write(conn, records, counts)
        with tx(conn):
            _mark_query(conn, provider, key)
        queried[provider] += 1
    counts["targeted_nvd"], counts["targeted_osv"] = queried["nvd"], queried["osv"]


def enrich_missing_scores(conn: sqlite3.Connection, nvd: NvdProvider, circl: CirclProvider, counts: dict, limit: int = 20) -> None:
    rows = conn.execute("SELECT cve_id FROM cves WHERE cvss_score IS NULL AND cve_id LIKE 'CVE-%' AND primary_source!='kev' ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
    for row in rows:
        for provider in (nvd, circl):
            try:
                rec = provider.get(row["cve_id"])
            except Exception:
                continue
            if rec and rec.fact.cvss_score is not None:
                _write(conn, [rec], counts)
                break


def load_offline(conn: sqlite3.Connection, counts: dict) -> int:
    """RISKPATCH_OFFLINE=1: seed from bundled fixtures so air-gapped installs still produce verdicts."""
    loaded = 0
    for comp in tracked_components(conn):
        for fact in bundled_fixture_by_product(comp["product"] or comp["name"]):
            rec = CveRecord(fact=fact, affected={comp["match_key"]: fact.ranges}, source="fixture", url="bundled-fixture", raw=fact.model_dump())
            _write(conn, [rec], counts)
            loaded += 1
    return loaded


def run_cve_sync(conn: sqlite3.Connection, settings: Settings, client: httpx.Client | None = None, log_event=lambda level, msg: None) -> dict:
    counts = {"created": 0, "updated": 0, "unchanged": 0, "kev_new": 0, "failed": 0}
    providers: dict[str, dict] = {}
    if settings.offline:
        n = load_offline(conn, counts)
        with tx(conn):
            _record(conn, "fixture", True, "", None, n)
        log_event("info", f"offline: {n} record fixture dimuat")
        return {"counts": counts, "providers": {"fixture": {"ok": True, "records": n}}, "ok": True}
    own = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "riskpatch/0.2"})
    nvd, osv, circl = NvdProvider(client, settings.nvd_delay), OsvProvider(client), CirclProvider(client)
    try:
        errors: dict[str, str] = {}
        steps = [
            ("kev", lambda: sync_kev(conn, client, counts)),
            ("nvd", lambda: sync_nvd_feed(conn, nvd, settings, counts)),
        ]
        for name, step in steps:
            try:
                n = step()
                if name == "kev":
                    with tx(conn):
                        st = _status(conn, "kev")
                        _record(conn, "kev", True, "", st["cursor"], n)
                providers[name] = {"ok": True, "records": n}
                log_event("info", f"{name}: ok ({n})")
            except Exception as exc:
                errors[name] = str(exc)[:300]
                counts["failed"] += 1
                with tx(conn):
                    _record(conn, name, False, str(exc), None, 0)
                providers[name] = {"ok": False, "error": errors[name]}
                log_event("error", f"{name}: {exc}")
        targeted_errors: dict[str, str] = {}
        sync_targeted(conn, nvd, osv, settings, counts, targeted_errors)
        for name, message in targeted_errors.items():
            counts["failed"] += 1
            with tx(conn):
                _record(conn, name, False, message, None, 0)
            providers[name] = {"ok": False, "error": message}
            log_event("warning", f"{name} targeted: {message}")
        if "osv" not in providers:
            with tx(conn):
                _record(conn, "osv", True, "", None, counts.get("targeted_osv", 0))
            providers["osv"] = {"ok": True, "records": counts.get("targeted_osv", 0)}
        enrich_missing_scores(conn, nvd, circl, counts)
    finally:
        if own:
            client.close()
    ok = all(p["ok"] for p in providers.values())
    return {"counts": counts, "providers": providers, "ok": ok}
