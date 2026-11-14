from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from riskpatch import auth, llm
from riskpatch.api.deps import ListParams, RateLimiter, bearer, get_conn, listing, require
from riskpatch.api.models import (
    AlertCloseRequest, AlertOut, AssetDeleteRequest, AssetOut, CorrelationRequest, AssetPatch, OwnershipPatch, CveDetail, CveOut, FindingDetail, FindingOut, FreshnessRefreshRequest, Health, JobDetail, JobOut, JobRequest, Page,
    ProviderOut, Ready, ReportDetail, ReportOut, SearchHit, SnapshotDetail, SnapshotOut,
)
from riskpatch.auth import Principal
from riskpatch.collector_contract import IngestResult, SnapshotIn
from riskpatch import freshness
from riskpatch.asset_admin import delete_assets, set_ownership
from riskpatch.correlate import correlate
from riskpatch.config import APP_VERSION, Settings, get_settings
from riskpatch.freshness import assets_reporting, utc_now
from riskpatch.db import audit, connect, latest_version, migrate, now_iso, schema_version, tx
from riskpatch.ingest import IngestError, bounded_decompress, ingest_snapshot, snapshot_diff
from riskpatch.jobs import enqueue

log = logging.getLogger("riskpatch.api")

LEVELS = ["critical", "high", "medium", "low", "informational", "unverified"]
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
}


def _j(value: str | None, default: Any) -> Any:
    try:
        return json.loads(value) if value else default
    except json.JSONDecodeError:
        return default


def fts_query(q: str) -> str:
    tokens = re.findall(r"[\w.\-]+", q)[:8]
    if not tokens:
        raise HTTPException(400, "empty search query")
    return " ".join(f'"{t}"' for t in tokens[:-1]) + (" " if len(tokens) > 1 else "") + f'"{tokens[-1]}"*'


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


# ---- row mappers -------------------------------------------------------------------------------------------------

def asset_out(r: sqlite3.Row) -> AssetOut:
    d = dict(r)
    d["mitigations"] = _j(d.get("mitigations"), [])
    return AssetOut.model_validate(d)


def finding_out(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["kev"], d["exposure_assumed"] = bool(d["kev"]), bool(d["exposure_assumed"])
    return d


def cve_out(r: sqlite3.Row) -> dict:
    d = dict(r)
    d.update(kev=bool(d["kev"]), cwe=_j(d["cwe"], []), references=_j(d.pop("refs"), []), patched_versions=_j(d["patched_versions"], []))
    d.pop("content_hash", None)
    return d


def job_out(r: sqlite3.Row) -> dict:
    d = dict(r)
    d.update(scope=_j(d["scope_json"], {}), counts=_j(d["counts_json"], {}), provider_status=_j(d["provider_status_json"], {}))
    d["duration_seconds"] = None
    if d["started_at"] and d["finished_at"]:
        d["duration_seconds"] = (datetime.fromisoformat(d["finished_at"].replace("Z", "+00:00")) - datetime.fromisoformat(d["started_at"].replace("Z", "+00:00"))).total_seconds()
    return d


def provider_out(r: sqlite3.Row, stale_after: int) -> dict:
    d = dict(r)
    stale = bool(d["stale"])
    if d["last_success_at"]:
        age = datetime.now(timezone.utc) - datetime.fromisoformat(d["last_success_at"].replace("Z", "+00:00"))
        stale = stale or age > timedelta(seconds=stale_after)
    else:
        stale = True
    d["stale"] = stale
    return d


def dashboard_stats(conn: sqlite3.Connection, ws: int, settings: Settings, alert_period: str = "30d") -> dict:
    durations = {
        "24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30),
        "3m": timedelta(days=90), "6m": timedelta(days=180), "1y": timedelta(days=365), "all": None,
    }
    alert_period = alert_period if alert_period in durations else "30d"
    now = datetime.now(timezone.utc)
    until = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    if durations[alert_period] is None:
        alert_since = "0000-01-01T00:00:00Z"
    else:
        alert_since = (now - durations[alert_period]).isoformat(timespec="seconds").replace("+00:00", "Z")
    since_30d = (now - timedelta(days=30)).isoformat(timespec="seconds").replace("+00:00", "Z")
    by_level = {r["level"]: r["n"] for r in conn.execute("SELECT level, COUNT(*) n FROM findings WHERE workspace_id=? AND status='open' GROUP BY level", (ws,))}
    highest = next((lvl for lvl in LEVELS if by_level.get(lvl)), None)
    providers = [provider_out(r, settings.cve_sync_interval * 3) for r in conn.execute("SELECT * FROM provider_status ORDER BY provider")]
    last_jobs = {}
    for t in ("cve_sync", "analysis"):
        row = conn.execute("SELECT * FROM jobs WHERE workspace_id=? AND type IN (?,?) AND status IN ('success','partial') ORDER BY id DESC LIMIT 1", (ws, t, "manual_" + t)).fetchone()
        last_jobs[t] = job_out(row) if row else None
    return {
        "assets": conn.execute("SELECT COUNT(*) FROM assets WHERE workspace_id=?", (ws,)).fetchone()[0],
        "findings_open": sum(by_level.values()),
        "findings_by_level": by_level,
        "highest_level": highest,
        "last_30d_since": since_30d,
        "alert_period": alert_period,
        "alerts_period_since": alert_since,
        "alerts_period_until": until,
        "assets_reporting_24h": assets_reporting(conn, ws, now),
        "latest_snapshot_received": conn.execute(
            "SELECT MAX(received_at) FROM snapshots WHERE workspace_id=?", (ws,)
        ).fetchone()[0],
        "kev_findings": conn.execute("SELECT COUNT(*) FROM findings WHERE workspace_id=? AND status='open' AND kev=1", (ws,)).fetchone()[0],
        "cves": conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0],
        "findings_open_period": conn.execute(
            "SELECT COUNT(*) FROM findings WHERE workspace_id=? AND status='open' AND first_seen>=? AND first_seen<=?",
            (ws, alert_since, until),
        ).fetchone()[0],
        "open_alerts": conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status='open' AND created_at>=? AND created_at<=?",
            (ws, alert_since, until),
        ).fetchone()[0],
        "alerts_in_assessment": conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status='acknowledged' AND created_at>=? AND created_at<=?",
            (ws, alert_since, until),
        ).fetchone()[0],
        "alerts_closed_period": conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status='closed' AND created_at>=? AND created_at<=?",
            (ws, alert_since, until),
        ).fetchone()[0],
        "alerts_remaining_period": conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE workspace_id=? AND status IN ('open','acknowledged') AND created_at>=? AND created_at<=?",
            (ws, alert_since, until),
        ).fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts WHERE workspace_id=?", (ws,)).fetchone()[0],
        "stale_providers": [p["provider"] for p in providers if p["stale"]],
        "providers": providers,
        "last_successful_jobs": last_jobs,
        "running_jobs": conn.execute("SELECT COUNT(*) FROM jobs WHERE workspace_id=? AND status IN ('queued','running')", (ws,)).fetchone()[0],
    }


async def read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, "payload too large")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, "payload too large")
        chunks.append(chunk)
    data = b"".join(chunks)
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            data = bounded_decompress(data, limit)
        except IngestError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(400, "invalid gzip") from exc
    return data


def build_router() -> APIRouter:
    r = APIRouter(prefix="/api/v1")

    @r.get("/health", response_model=Health, tags=["ops"])
    def health() -> Health:
        return Health(status="ok", version=APP_VERSION)

    @r.get("/ready", response_model=Ready, tags=["ops"])
    def ready(conn: sqlite3.Connection = Depends(get_conn)) -> Any:
        try:
            conn.execute("SELECT 1").fetchone()
            version = schema_version(conn)
        except sqlite3.Error:
            return JSONResponse({"status": "unavailable", "schema_version": 0, "database": "error"}, status_code=503)
        if version < latest_version():
            return JSONResponse({"status": "migrating", "schema_version": version, "database": "ok"}, status_code=503)
        return Ready(status="ready", schema_version=version, database="ok")

    # ---- ingest ----
    @r.post(
        "/ingest/snapshots", response_model=IngestResult, status_code=201, tags=["ingest"],
        openapi_extra={"requestBody": {"required": True, "content": {"application/json": {"schema": SnapshotIn.model_json_schema()}}}},
        responses={200: {"description": "duplicate: same snapshot already stored"}, 413: {}, 422: {}},
    )
    async def ingest(request: Request, response: Response, who: Principal = Depends(require("ingest")), conn: sqlite3.Connection = Depends(get_conn)):
        settings: Settings = request.app.state.settings
        body = await read_body(request, settings.max_body_bytes)
        try:
            snapshot_id, asset_id, duplicate = await run_in_threadpool(ingest_snapshot, conn, body, who, settings.ingest_max_age_seconds)
        except IngestError as exc:
            raise HTTPException(exc.status, str(exc)) from exc

        # Auto-trigger analysis for newly ingested asset (use fresh connection to avoid threading issues)
        if not duplicate:
            try:
                with connect(settings.db_path) as analyze_conn:
                    enqueue(analyze_conn, "analysis", "ingest.snapshot", scope={"asset_id": asset_id}, workspace_id=who.workspace_id)
            except Exception:
                log.exception("could not queue analysis after ingest of %s", asset_id)

        response.status_code = 200 if duplicate else 201
        return IngestResult(snapshot_id=snapshot_id, status="accepted", duplicate=duplicate, asset_id=asset_id)

    # ---- snapshots ----
    @r.get("/snapshots", response_model=Page[SnapshotOut], tags=["snapshots"])
    def snapshots(lp: ListParams = Depends(), asset_id: str | None = None, status: str | None = Query(None, pattern="^(pending|analyzed|superseded)$"),
                  who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        where, params = ["workspace_id=?"], [who.workspace_id]
        if asset_id:
            where.append("asset_id=?"); params.append(asset_id)
        if status:
            where.append("analysis_status=?"); params.append(status)
        rows, total = listing(conn, "*", "snapshots", where, params, {"collected_at": "collected_at", "received_at": "received_at", "id": "id"},
                              "collected_at", lp, "id", "updated_at")
        return Page(items=[SnapshotOut.model_validate(dict(x)) for x in rows], total=total, limit=lp.limit, offset=lp.offset)

    @r.get("/snapshots/{id}", response_model=SnapshotDetail, tags=["snapshots"])
    def snapshot(id: int, include_facts: bool = False, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        row = conn.execute("SELECT * FROM snapshots WHERE id=? AND workspace_id=?", (id, who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "snapshot not found")
        facts = conn.execute("SELECT payload_json FROM snapshot_facts WHERE snapshot_id=?", (id,)).fetchone()
        payload = _j(facts["payload_json"], None) if facts else None
        prev = conn.execute("SELECT id FROM snapshots WHERE asset_pk=? AND collected_at < ? ORDER BY collected_at DESC LIMIT 1", (row["asset_pk"], row["collected_at"])).fetchone()
        prev_payload = None
        if prev:
            pf = conn.execute("SELECT payload_json FROM snapshot_facts WHERE snapshot_id=?", (prev["id"],)).fetchone()
            prev_payload = _j(pf["payload_json"], None) if pf else None
        comps = [dict(c) for c in conn.execute("SELECT kind, name, version, ecosystem, vendor, product, match_key, role, distro_package FROM components WHERE snapshot_id=?", (id,))]
        if include_facts:
            audit(conn, who.actor, "query.snapshot_facts", str(id), workspace_id=who.workspace_id)
        return SnapshotDetail(**dict(row), components=comps, diff_from_previous=snapshot_diff(prev_payload, payload or {}) if prev else {},
                              facts=payload if include_facts else None)

    # ---- assets ----
    @r.get("/assets", response_model=Page[AssetOut], tags=["assets"])
    def assets(lp: ListParams = Depends(), environment: str | None = None, exposure: str | None = None, q: str | None = None,
               owner: str | None = None, business_tier: str | None = None,
               who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        where, params = ["a.workspace_id=?"], [who.workspace_id]
        for col, val in (("environment", environment), ("exposure", exposure)):
            if val:
                where.append(f"a.{col}=?"); params.append(val)
        if q:
            where.append("(a.asset_id LIKE ? OR a.hostname LIKE ?)"); params += [f"%{q}%"] * 2
        if owner == "none":  # servers without an owner
            where.append("a.owner=''")
        elif owner:
            where.append("a.owner LIKE ?"); params.append(f"%{owner}%")
        if business_tier:
            where.append("a.business_tier=?"); params.append("" if business_tier == "none" else business_tier)
        select = ("a.*, (SELECT COUNT(*) FROM findings f WHERE f.asset_pk=a.id AND f.status='open') AS findings_open, "
                  "(SELECT level FROM findings f WHERE f.asset_pk=a.id AND f.status='open' ORDER BY level_rank DESC LIMIT 1) AS highest_level")
        rows, total = listing(conn, select, "assets a", where, params,
                              {"last_seen": "a.last_seen", "asset_id": "a.asset_id", "first_seen": "a.first_seen", "findings_open": "findings_open"},
                              "last_seen", lp, "a.id", "a.updated_at")
        return Page(items=[asset_out(x) for x in rows], total=total, limit=lp.limit, offset=lp.offset)

    def _asset(conn: sqlite3.Connection, who: Principal, asset_id: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT a.*, (SELECT COUNT(*) FROM findings f WHERE f.asset_pk=a.id AND f.status='open') AS findings_open, "
            "(SELECT level FROM findings f WHERE f.asset_pk=a.id AND f.status='open' ORDER BY level_rank DESC LIMIT 1) AS highest_level "
            "FROM assets a WHERE a.workspace_id=? AND a.asset_id=?", (who.workspace_id, asset_id)).fetchone()
        if row is None:
            raise HTTPException(404, "asset not found")
        return row

    @r.get("/assets/{id}", response_model=AssetOut, tags=["assets"])
    def asset(id: str, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        return asset_out(_asset(conn, who, id))

    @r.patch("/assets/{id}", response_model=AssetOut, tags=["assets"], summary="Correct asset metadata (audited)")
    def patch_asset(id: str, body: AssetPatch, who: Principal = Depends(require("operate")), conn: sqlite3.Connection = Depends(get_conn)):
        row = _asset(conn, who, id)
        override = _j(row["metadata_override"], {})
        override.update({k: v for k, v in body.model_dump().items() if v is not None})
        with tx(conn):
            conn.execute("UPDATE assets SET metadata_override=?, updated_at=? WHERE id=?", (json.dumps(override), now_iso(), row["id"]))
            audit(conn, who.actor, "asset.metadata_override", id, override, who.workspace_id)
        return asset_out(_asset(conn, who, id))

    @r.patch("/assets/{id}/ownership", response_model=AssetOut, tags=["assets"], summary="Set owner, business tier, service and maintenance window (audited)")
    def patch_ownership(id: str, body: OwnershipPatch, who: Principal = Depends(require("operate")), conn: sqlite3.Connection = Depends(get_conn)):
        try:
            set_ownership(conn, who.workspace_id, id, who.actor, **body.model_dump())
        except LookupError as exc:
            raise HTTPException(404, "asset not found") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return asset_out(_asset(conn, who, id))

    @r.post("/assets/delete", tags=["assets"], summary="Permanently delete assets with their findings, alerts, reports, and snapshots (admin, audited)")
    def delete_assets_route(body: AssetDeleteRequest, who: Principal = Depends(require("admin")), conn: sqlite3.Connection = Depends(get_conn)):
        try:
            return delete_assets(conn, who.workspace_id, body.asset_ids, who.actor)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        except LookupError as exc:
            raise HTTPException(404, str(exc))
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))

    @r.get("/assets/{id}/findings", response_model=Page[FindingOut], tags=["assets"])
    def asset_findings(id: str, lp: ListParams = Depends(), status: str | None = "open", who: Principal = Depends(require("read")),
                       conn: sqlite3.Connection = Depends(get_conn)):
        _asset(conn, who, id)
        return _findings(conn, who, lp, asset_id=id, status=status)

    # ---- CVEs ----
    @r.get("/cves", response_model=Page[CveOut], tags=["cves"])
    def cves(lp: ListParams = Depends(), q: str | None = None, kev: bool | None = None, min_cvss: float | None = Query(None, ge=0, le=10),
             source: str | None = None, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        where, params = [], []
        if q:
            where.append("cve_id IN (SELECT ref FROM search_index WHERE kind='cve' AND search_index MATCH ?)"); params.append(fts_query(q))
        if kev is not None:
            where.append("kev=?"); params.append(int(kev))
        if min_cvss is not None:
            where.append("cvss_score>=?"); params.append(min_cvss)
        if source:
            where.append("primary_source=?"); params.append(source)
        rows, total = listing(conn, "*", "cves", where, params, {"updated_at": "updated_at", "cvss_score": "cvss_score", "cve_id": "cve_id", "first_seen": "first_seen"},
                              "updated_at", lp, "cve_id", "updated_at")
        return Page(items=[cve_out(x) for x in rows], total=total, limit=lp.limit, offset=lp.offset)

    @r.get("/cves/{cve_id}", response_model=CveDetail, tags=["cves"])
    def cve(cve_id: str, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        row = conn.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id.upper(),)).fetchone()
        if row is None:
            raise HTTPException(404, "CVE not found")
        d = cve_out(row)
        d["affected"] = [{"match_key": a["match_key"], "source": a["source"], "ranges": _j(a["ranges_json"], [])}
                         for a in conn.execute("SELECT * FROM cve_affected WHERE cve_id=?", (row["cve_id"],))]
        d["sources"] = [dict(s) for s in conn.execute("SELECT source, url, fetched_at, content_hash FROM cve_sources WHERE cve_id=?", (row["cve_id"],))]
        d["revisions"] = [dict(s) for s in conn.execute("SELECT revision, source, content_hash, created_at FROM cve_revisions WHERE cve_id=? ORDER BY revision DESC LIMIT 20", (row["cve_id"],))]
        d["affected_assets"] = [dict(s) for s in conn.execute(
            "SELECT asset_id, component_name, component_version, level, status, id AS finding_id FROM findings WHERE cve_id=? AND workspace_id=? ORDER BY level_rank DESC",
            (row["cve_id"], who.workspace_id))]
        return d

    # ---- findings ----
    def _findings(conn, who, lp, *, asset_id=None, severity=None, cve_id=None, exposure=None, status=None, confidence=None, kev=None,
                  environment=None, min_cvss=None, component=None, q=None) -> Page:
        where, params = ["f.workspace_id=?"], [who.workspace_id]
        levels = _csv(severity)
        if levels:
            bad = [v for v in levels if v not in LEVELS]
            if bad:
                raise HTTPException(400, f"unknown severity: {bad}")
            where.append(f"f.level IN ({','.join('?' * len(levels))})"); params += levels
        for col, val in (("asset_id", asset_id), ("cve_id", cve_id and cve_id.upper()), ("exposure", exposure), ("status", status), ("confidence", confidence)):
            if val:
                where.append(f"f.{col}=?"); params.append(val)
        if kev is not None:
            where.append("f.kev=?"); params.append(int(kev))
        if environment:
            where.append("a.environment=?"); params.append(environment)
        if min_cvss is not None:
            where.append("f.cvss_score>=?"); params.append(min_cvss)
        if component:
            where.append("f.component_name LIKE ?"); params.append(f"%{component}%")
        if q:
            where.append("CAST(f.id AS TEXT) IN (SELECT ref FROM search_index WHERE kind='finding' AND search_index MATCH ?)"); params.append(fts_query(q))
        rows, total = listing(conn, "f.*", "findings f JOIN assets a ON a.id=f.asset_pk", where, params,
                              {"level": "f.level_rank", "updated_at": "f.updated_at", "cvss_score": "f.cvss_score", "first_seen": "f.first_seen", "asset_id": "f.asset_id", "cve_id": "f.cve_id"},
                              "level", lp, "f.id", "f.updated_at")
        return Page(items=[FindingOut.model_validate(finding_out(x)) for x in rows], total=total, limit=lp.limit, offset=lp.offset)

    @r.get("/findings", response_model=Page[FindingOut], tags=["findings"])
    def findings(lp: ListParams = Depends(),     severity: str | None = Query(None, description="levels, comma-separated"), cve_id: str | None = None,
                 asset_id: str | None = None, exposure: str | None = None, status: str | None = Query(None, pattern="^(open|resolved)$"),
                 confidence: str | None = Query(None, pattern="^(high|medium|low)$"), kev: bool | None = None, environment: str | None = None,
                 min_cvss: float | None = Query(None, ge=0, le=10), component: str | None = None, q: str | None = None,
                 who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        return _findings(conn, who, lp, asset_id=asset_id, severity=severity, cve_id=cve_id, exposure=exposure, status=status, confidence=confidence,
                         kev=kev, environment=environment, min_cvss=min_cvss, component=component, q=q)

    @r.get("/findings/{id}", response_model=FindingDetail, tags=["findings"])
    def finding(id: int, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        row = conn.execute("SELECT * FROM findings WHERE id=? AND workspace_id=?", (id, who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "finding not found")
        d = finding_out(row)
        d["verdict"] = _j(row["verdict_json"], {})
        d["evidence"] = [{"kind": e["kind"], "detail": e["detail"]} for e in conn.execute("SELECT kind, detail FROM finding_evidence WHERE finding_id=? ORDER BY id", (id,))]
        return d

    # ---- reports ----
    def _report(row: sqlite3.Row) -> dict:
        d = dict(row)
        d.update(stale=bool(d["stale"]), content=_j(d.pop("content_json"), {}), markdown=d.pop("content_md"))
        return d

    @r.get("/reports", response_model=Page[ReportOut], tags=["reports"])
    def reports(lp: ListParams = Depends(), asset_id: str | None = None, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        where, params = ["workspace_id=?"], [who.workspace_id]
        if asset_id:
            where.append("asset_id=?"); params.append(asset_id)
        rows, total = listing(conn, "id, asset_id, snapshot_id, analysis_run_id, generated_at, highest, stale", "reports", where, params,
                              {"generated_at": "generated_at", "id": "id"}, "generated_at", lp, "id", "generated_at")
        return Page(items=[ReportOut.model_validate({**dict(x), "stale": bool(x["stale"])}) for x in rows], total=total, limit=lp.limit, offset=lp.offset)

    @r.get("/reports/latest", response_model=ReportDetail, tags=["reports"])
    def latest_report(asset_id: str | None = None, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        sql, params = "SELECT * FROM reports WHERE workspace_id=?", [who.workspace_id]
        if asset_id:
            sql += " AND asset_id=?"; params.append(asset_id)
        row = conn.execute(sql + " ORDER BY id DESC LIMIT 1", params).fetchone()
        if row is None:
            raise HTTPException(404, "no report yet")
        return _report(row)

    @r.get("/reports/{id}", response_model=ReportDetail, tags=["reports"])
    def report(id: int, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        row = conn.execute("SELECT * FROM reports WHERE id=? AND workspace_id=?", (id, who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "report not found")
        return _report(row)

    # ---- jobs ----
    @r.get("/jobs", response_model=Page[JobOut], tags=["jobs"])
    def jobs(lp: ListParams = Depends(), type: str | None = None, status: str | None = None, trigger_source: str | None = None,
             who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        where, params = ["workspace_id=?"], [who.workspace_id]
        for col, val in (("type", type), ("status", status), ("trigger_source", trigger_source)):
            if val:
                where.append(f"{col}=?"); params.append(val)
        rows, total = listing(conn, "*", "jobs", where, params, {"queued_at": "queued_at", "id": "id", "finished_at": "finished_at"}, "id", lp, "id", "updated_at")
        return Page(items=[JobOut.model_validate(job_out(x)) for x in rows], total=total, limit=lp.limit, offset=lp.offset)

    @r.get("/jobs/{id}", response_model=JobDetail, tags=["jobs"])
    def job(id: int, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        row = conn.execute("SELECT * FROM jobs WHERE id=? AND workspace_id=?", (id, who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "job not found")
        d = job_out(row)
        d["events"] = [dict(e) for e in conn.execute("SELECT at, level, message FROM job_events WHERE job_id=? ORDER BY id", (id,))]
        return d

    def _trigger(job_type: str, scope: dict, who: Principal, conn: sqlite3.Connection, source: str = "api") -> sqlite3.Row:
        job_id, created = enqueue(conn, job_type, source, scope, who.workspace_id)
        with tx(conn):
            audit(conn, who.actor, "job.trigger", str(job_id), {"type": job_type, "scope": scope, "new": created}, who.workspace_id)
        return conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()

    @r.post("/jobs/analysis/run", response_model=JobOut, status_code=202, tags=["jobs"])
    def run_analysis_job(body: JobRequest | None = None, who: Principal = Depends(require("operate")), conn: sqlite3.Connection = Depends(get_conn)):
        scope = {"asset_id": body.asset_id} if body and body.asset_id else {}
        if scope:
            _asset(conn, who, scope["asset_id"])
        return job_out(_trigger("manual_analysis", scope, who, conn))

    @r.post("/jobs/cve-sync/run", response_model=JobOut, status_code=202, tags=["jobs"])
    def run_sync_job(who: Principal = Depends(require("operate")), conn: sqlite3.Connection = Depends(get_conn)):
        return job_out(_trigger("manual_cve_sync", {}, who, conn))

    # ---- Coverage & freshness ----
    @r.get("/freshness/summary", tags=["freshness"])
    def freshness_summary(who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        return freshness.summary(conn, who.workspace_id, utc_now())

    @r.get("/freshness/layers", tags=["freshness"])
    def freshness_layers(who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        return {"items": freshness.layer_views(conn, who.workspace_id, utc_now())}

    @r.get("/freshness/jobs", tags=["freshness"])
    def freshness_jobs(limit: int = Query(50, ge=1, le=200), state: str | None = Query(None, pattern="^(queued|running|success|retry_wait|failed)$"),
                       who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        return {"items": freshness.list_jobs(conn, who.workspace_id, limit, state)}

    @r.get("/freshness/triggers", tags=["freshness"])
    def freshness_triggers(who: Principal = Depends(require("read"))):
        return {"items": list(freshness.TRIGGERS)}

    @r.get("/freshness/gaps", tags=["freshness"])
    def freshness_gaps(who: Principal = Depends(require("read"))):
        open_items = [c for c in freshness.CAPABILITIES if not (c["shipped"] and c["tested"])]
        return {"items": sorted(open_items, key=lambda c: c["priority"])}

    @r.post("/freshness/refresh", status_code=202, tags=["freshness"])
    def freshness_refresh(body: FreshnessRefreshRequest | None = None, who: Principal = Depends(require("operate")),
                          conn: sqlite3.Connection = Depends(get_conn)):
        body = body or FreshnessRefreshRequest()
        if body.asset_id:
            _asset(conn, who, body.asset_id)
        try:
            results = freshness.request_refresh(conn, who.workspace_id, who.actor, body.layer, body.asset_id)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return {"results": results}

    @r.post("/freshness/invalidate-stale", status_code=202, tags=["freshness"])
    def freshness_invalidate_stale(who: Principal = Depends(require("operate")), conn: sqlite3.Connection = Depends(get_conn)):
        return {"results": freshness.invalidate_stale(conn, who.workspace_id, who.actor, utc_now())}

    # ---- AI correlation (read-only; never changes level/action/status) ----
    @r.post("/correlations/ai", tags=["correlations"], summary="AI correlation for asset, finding, and report",
            description="Sends a summary of open findings (one request) to the LLM gateway. The response includes the "
                        "deterministic verdict from the DB as-is, plus an AI narrative with explicit evidence and uncertainty. `ai.status`: ok | unconfigured | error | skipped. Scope: operate.")
    def correlate_ai(body: CorrelationRequest | None = None, who: Principal = Depends(require("operate")), conn: sqlite3.Connection = Depends(get_conn)):
        body = body or CorrelationRequest()
        if body.asset_id:
            _asset(conn, who, body.asset_id)
        with httpx.Client(timeout=llm.load_config().timeout if llm.load_config() else 60) as client:
            result = correlate(conn, who.workspace_id, client, body.asset_id, body.max_findings, skills=body.skills)
        with tx(conn):
            audit(conn, who.actor, "correlation.ai", body.asset_id, {"status": result["ai"]["status"], "findings": len(result["deterministic"]["verdicts"]),
                                                                      "error": (result["ai"]["error"] or {}).get("code")}, who.workspace_id)
        return result

    # ---- providers / alerts ----
    @r.get("/providers", response_model=list[ProviderOut], tags=["cves"])
    def providers(request: Request, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        s: Settings = request.app.state.settings
        return [provider_out(x, s.cve_sync_interval * 3) for x in conn.execute("SELECT * FROM provider_status ORDER BY provider")]

    @r.get("/alerts", response_model=Page[AlertOut], tags=["alerts"])
    def alerts(lp: ListParams = Depends(), acknowledged: bool | None = None, status: str | None = None, asset_id: str | None = None, kind: str | None = None,
               who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        where, params = ["workspace_id=?"], [who.workspace_id]
        if acknowledged is not None:
            where.append("status IN ('acknowledged','closed')" if acknowledged else "status='open'")
        if status is not None:
            if status not in {"open", "acknowledged", "closed"}:
                raise HTTPException(422, "invalid alert status")
            where.append("status=?"); params.append(status)
        for col, val in (("asset_id", asset_id), ("kind", kind)):
            if val:
                where.append(f"{col}=?"); params.append(val)
        rows, total = listing(conn, "*", "alerts", where, params, {"created_at": "created_at", "id": "id"}, "created_at", lp, "id", "created_at")
        return Page(items=[AlertOut.model_validate(dict(x)) for x in rows], total=total, limit=lp.limit, offset=lp.offset)

    @r.post("/alerts/{id}/ack", response_model=AlertOut, tags=["alerts"])
    def ack_alert(id: int, who: Principal = Depends(require("operate")), conn: sqlite3.Connection = Depends(get_conn)):
        with tx(conn):
            cur = conn.execute("UPDATE alerts SET status='acknowledged', acknowledged_at=?, acknowledged_by=? WHERE id=? AND workspace_id=? AND status='open'",
                               (now_iso(), who.actor, id, who.workspace_id))
            if cur.rowcount:
                audit(conn, who.actor, "alert.ack", str(id), {"status": "acknowledged"}, who.workspace_id)
        row = conn.execute("SELECT * FROM alerts WHERE id=? AND workspace_id=?", (id, who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "alert not found")
        if row["status"] != "acknowledged":
            raise HTTPException(409, "alert is not open")
        return AlertOut.model_validate(dict(row))

    @r.post("/alerts/{id}/close", response_model=AlertOut, tags=["alerts"])
    def close_alert(id: int, body: AlertCloseRequest, who: Principal = Depends(require("operate")), conn: sqlite3.Connection = Depends(get_conn)):
        note = body.resolution_note.strip()
        if len(note) < 3:
            raise HTTPException(422, "resolution_note must contain at least 3 non-whitespace characters")
        with tx(conn):
            cur = conn.execute(
                "UPDATE alerts SET status='closed', closed_at=?, closed_by=?, resolution_note=? WHERE id=? AND workspace_id=? AND status='acknowledged'",
                (now_iso(), who.actor, note, id, who.workspace_id),
            )
            if cur.rowcount:
                audit(conn, who.actor, "alert.close", str(id), {"resolution_note": note}, who.workspace_id)
        row = conn.execute("SELECT * FROM alerts WHERE id=? AND workspace_id=?", (id, who.workspace_id)).fetchone()
        if row is None:
            raise HTTPException(404, "alert not found")
        if row["status"] != "closed":
            raise HTTPException(409, "alert must be acknowledged before closure")
        return AlertOut.model_validate(dict(row))

    # ---- search & aggregation ----
    @r.get("/search", response_model=list[SearchHit], tags=["search"], summary="Global FTS5 search (CVE, asset/package, finding evidence)")
    def search(q: str, kind: str | None = Query(None, pattern="^(cve|asset|finding)$"), limit: int = Query(25, ge=1, le=100),
               who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        sql = "SELECT kind, ref, title, snippet(search_index, 3, '[', ']', '…', 12) AS snippet FROM search_index WHERE search_index MATCH ?"
        params: list = [fts_query(q)]
        if kind:
            sql += " AND kind=?"; params.append(kind)
        hits = [SearchHit.model_validate(dict(x)) for x in conn.execute(sql + " ORDER BY rank LIMIT ?", params + [limit])]
        return hits

    @r.get("/aggregations/affected-assets", tags=["aggregations"], summary="Assets affected by a CVE")
    def affected_assets(cve_id: str, include_resolved: bool = False, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        sql = ("SELECT f.asset_id, a.environment, a.kernel, f.component_name, f.component_version, f.level, f.confidence, f.exposure, f.status, f.id AS finding_id, "
               "json_extract(f.verdict_json, '$.min_safe_target') AS min_safe_target "
               "FROM findings f JOIN assets a ON a.id=f.asset_pk WHERE f.cve_id=? AND f.workspace_id=?")
        if not include_resolved:
            sql += " AND f.status='open'"
        rows = [dict(x) for x in conn.execute(sql + " ORDER BY f.level_rank DESC, f.asset_id", (cve_id.upper(), who.workspace_id))]
        return {"cve_id": cve_id.upper(), "count": len(rows), "assets": rows}

    @r.get("/aggregations/highest-risk-assets", tags=["aggregations"])
    def highest_risk(limit: int = Query(10, ge=1, le=100), who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        rows = conn.execute(
            """SELECT a.asset_id, a.environment, a.exposure, MAX(f.level_rank) AS rank, SUM(f.kev) AS kev_findings, COUNT(*) AS open_findings,
               (SELECT level FROM findings x WHERE x.asset_pk=a.id AND x.status='open' ORDER BY x.level_rank DESC LIMIT 1) AS highest_level
               FROM findings f JOIN assets a ON a.id=f.asset_pk WHERE f.workspace_id=? AND f.status='open'
               GROUP BY a.id ORDER BY rank DESC, kev_findings DESC, open_findings DESC LIMIT ?""",
            (who.workspace_id, limit)).fetchall()
        return {"assets": [{k: v for k, v in dict(x).items() if k != "rank"} for x in rows]}

    @r.get("/changes", tags=["aggregations"], summary="Perubahan sejak timestamp")
    def changes(since: str, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        ws = who.workspace_id
        def q(sql: str, *extra):
            return [dict(x) for x in conn.execute(sql, (ws, since, *extra))]
        return {
            "since": since,
            "new_findings": q("SELECT id, asset_id, cve_id, level FROM findings WHERE workspace_id=? AND first_seen>=?"),
            "level_changes": q("SELECT id, asset_id, cve_id, previous_level, level FROM findings WHERE workspace_id=? AND level_changed_at>=? AND first_seen<?", since),
            "resolved_findings": q("SELECT id, asset_id, cve_id FROM findings WHERE workspace_id=? AND status='resolved' AND updated_at>=?"),
            "new_snapshots": q("SELECT id, asset_id, collected_at FROM snapshots WHERE workspace_id=? AND received_at>=?"),
            "alerts": q("SELECT id, asset_id, kind, message FROM alerts WHERE workspace_id=? AND created_at>=?"),
            "changed_cves": [dict(x) for x in conn.execute("SELECT cve_id, revision, kev FROM cves WHERE updated_at>=? ORDER BY updated_at DESC LIMIT 200", (since,))],
        }

    @r.get("/stats", tags=["aggregations"])
    def stats(request: Request, who: Principal = Depends(require("read")), conn: sqlite3.Connection = Depends(get_conn)):
        return dashboard_stats(conn, who.workspace_id, request.app.state.settings)

    @r.get("/audit", tags=["admin"])
    def audit_log(lp: ListParams = Depends(), action: str | None = None, who: Principal = Depends(require("admin")), conn: sqlite3.Connection = Depends(get_conn)):
        where, params = ["workspace_id=?"], [who.workspace_id]
        if action:
            where.append("action=?"); params.append(action)
        rows, total = listing(conn, "*", "audit_events", where, params, {"at": "at", "id": "id"}, "id", lp, "id", "at")
        return {"items": [dict(x) for x in rows], "total": total, "limit": lp.limit, "offset": lp.offset}

    return r


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        import os

        conn = connect(settings.db_path)
        migrate(conn)
        auth.ensure_bootstrap(conn, os.environ.get("RISKPATCH_BOOTSTRAP_TOKEN", "").strip())
        auth.ensure_bootstrap_admin(conn, os.environ.get("RISKPATCH_BOOTSTRAP_ADMIN_USER", "").strip(), os.environ.get("RISKPATCH_BOOTSTRAP_ADMIN_PASSWORD", ""))
        conn.close()
        yield

    app = FastAPI(title="RiskPatch", version=APP_VERSION, openapi_url="/api/v1/openapi.json", docs_url="/api/v1/docs", redoc_url=None, lifespan=lifespan,
                  description="CVE intelligence server. Token scopes: read, ingest, operate, admin. Send `Authorization: Bearer <token>`.")
    app.state.settings = settings
    limiter = RateLimiter(settings.rate_limit_per_minute)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > settings.max_body_bytes:
            return JSONResponse({"detail": "payload too large"}, status_code=413, headers=SECURITY_HEADERS)
        who = hashlib.sha256((bearer(request) or request.cookies.get("rp_session", "") or (request.client.host if request.client else "-")).encode()).hexdigest()
        if request.url.path != "/api/v1/health" and not limiter.allow(who):
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={**SECURITY_HEADERS, "Retry-After": "60"})
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            if key == "Content-Security-Policy" and request.url.path.startswith("/api/v1/docs"):
                continue  # swagger UI loads its assets from a CDN
            response.headers.setdefault(key, value)
        return response

    app.include_router(build_router())
    from riskpatch.ui import build_ui

    app.include_router(build_ui())
    return app
