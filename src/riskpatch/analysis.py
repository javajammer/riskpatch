from __future__ import annotations

import json
import logging
import sqlite3
from packaging.version import InvalidVersion, Version

import httpx
from pydantic import ValidationError

from riskpatch.alerts import changed, emit
from riskpatch.config import RULESET_VERSION, Settings
from riskpatch.cvestore import facts_for
from riskpatch.db import index_text, now_iso, tx
from riskpatch.match import derive_fixed_versions
from riskpatch.inventory import AuthBoundary, Component, Ecosystem, Exposure, Role
from riskpatch.llm import attach, configured
from riskpatch.report import ComponentReport, StackReport, action_for, level_rank, render_markdown, rollup
from riskpatch.rules import CveVerdict, judge

log = logging.getLogger("riskpatch.analysis")


def min_safe_target(component_version: str, patched_versions: list[str]) -> str | None:
    """Return the minimum patched version that is newer than component_version, or None if none exists."""
    try:
        comp_ver = Version(component_version)
    except InvalidVersion:
        return None
    if not patched_versions:
        # No patched versions listed in CVE data; return None with clear indication
        return None
    candidates = []
    for pv in patched_versions:
        try:
            v = Version(pv)
            if v > comp_ver:
                candidates.append(v)
        except InvalidVersion:
            continue
    return str(min(candidates)) if candidates else None


def _enum(cls, value: str, default):
    try:
        return cls(value)
    except ValueError:
        return default


def build_components(rows: list[sqlite3.Row], asset: dict) -> tuple[list[tuple[sqlite3.Row, Component]], list[str]]:
    override = json.loads(asset["metadata_override"] or "{}")
    exposure = _enum(Exposure, override.get("exposure") or asset["exposure"], Exposure.unknown)
    auth = _enum(AuthBoundary, override.get("auth_boundary") or asset["auth_boundary"], AuthBoundary.unknown)
    mitigations = override.get("mitigations") or json.loads(asset["mitigations"] or "[]")
    built, errors = [], []
    for row in rows:
        try:
            comp = Component(
                id=f"c{row['id']}", name=row["name"], version=row["version"], ecosystem=_enum(Ecosystem, row["ecosystem"], Ecosystem.generic),
                vendor=row["vendor"], product=row["product"], role=_enum(Role, row["role"], Role.library), exposure=exposure,
                auth_boundary=auth, used_at_runtime=bool(row["used_at_runtime"]), mitigations=mitigations, distro_package=row["distro_package"],
            )
        except ValidationError as exc:
            errors.append(f"{row['name']} {row['version']}: component invalid ({exc.errors()[0]['msg']})")
            continue
        built.append((row, comp))
    return built, errors


def confidence(verdict: CveVerdict, comp: Component) -> str:
    if verdict.level == "unverified":
        return "low"
    if verdict.exposure_assumed or comp.distro_package:
        return "medium"
    return "high"


def provider_stale(conn: sqlite3.Connection) -> bool:
    return bool(conn.execute("SELECT 1 FROM provider_status WHERE stale=1 LIMIT 1").fetchone())


def select_assets(conn: sqlite3.Connection, workspace_id: int, scope: dict) -> list[sqlite3.Row]:
    if scope.get("asset_id"):
        return conn.execute("SELECT * FROM assets WHERE workspace_id=? AND asset_id=? AND latest_snapshot_id IS NOT NULL", (workspace_id, scope["asset_id"])).fetchall()
    # newest snapshot per asset supersedes older pending ones
    with tx(conn):
        conn.execute(
            """UPDATE snapshots SET analysis_status='superseded', updated_at=? WHERE analysis_status='pending'
               AND id NOT IN (SELECT latest_snapshot_id FROM assets WHERE latest_snapshot_id IS NOT NULL)""",
            (now_iso(),),
        )
    return conn.execute(
        """SELECT a.* FROM assets a JOIN snapshots s ON s.id=a.latest_snapshot_id WHERE a.workspace_id=? AND (
             s.analysis_status='pending' OR EXISTS (
               SELECT 1 FROM components c JOIN cve_affected ca ON ca.match_key=c.match_key JOIN cves v ON v.cve_id=ca.cve_id
               WHERE c.snapshot_id=s.id AND v.updated_at > COALESCE(s.analyzed_at,'')))""",
        (workspace_id,),
    ).fetchall()


def evidence_for(conn: sqlite3.Connection, comp: Component, verdict: CveVerdict, fact_ranges: list, snapshot_id: int, match_note: str) -> list[tuple[str, str]]:
    ev = [
        ("component", f"{comp.name} {comp.version} ({comp.ecosystem.value}) from snapshot #{snapshot_id}"),
        ("affected_range", json.dumps({"ranges": [r.model_dump(exclude_none=True) for r in fact_ranges], "note": match_note})),
        ("cvss", json.dumps({"score": verdict.cvss_score, "severity": verdict.cvss_severity, "attack_vector": verdict.attack_vector})),
        ("kev", "yes" if verdict.kev else "no"),
        ("exposure", json.dumps({"exposure": verdict.exposure, "assumed": verdict.exposure_assumed, "auth_boundary": comp.auth_boundary.value, "role": comp.role.value})),
        ("reachability", verdict.reachability),
        ("rule_trace", json.dumps({"ruleset": RULESET_VERSION, "summary": verdict.one_line, "raises": verdict.raises, "lowers": verdict.lowers})),
    ]
    if comp.distro_package:
        ev.append(("distro_backport", f"paket distro {comp.distro_package}; backport patch perlu diverifikasi lewat changelog vendor"))
    for src in conn.execute("SELECT source, url, fetched_at FROM cve_sources WHERE cve_id=?", (verdict.cve_id,)):
        ev.append(("provenance", json.dumps(dict(src))))
    return ev


def analyze_asset(conn: sqlite3.Connection, settings: Settings, asset: sqlite3.Row, run_id: int, client: httpx.Client | None, counts: dict) -> None:
    snapshot_id = asset["latest_snapshot_id"]
    rows = conn.execute("SELECT * FROM components WHERE snapshot_id=? ORDER BY id", (snapshot_id,)).fetchall()
    built, errors = build_components(rows, dict(asset))
    snap = conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()
    if snap["error_count"]:
        errors.append(f"Collector reported {snap['error_count']} collection error(s)")

    per_component: list[tuple[Component, list[tuple[CveVerdict, list, str]]]] = []
    for row, comp in built:
        items = []
        for fact in facts_for(conn, row["match_key"]):
            verdict = judge(comp, fact)
            if verdict.level == "informational":
                counts["not_affected"] += 1
                continue
            items.append((verdict, fact.ranges, fact.match_note))
        per_component.append((comp, items))

    if client is not None and configured():
        # one summarized request per asset; narrative only, never touches level
        attach([v for _, items in per_component for v, _, _ in items], client)

    stale = provider_stale(conn) or settings.offline
    comp_reports = []
    for comp, items in per_component:
        level = rollup([v.level for v, _, _ in items]) if items else "informational"
        comp_reports.append(ComponentReport(id=comp.id, name=comp.name, version=comp.version, ecosystem=comp.ecosystem.value,
                                            rollup=level, action=action_for(level), cves=[v for v, _, _ in items],
                                            distro_package=comp.distro_package or ""))
    highest = rollup([c.rollup for c in comp_reports]) if comp_reports else "unverified"
    if not comp_reports:
        errors.append("No components with a matchable CPE or ecosystem identity")
    report = StackReport(
        generated_at=now_iso(),
        stale=stale,
        inventory_name=asset["asset_id"],
        environment=asset["environment"] or "",
        highest=highest,
        action=action_for(highest),
        components=comp_reports,
        errors=errors,
        hostname=asset["hostname"] or "",
        os_name=asset["os_name"] or "",
        os_version=asset["os_version"] or "",
        exposure=asset["exposure"] or "",
        tech_stack=[f"{c.name} {c.version}" for c in comp_reports],
    )

    prev_row = conn.execute("SELECT content_json FROM reports WHERE asset_pk=? ORDER BY id DESC LIMIT 1", (asset["id"],)).fetchone()
    previous = None
    if prev_row:
        try:
            previous = StackReport.model_validate_json(prev_row["content_json"])
        except ValidationError:
            previous = None
    reasons = changed(previous, report)
    if stale and (previous is None or not previous.stale):
        reasons.append("CVE data stale: provider failed or offline mode")

    ts = now_iso()
    seen_keys: set[tuple[str, str]] = set()
    with tx(conn):
        for (row, comp), (_c, items) in zip(built, per_component):
            for verdict, ranges, note in items:
                key = (row["match_key"] + "@" + row["version"], verdict.cve_id)
                seen_keys.add(key)
                existing = conn.execute(
                    "SELECT id, level FROM findings WHERE workspace_id=? AND asset_pk=? AND component_key=? AND cve_id=?",
                    (asset["workspace_id"], asset["id"], key[0], verdict.cve_id),
                ).fetchone()
                # feeds rarely list patched versions; fall back to the end of the affected range that contains this version
                mst = min_safe_target(row["version"], verdict.patched_versions or derive_fixed_versions(row["version"], ranges))
                verdict_dict = verdict.model_dump()
                verdict_dict["min_safe_target"] = mst if mst else ""
                values = (snapshot_id, row["name"], row["version"], comp.ecosystem.value, verdict.level, level_rank(verdict.level), verdict.action,
                          confidence(verdict, comp), verdict.cvss_score, int(verdict.kev), verdict.exposure, int(verdict.exposure_assumed),
                          verdict.reachability, verdict.one_line, json.dumps(verdict_dict), RULESET_VERSION, mst or "")
                if existing is None:
                    cur = conn.execute(
                        """INSERT INTO findings (snapshot_id, component_name, component_version, ecosystem, level, level_rank, action, confidence,
                           cvss_score, kev, exposure, exposure_assumed, reachability, one_line, verdict_json, ruleset_version, fixed_version,
                           workspace_id, asset_pk, asset_id, component_key, cve_id, first_seen, last_seen, level_changed_at, updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        values + (asset["workspace_id"], asset["id"], asset["asset_id"], key[0], verdict.cve_id, ts, ts, ts, ts),
                    )
                    fid = cur.lastrowid
                    counts["created"] += 1
                else:
                    fid = existing["id"]
                    flipped = existing["level"] != verdict.level
                    conn.execute(
                        """UPDATE findings SET snapshot_id=?, component_name=?, component_version=?, ecosystem=?, level=?, level_rank=?, action=?,
                           confidence=?, cvss_score=?, kev=?, exposure=?, exposure_assumed=?, reachability=?, one_line=?, verdict_json=?,
                           ruleset_version=?, fixed_version=?, status='open', last_seen=?, updated_at=?,
                           previous_level=CASE WHEN ? THEN level ELSE previous_level END,
                           level_changed_at=CASE WHEN ? THEN ? ELSE level_changed_at END WHERE id=?""",
                        values + (ts, ts, int(flipped), int(flipped), ts, fid),
                    )
                    counts["updated"] += 1
                conn.execute("DELETE FROM finding_evidence WHERE finding_id=?", (fid,))
                evidence = evidence_for(conn, comp, verdict, ranges, snapshot_id, note)
                conn.executemany("INSERT INTO finding_evidence (finding_id, kind, detail, created_at) VALUES (?,?,?,?)", [(fid, k, d, ts) for k, d in evidence])
                index_text(conn, "finding", str(fid), f"{verdict.cve_id} {row['name']} {asset['asset_id']}",
                           " ".join(d for _, d in evidence) + " " + verdict.summary)
        open_rows = conn.execute("SELECT id, component_key, cve_id FROM findings WHERE asset_pk=? AND status='open'", (asset["id"],)).fetchall()
        for old in open_rows:
            if (old["component_key"], old["cve_id"]) not in seen_keys:
                conn.execute("UPDATE findings SET status='resolved', updated_at=? WHERE id=?", (ts, old["id"]))
                counts["resolved"] += 1
        sync_alerts(conn, asset, ts, counts)
        conn.execute(
            """INSERT INTO reports (workspace_id, analysis_run_id, asset_pk, asset_id, snapshot_id, generated_at, highest, stale, content_json, content_md)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (asset["workspace_id"], run_id, asset["id"], asset["asset_id"], snapshot_id, report.generated_at, report.highest, int(report.stale),
             json.dumps(report.model_dump()), render_markdown(report)),
        )
        conn.execute("UPDATE snapshots SET analysis_status='analyzed', analyzed_at=?, updated_at=? WHERE id=?", (ts, ts, snapshot_id))
    counts["assets"] += 1
    if reasons:
        _webhook(settings, report, reasons)


def sync_alerts(conn: sqlite3.Connection, asset: sqlite3.Row, ts: str, counts: dict) -> None:
    """Keep one alert per CVE finding: open findings get an alert, resolved findings close theirs."""
    created = conn.execute(
        """INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at, finding_id)
           SELECT f.workspace_id, f.asset_id, CASE WHEN f.kev=1 THEN 'kev' ELSE 'verdict' END,
                  f.cve_id || ' · ' || f.component_name || ' ' || f.component_version || ' · ' || f.level,
                  f.first_seen, f.id
           FROM findings f
           WHERE f.asset_pk=? AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.finding_id=f.id)""",
        (asset["id"],),
    ).rowcount
    counts["alerts"] += created
    conn.execute(
        """UPDATE alerts SET status='open', closed_at=NULL, closed_by=NULL, resolution_note='',
                  acknowledged_at=NULL, acknowledged_by=NULL
           WHERE status='closed' AND closed_by='system:analysis'
             AND finding_id IN (SELECT id FROM findings WHERE asset_pk=? AND status='open')""",
        (asset["id"],),
    )
    conn.execute(
        """UPDATE alerts SET status='closed', closed_at=?, closed_by='system:analysis',
                  resolution_note='CVE no longer matches this component in analysis'
           WHERE status!='closed' AND finding_id IN (SELECT id FROM findings WHERE asset_pk=? AND status='resolved')""",
        (ts, asset["id"]),
    )


def _webhook(settings: Settings, report: StackReport, reasons: list[str]) -> None:
    import os

    url = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
    try:
        with httpx.Client(timeout=10, follow_redirects=False) as hook:
            emit(report, reasons, settings.reports_dir, url, hook)
    except OSError:
        log.warning("alerts.jsonl cannot be written to %s", settings.reports_dir)


def run_analysis(conn: sqlite3.Connection, settings: Settings, workspace_id: int, scope: dict, job_id: int | None,
                 heartbeat=lambda: None, log_event=lambda level, msg: None) -> dict:
    counts = {"assets": 0, "created": 0, "updated": 0, "resolved": 0, "not_affected": 0, "alerts": 0, "failed": 0}
    with tx(conn):
        run_id = conn.execute("INSERT INTO analysis_runs (workspace_id, job_id, started_at, ruleset_version) VALUES (?,?,?,?)",
                              (workspace_id, job_id, now_iso(), RULESET_VERSION)).lastrowid
    assets = select_assets(conn, workspace_id, scope)
    log_event("info", f"{len(assets)} assets analyzed")
    client = httpx.Client(timeout=30) if configured() else None
    failed_ids: set[str] = set()
    try:
        for asset in assets:
            try:
                analyze_asset(conn, settings, asset, run_id, client, counts)
            except Exception as exc:  # one broken asset must not block the rest, and last results stay intact
                counts["failed"] += 1
                failed_ids.add(asset["asset_id"])
                log_event("error", f"{asset['asset_id']}: {exc}")
                log.exception("analisis %s gagal", asset["asset_id"])
            heartbeat()
    finally:
        if client:
            client.close()
    try:
        from riskpatch import freshness

        scoped = [asset["asset_id"] for asset in assets] if scope.get("asset_id") else None
        freshness.mark_correlation_current(conn, workspace_id, freshness.utc_now(), scoped, frozenset(failed_ids))
    except Exception:  # coverage bookkeeping must never fail an analysis run
        log.exception("could not record correlation freshness")
    with tx(conn):
        conn.execute("UPDATE analysis_runs SET finished_at=?, assets_processed=?, findings_created=?, findings_updated=?, findings_resolved=? WHERE id=?",
                     (now_iso(), counts["assets"], counts["created"], counts["updated"], counts["resolved"], run_id))
    counts["analysis_run_id"] = run_id
    return counts
