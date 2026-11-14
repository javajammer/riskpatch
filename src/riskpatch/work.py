"""Work queue: open findings grouped into decisions (CVE + package version + recommended fix) and the triage history on them.

The queue is computed live from open findings; a `work_items` row exists only once a person has decided something about a group,
and `work_events` keeps every decision (who, what, how many servers, from which snapshots). A group that has no row is "New".
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from riskpatch import risk, sla
from riskpatch.db import audit, now_iso, tx

STATE_LABELS = {
    "new": "New", "needs_validation": "Needs validation", "accepted": "Accepted", "scheduled": "Scheduled",
    "mitigated": "Mitigated", "verified": "Verified", "deferred": "Deferred", "not_applicable": "Not applicable",
}
# 'verified' needs a fresh snapshot that shows the affected version gone; that automatic check is not built yet, so it cannot be set by hand.
SETTABLE_STATES = tuple(s for s in STATE_LABELS if s != "verified")
APPLICABILITY_LABELS = {"unknown": "Unknown", "confirmed": "Confirmed", "potential": "Potential", "not_applicable": "Not applicable"}
NEEDS_REASON = {"deferred", "not_applicable", "mitigated"}
ASSIGNEE_MAX = 120
NOTE_MAX = 1000
BULK_MAX = 200
MAX_DEFER_DAYS = 180
CONTROL_MAX = 500
EXPIRER = "system:exceptions"
SEP = "\x1f"


@dataclass(frozen=True)
class Key:
    cve_id: str
    ecosystem: str
    component_name: str
    component_version: str
    fixed_version: str = ""

    def encode(self) -> str:
        return SEP.join((self.cve_id, self.ecosystem, self.component_name, self.component_version, self.fixed_version))

    @classmethod
    def decode(cls, text: str) -> "Key":
        parts = (text or "").split(SEP)
        if len(parts) != 5 or not parts[0]:
            raise ValueError("invalid work item key")
        return cls(*parts)


def _where(key: Key) -> tuple[str, list]:
    return ("f.cve_id=? AND f.ecosystem=? AND f.component_name=? AND f.component_version=? AND COALESCE(f.fixed_version,'')=?",
            [key.cve_id, key.ecosystem, key.component_name, key.component_version, key.fixed_version])


QUEUE_VIEWS = ("all", "kev", "needs_validation", "no_fix", "mine", "past_sla")
LEVEL_ORDER = ("critical", "high", "medium", "low", "unverified", "informational")  # low before unverified: they share level_rank 1
CACHE_TTL = 300.0  # seconds; computing every group scans the findings table (1-2 s at 200k findings)
_CACHE: dict[tuple, tuple[float, tuple, list]] = {}


def _parse(ts: str | None) -> datetime:
    try:
        return datetime.fromisoformat((ts or "").replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _stamp(conn: sqlite3.Connection, ws: int) -> tuple:
    """Cheap fingerprint of everything the groups depend on. A decision, an SLA change or any new finding write changes it,
    so every worker process sees fresh data right away. Asset deletions change the asset count, so they are picked up too."""
    w = conn.execute("SELECT COUNT(*), COALESCE(MAX(updated_at),'') FROM work_items WHERE workspace_id=?", (ws,)).fetchone()
    sla_changed = conn.execute("SELECT COALESCE(MAX(updated_at),'') FROM system_settings WHERE key LIKE 'sla\\_%' ESCAPE '\\'").fetchone()[0]
    f = conn.execute("SELECT COALESCE(MAX(updated_at),'') FROM findings").fetchone()[0]  # served by idx_findings_updated
    assets = conn.execute("SELECT COUNT(*) FROM assets WHERE workspace_id=?", (ws,)).fetchone()[0]  # an asset deletion removes its findings
    return (w[0], w[1], sla_changed, f, assets)


def groups(conn: sqlite3.Connection, ws: int, now: datetime | None = None, targets: dict | None = None, key: "Key | None" = None) -> list[dict]:
    """Every group of open findings with its decision (if any), priority score and SLA dates, or only the group for `key`.
    The full list is cached briefly (validated by _stamp); an explicit `now`, `targets` or `key` always computes fresh."""
    if now is None and targets is None and key is None:
        ck = (conn.execute("PRAGMA database_list").fetchone()[2], ws)
        stamp = _stamp(conn, ws)
        hit = _CACHE.get(ck)
        if hit and hit[1] == stamp and time.monotonic() - hit[0] < CACHE_TTL:
            return hit[2]
        rows = _compute(conn, ws, None, None, None)
        _CACHE[ck] = (time.monotonic(), stamp, rows)
        return rows
    return _compute(conn, ws, now, targets, key)


def _compute(conn: sqlite3.Connection, ws: int, now: datetime | None, targets: dict | None, key: "Key | None") -> list[dict]:
    now = now or datetime.now(timezone.utc)
    targets = targets or sla.load(conn)
    key_sql, key_params = ("", [])
    if key is not None:
        key_sql, key_params = (" AND " + _where(key)[0], _where(key)[1])
    rows = conn.execute(
        f"""WITH g AS (
              SELECT f.cve_id, f.ecosystem, f.component_name, f.component_version, COALESCE(f.fixed_version,'') AS fixed,
                     COUNT(DISTINCT f.asset_pk) AS servers, COUNT(*) AS findings, SUM(f.kev) AS kev, MIN(f.first_seen) AS first_seen,
                     MAX(f.exposure='internet') AS internet, MIN(CASE a.business_tier WHEN 'tier1' THEN 1 WHEN 'tier2' THEN 2 WHEN 'tier3' THEN 3 ELSE 9 END) AS tier_rank,
                     SUM(CASE WHEN f.level='critical' THEN 1 ELSE 0 END) AS n_critical, SUM(CASE WHEN f.level='high' THEN 1 ELSE 0 END) AS n_high,
                     SUM(CASE WHEN f.level='medium' THEN 1 ELSE 0 END) AS n_medium, SUM(CASE WHEN f.level='low' THEN 1 ELSE 0 END) AS n_low,
                     SUM(CASE WHEN f.level='unverified' THEN 1 ELSE 0 END) AS n_unverified
              FROM findings f JOIN assets a ON a.id=f.asset_pk WHERE f.workspace_id=? AND f.status='open'{key_sql}
              GROUP BY f.cve_id, f.ecosystem, f.component_name, f.component_version, COALESCE(f.fixed_version,''))
            SELECT g.*, w.id AS work_id, COALESCE(w.state,'new') AS state, COALESCE(w.assignee,'') AS assignee,
                   COALESCE(w.applicability,'unknown') AS applicability, w.created_at AS acked_at, w.updated_at AS decided_at
            FROM g LEFT JOIN work_items w ON w.workspace_id=? AND w.cve_id=g.cve_id AND w.ecosystem=g.ecosystem
                 AND w.component_name=g.component_name AND w.component_version=g.component_version AND w.fixed_version=g.fixed""",
        (ws, *key_params, ws)).fetchall()
    out = []
    tiers = {1: "tier1", 2: "tier2", 3: "tier3"}
    for r in rows:
        d = dict(r)
        d["lvl"] = next((lv for lv in LEVEL_ORDER if lv != "informational" and d[f"n_{lv}"]), "informational")
        first_seen = _parse(d["first_seen"])
        sc = risk.score(d["lvl"], bool(d["kev"]), bool(d["internet"]), tiers.get(d["tier_rank"], ""), bool(d["fixed"]),
                        max(0, (now - first_seen).days), d["n_unverified"] == d["findings"])
        d.update(score=sc.points, band=sc.band, why=sc.explain(), reasons=sc.reasons)
        d.update(sla.evaluate(sc.band, d["state"], first_seen, _parse(d["acked_at"]) if d["acked_at"] else None, targets, now))
        out.append(d)
    out.sort(key=lambda d: (d["paused"], -d["score"], -d["servers"], d["cve_id"]))
    return out


def queue(conn: sqlite3.Connection, ws: int, view: str = "all", state: str = "", me: str = "", limit: int = 50, offset: int = 0,
          now: datetime | None = None) -> tuple[list[dict], int]:
    """Work items, highest priority first (items already decided as mitigated, deferred or not applicable sink to the bottom)."""
    rows = groups(conn, ws, now)
    if state in STATE_LABELS:
        rows = [r for r in rows if r["state"] == state]
    if view == "kev":
        rows = [r for r in rows if r["kev"]]
    elif view == "needs_validation":
        rows = [r for r in rows if r["state"] == "needs_validation"]
    elif view == "no_fix":
        rows = [r for r in rows if not r["fixed"]]
    elif view == "mine":
        rows = [r for r in rows if me and r["assignee"] == me]
    elif view == "past_sla":
        rows = [r for r in rows if r["fix_overdue"] or r["ack_overdue"]]
    return rows[max(0, offset):max(0, offset) + limit], len(rows)


def summary(conn: sqlite3.Connection, ws: int, now: datetime | None = None) -> dict:
    """Counts for the Overview, from the same cached groups as the queue."""
    rows = groups(conn, ws, now)
    active = [r for r in rows if not r["paused"]]
    return {
        "items": len(rows), "p1": sum(1 for r in active if r["band"] == "P1"),
        "past_sla": sum(1 for r in rows if r["fix_overdue"]), "ack_overdue": sum(1 for r in rows if r["ack_overdue"]),
        "kev_unassigned": sum(1 for r in active if r["kev"] and not r["assignee"]),
        "undecided": sum(1 for r in rows if r["state"] == "new"),
        "deferrals_soon": conn.execute("SELECT COUNT(*) FROM work_exceptions WHERE workspace_id=? AND status='active' AND expires_on<=?",
                                       (ws, ((now or datetime.now(timezone.utc)).date() + timedelta(days=14)).isoformat())).fetchone()[0],
    }


def invalidate_summary() -> None:
    """Drop this process's cache (other processes notice through _stamp)."""
    _CACHE.clear()


def servers(conn: sqlite3.Connection, ws: int, key: Key) -> list[sqlite3.Row]:
    where, params = _where(key)
    return conn.execute(
        f"""SELECT a.asset_id, a.owner, a.business_tier, a.latest_snapshot_id, f.id AS finding_id, f.level, f.exposure, f.confidence, f.kev, f.cvss_score
            FROM findings f JOIN assets a ON a.id=f.asset_pk
            WHERE f.workspace_id=? AND f.status='open' AND {where} ORDER BY f.level_rank DESC, a.asset_id""", [ws, *params]).fetchall()


def item(conn: sqlite3.Connection, ws: int, key: Key) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM work_items WHERE workspace_id=? AND cve_id=? AND ecosystem=? AND component_name=? AND component_version=? AND fixed_version=?",
        (ws, *key.encode().split(SEP))).fetchone()


def history(conn: sqlite3.Connection, work_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM work_events WHERE work_item_id=? ORDER BY id DESC", (work_id,)).fetchall()


def _clean(state: str, applicability: str, assignee: str, note: str) -> tuple[str, str, str, str]:
    state, applicability = (state or "").strip(), (applicability or "unknown").strip() or "unknown"
    assignee, note = " ".join((assignee or "").split()), " ".join((note or "").split())
    if state == "verified":
        raise ValueError("Verified is set only from a fresh snapshot that shows the affected version gone; it cannot be set by hand")
    if state not in SETTABLE_STATES:
        raise ValueError("unknown state")
    if applicability not in APPLICABILITY_LABELS:
        raise ValueError("unknown applicability")
    if len(assignee) > ASSIGNEE_MAX:
        raise ValueError(f"assignee is longer than {ASSIGNEE_MAX} characters")
    if len(note) > NOTE_MAX:
        raise ValueError(f"note is longer than {NOTE_MAX} characters")
    if state in NEEDS_REASON and len(note) < 3:
        raise ValueError(f"a reason is required for {STATE_LABELS[state]}")
    if state == "not_applicable":
        applicability = "not_applicable"
    return state, applicability, assignee, note


def _clean_deferral(state: str, expires_on: str, control: str, today: date | None = None) -> tuple[str, str]:
    """A deferral is only valid with an expiry date in the future (at most MAX_DEFER_DAYS away); other states ignore both fields."""
    if state != "deferred":
        return "", ""
    today = today or datetime.now(timezone.utc).date()
    control = " ".join((control or "").split())
    if len(control) > CONTROL_MAX:
        raise ValueError(f"the compensating control is longer than {CONTROL_MAX} characters")
    try:
        when = date.fromisoformat((expires_on or "").strip())
    except ValueError:
        raise ValueError("a deferral needs an expiry date (YYYY-MM-DD)") from None
    if when <= today:
        raise ValueError("the expiry date must be in the future")
    if when > today + timedelta(days=MAX_DEFER_DAYS):
        raise ValueError(f"a deferral can last at most {MAX_DEFER_DAYS} days; ask for a new one when it expires")
    return when.isoformat(), control


def triage(conn: sqlite3.Connection, ws: int, key: Key, actor: str, state: str, applicability: str = "unknown", assignee: str = "", note: str = "",
           expires_on: str = "", control: str = "") -> dict:
    """Record a decision for a group. Creates the work item on first use and always appends a history event.
    A deferral also records an exception (reason, compensating control, expiry); leaving the Deferred state closes it."""
    state, applicability, assignee, note = _clean(state, applicability, assignee, note)
    expires_on, control = _clean_deferral(state, expires_on, control)
    affected = servers(conn, ws, key)
    if not affected:
        raise LookupError("no open findings match this group")
    snapshots = sorted({r["latest_snapshot_id"] for r in affected if r["latest_snapshot_id"]})[:500]
    ts = now_iso()
    with tx(conn):
        current = item(conn, ws, key)
        if current is None:
            work_id = conn.execute(
                """INSERT INTO work_items (workspace_id, cve_id, ecosystem, component_name, component_version, fixed_version, state, applicability, assignee,
                   decision, reason, created_at, created_by, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ws, *key.encode().split(SEP), state, applicability, assignee, STATE_LABELS[state], note, ts, actor, ts, actor)).lastrowid
            before = None
        else:
            work_id, before = current["id"], current["state"]
            conn.execute("UPDATE work_items SET state=?, applicability=?, assignee=?, decision=?, reason=?, updated_at=?, updated_by=? WHERE id=?",
                         (state, applicability, assignee, STATE_LABELS[state], note, ts, actor, work_id))
        event_note = note + (f" (deferred until {expires_on})" if expires_on else "")
        conn.execute(
            "INSERT INTO work_events (work_item_id, at, actor, from_state, to_state, applicability, assignee, note, server_count, snapshot_ids, servers) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (work_id, ts, actor, before or "new", state, applicability, assignee, event_note, len(affected), json.dumps(snapshots),
             json.dumps(sorted({r["asset_id"] for r in affected})[:2000])))
        conn.execute("UPDATE work_exceptions SET status='superseded', closed_at=?, closed_by=?, closed_note=? WHERE work_item_id=? AND status='active'",
                     (ts, actor, f"replaced by decision: {STATE_LABELS[state]}", work_id))
        if state == "deferred":
            conn.execute(
                "INSERT INTO work_exceptions (workspace_id, work_item_id, reason, compensating_control, requested_by, created_at, expires_on, server_count) VALUES (?,?,?,?,?,?,?,?)",
                (ws, work_id, note, control, actor, ts, expires_on, len(affected)))
        audit(conn, actor, "work.triage", f"{key.cve_id} {key.component_name} {key.component_version}",
              {"from": before or "new", "to": state, "applicability": applicability, "assignee": assignee, "servers": len(affected)}, ws)
    invalidate_summary()
    return {"work_id": work_id, "servers": len(affected), "from": before or "new", "to": state}


def triage_bulk(conn: sqlite3.Connection, ws: int, keys: list[Key], actor: str, state: str, applicability: str = "unknown", assignee: str = "", note: str = "",
                expires_on: str = "", control: str = "") -> dict:
    """Apply one decision to several groups; each group gets its own history event. Validates once before changing anything."""
    _clean(state, applicability, assignee, note)
    _clean_deferral(state, expires_on, control)
    unique = list(dict.fromkeys(keys))
    if not unique:
        raise ValueError("no work item selected")
    if len(unique) > BULK_MAX:
        raise ValueError(f"too many items at once (limit {BULK_MAX})")
    done = skipped = servers_total = 0
    for key in unique:
        try:
            servers_total += triage(conn, ws, key, actor, state, applicability, assignee, note, expires_on, control)["servers"]
            done += 1
        except LookupError:
            skipped += 1  # the group no longer has open findings
    with tx(conn):
        audit(conn, actor, "work.triage.bulk", f"{done} items", {"to": state, "assignee": assignee, "items": done, "skipped": skipped, "servers": servers_total}, ws)
    return {"updated": done, "skipped": skipped, "servers": servers_total}


def alert_counts(conn: sqlite3.Connection, ws: int, key: Key) -> dict[str, int]:
    """Alerts raised for the findings of this work item, by alert status."""
    where, params = _where(key)
    return {r["status"]: r["n"] for r in conn.execute(
        f"SELECT a.status, COUNT(*) AS n FROM alerts a JOIN findings f ON f.id=a.finding_id WHERE a.workspace_id=? AND {where} GROUP BY a.status", [ws, *params])}


def for_findings(conn: sqlite3.Connection, ws: int, finding_ids: list[int]) -> dict[int, tuple[Key, str] | None]:
    """For alert rows: finding id -> (work item key, its state). A finding that is no longer open and was never triaged maps to None,
    because there is no work item to open."""
    ids = sorted({i for i in finding_ids if i})
    if not ids:
        return {}
    rows = conn.execute(
        f"SELECT id, status, cve_id, ecosystem, component_name, component_version, COALESCE(fixed_version,'') AS fixed FROM findings WHERE id IN ({','.join('?' * len(ids))})", ids).fetchall()
    states: dict[Key, str | None] = {}
    out: dict[int, tuple[Key, str] | None] = {}
    for r in rows:
        key = Key(r["cve_id"], r["ecosystem"], r["component_name"], r["component_version"], r["fixed"])
        if key not in states:
            saved = item(conn, ws, key)
            states[key] = saved["state"] if saved else None
        state = states[key]
        out[r["id"]] = (key, state or "new") if (state or r["status"] == "open") else None
    return out


# ---- verification ------------------------------------------------------------------------------------------------------

VERIFIER = "system:verification"


def still_open(conn: sqlite3.Connection, ws: int, key: Key) -> set[str]:
    """Servers that currently have an open finding for this group (one scan; reuse it for many servers)."""
    where, params = _where(key)
    return {r[0] for r in conn.execute(f"SELECT DISTINCT f.asset_id FROM findings f WHERE f.workspace_id=? AND f.status='open' AND {where}", [ws, *params])}


def server_evidence(conn: sqlite3.Connection, ws: int, asset_id: str, since: str, still: set[str]) -> dict:
    """Evidence for one server after a fix. 'clear' only when its latest snapshot was collected after `since`, that snapshot is analyzed,
    and the group has no open finding on it. A server that has not reported again stays 'waiting': silence is never proof."""
    a = conn.execute(
        """SELECT a.asset_id, s.id AS snapshot_id, s.collected_at, s.analysis_status FROM assets a
           LEFT JOIN snapshots s ON s.id=a.latest_snapshot_id WHERE a.workspace_id=? AND a.asset_id=?""", (ws, asset_id)).fetchone()
    base = {"asset_id": asset_id, "snapshot_id": None, "collected_at": None}
    if a is None:
        return {**base, "status": "removed", "label": "Server no longer exists"}
    base.update(snapshot_id=a["snapshot_id"], collected_at=a["collected_at"])
    if not a["collected_at"] or a["collected_at"] <= since:
        return {**base, "status": "waiting", "label": "Waiting for a new snapshot"}
    if a["analysis_status"] != "analyzed":
        return {**base, "status": "waiting", "label": "Waiting for analysis of the new snapshot"}
    if asset_id in still:
        return {**base, "status": "affected", "label": "Still affected after the fix"}
    return {**base, "status": "clear", "label": "Confirmed clear"}


def verification(conn: sqlite3.Connection, ws: int, key: Key, mitigated_at: str, server_ids: list[str]) -> dict:
    """Is the mitigation confirmed by evidence on every server it covered? Servers that no longer exist are set aside."""
    still = still_open(conn, ws, key)
    rows = [server_evidence(conn, ws, asset_id, mitigated_at, still) for asset_id in server_ids]
    counted = [r for r in rows if r["status"] != "removed"]
    clear = [r for r in counted if r["status"] == "clear"]
    return {"servers": rows, "clear": len(clear), "total": len(counted), "verified": bool(counted) and len(clear) == len(counted),
            "affected": sum(1 for r in counted if r["status"] == "affected"), "waiting": sum(1 for r in counted if r["status"] == "waiting")}


def latest_mitigation(conn: sqlite3.Connection, work_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM work_events WHERE work_item_id=? AND to_state='mitigated' ORDER BY id DESC LIMIT 1", (work_id,)).fetchone()


def mark_verified(conn: sqlite3.Connection, ws: int, it: sqlite3.Row, server_ids: list[str], snapshot_ids: list[int], note: str, actor: str = VERIFIER) -> None:
    """Set an item to Verified by the system, with the evidence in its history. Never reachable from a form."""
    key = Key(it["cve_id"], it["ecosystem"], it["component_name"], it["component_version"], it["fixed_version"])
    ts = now_iso()
    with tx(conn):
        conn.execute("UPDATE work_items SET state='verified', decision=?, updated_at=?, updated_by=? WHERE id=?", (STATE_LABELS["verified"], ts, actor, it["id"]))
        conn.execute(
            "INSERT INTO work_events (work_item_id, at, actor, from_state, to_state, applicability, assignee, note, server_count, snapshot_ids, servers) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (it["id"], ts, actor, it["state"], "verified", it["applicability"], it["assignee"], note, len(server_ids), json.dumps(sorted(set(snapshot_ids))[:500]), json.dumps(server_ids)))
        conn.execute("UPDATE work_exceptions SET status='superseded', closed_at=?, closed_by=?, closed_note='verified' WHERE work_item_id=? AND status='active'", (ts, actor, it["id"]))
        audit(conn, actor, "work.verified", f"{key.cve_id} {key.component_name} {key.component_version}", {"servers": len(server_ids), "snapshots": len(set(snapshot_ids))}, ws)
    invalidate_summary()


def verify_mitigated(conn: sqlite3.Connection, ws: int) -> int:
    """Promote Mitigated items to Verified when fresh snapshots confirm every covered server is clear. Returns how many were promoted.
    Items whose mitigation predates server tracking (no recorded server list) are left for a person to re-record."""
    promoted = 0
    for it in conn.execute("SELECT * FROM work_items WHERE workspace_id=? AND state='mitigated'", (ws,)).fetchall():
        ev = latest_mitigation(conn, it["id"])
        servers_ = json.loads(ev["servers"] or "[]") if ev else []
        if not servers_:
            continue
        key = Key(it["cve_id"], it["ecosystem"], it["component_name"], it["component_version"], it["fixed_version"])
        res = verification(conn, ws, key, ev["at"], servers_)
        if not res["verified"]:
            continue
        snaps = sorted({r["snapshot_id"] for r in res["servers"] if r["snapshot_id"]})[:500]
        mark_verified(conn, ws, it, servers_, snaps, f"Fresh snapshots from {res['clear']} server(s) no longer show this CVE on this package version.")
        promoted += 1
    if promoted:
        invalidate_summary()
    return promoted


# ---- exceptions ---------------------------------------------------------------------------------------------------------

def exceptions(conn: sqlite3.Connection, ws: int, view: str = "active", today: date | None = None) -> list[dict]:
    """Exceptions with their work item, soonest expiry first. view: active | soon (expires within 30 days) | closed."""
    today = today or datetime.now(timezone.utc).date()
    where = {"active": "e.status='active'", "soon": "e.status='active' AND e.expires_on<=?", "closed": "e.status!='active'"}.get(view, "e.status='active'")
    params: list = [ws] + ([(today + timedelta(days=30)).isoformat()] if view == "soon" else [])
    rows = conn.execute(
        f"""SELECT e.*, w.cve_id, w.ecosystem, w.component_name, w.component_version, w.fixed_version, w.state AS item_state
            FROM work_exceptions e JOIN work_items w ON w.id=e.work_item_id WHERE e.workspace_id=? AND {where}
            ORDER BY e.expires_on, e.id DESC LIMIT 500""", params).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["days_left"] = (date.fromisoformat(r["expires_on"]) - today).days
        d["key"] = Key(r["cve_id"], r["ecosystem"], r["component_name"], r["component_version"], r["fixed_version"])
        out.append(d)
    return out


def _reopen(conn: sqlite3.Connection, ws: int, exc: sqlite3.Row, actor: str, status: str, note: str, ts: str) -> None:
    """Close an exception and, if its item is still Deferred, send the item back to Needs validation."""
    conn.execute("UPDATE work_exceptions SET status=?, closed_at=?, closed_by=?, closed_note=? WHERE id=?", (status, ts, actor, note, exc["id"]))
    item_row = conn.execute("SELECT * FROM work_items WHERE id=?", (exc["work_item_id"],)).fetchone()
    if item_row is not None and item_row["state"] == "deferred":
        conn.execute("UPDATE work_items SET state='needs_validation', decision=?, updated_at=?, updated_by=? WHERE id=?",
                     (STATE_LABELS["needs_validation"], ts, actor, item_row["id"]))
        conn.execute(
            "INSERT INTO work_events (work_item_id, at, actor, from_state, to_state, applicability, assignee, note, server_count, snapshot_ids, servers) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (item_row["id"], ts, actor, "deferred", "needs_validation", item_row["applicability"], item_row["assignee"], note, exc["server_count"], "[]", "[]"))
    audit(conn, actor, f"work.exception.{status}", f"exception #{exc['id']}", {"item": exc["work_item_id"], "note": note}, ws)


def expire_exceptions(conn: sqlite3.Connection, ws: int, today: date | None = None) -> int:
    """Close exceptions whose date has passed and reopen their items. The SLA clock is NOT reset, so the item may be overdue at once."""
    today = today or datetime.now(timezone.utc).date()
    due = conn.execute("SELECT * FROM work_exceptions WHERE workspace_id=? AND status='active' AND expires_on<?", (ws, today.isoformat())).fetchall()
    ts = now_iso()
    for exc in due:
        with tx(conn):
            _reopen(conn, ws, exc, EXPIRER, "expired", f"Deferral expired on {exc['expires_on']}; the work is open again.", ts)
    if due:
        invalidate_summary()
    return len(due)


def revoke_exception(conn: sqlite3.Connection, ws: int, exception_id: int, actor: str, note: str = "") -> None:
    exc = conn.execute("SELECT * FROM work_exceptions WHERE id=? AND workspace_id=?", (exception_id, ws)).fetchone()
    if exc is None or exc["status"] != "active":
        raise LookupError("no active exception with that id")
    note = " ".join((note or "").split())
    if len(note) < 3:
        raise ValueError("a reason is required to revoke an exception")
    with tx(conn):
        _reopen(conn, ws, exc, actor, "revoked", note[:NOTE_MAX], now_iso())
    invalidate_summary()
