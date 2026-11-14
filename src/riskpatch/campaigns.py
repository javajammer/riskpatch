"""Remediation campaigns: a plan that groups work items, names the servers, an owner, a window, a change ticket and a backout plan.

A campaign plans and tracks; it never deploys. What people report per server (attempted, updated, failed, ...) is recorded as reported.
Whether a fix really worked is computed from fresh snapshots (work.server_evidence), so "Verified" can never be typed in.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import date

from riskpatch import work
from riskpatch.db import audit, now_iso, tx

STATUS_LABELS = {"planned": "Planned", "scheduled": "Scheduled", "in_progress": "In progress", "completed": "Completed", "cancelled": "Cancelled"}
REPORTED_LABELS = {"planned": "Planned", "attempted": "Attempted", "updated": "Updated", "failed": "Failed", "unreachable": "Unreachable", "excepted": "Excepted"}
# transitions people may make; Scheduled additionally needs approval, a window and a backout plan
NEXT = {"planned": {"scheduled", "cancelled"}, "scheduled": {"in_progress", "planned", "cancelled"}, "in_progress": {"completed", "cancelled"}, "completed": set(), "cancelled": set()}
EDITABLE = ("planned", "scheduled")
PLANNABLE_STATES = {"new", "needs_validation", "accepted", "scheduled"}
NAME_MAX, TEXT_MAX, ITEMS_MAX = 120, 1000, 200


def _text(value: str | None, label: str, limit: int = TEXT_MAX) -> str:
    value = " ".join((value or "").split())
    if len(value) > limit:
        raise ValueError(f"{label} is longer than {limit} characters")
    return value


def _day(value: str | None, label: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        raise ValueError(f"{label} must be a date (YYYY-MM-DD)") from None


def _event(conn: sqlite3.Connection, campaign_id: int, actor: str, action: str, detail: str = "") -> None:
    conn.execute("INSERT INTO campaign_events (campaign_id, at, actor, action, detail) VALUES (?,?,?,?,?)", (campaign_id, now_iso(), actor, action, detail))


def get(conn: sqlite3.Connection, ws: int, campaign_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM campaigns WHERE id=? AND workspace_id=?", (campaign_id, ws)).fetchone()
    if row is None:
        raise LookupError("campaign not found")
    return row


def create(conn: sqlite3.Connection, ws: int, actor: str, name: str, keys: list[work.Key], owner: str = "", window_start: str = "", window_end: str = "",
           ticket_id: str = "", backout_plan: str = "") -> int:
    name = _text(name, "name", NAME_MAX)
    if len(name) < 3:
        raise ValueError("give the campaign a name of at least 3 characters")
    owner, ticket_id, backout_plan = _text(owner, "owner", 120), _text(ticket_id, "ticket", 120), _text(backout_plan, "backout plan")
    window_start, window_end = _day(window_start, "window start"), _day(window_end, "window end")
    if window_start and window_end and window_end < window_start:
        raise ValueError("the window cannot end before it starts")
    unique = list(dict.fromkeys(keys))
    if not unique:
        raise ValueError("select at least one work item")
    if len(unique) > ITEMS_MAX:
        raise ValueError(f"too many items in one campaign (limit {ITEMS_MAX})")
    targets: dict[work.Key, list[str]] = {}
    for key in unique:
        saved = work.item(conn, ws, key)
        if saved is not None and saved["state"] not in PLANNABLE_STATES:
            raise ValueError(f"{key.cve_id} {key.component_name} is {work.STATE_LABELS[saved['state']]} and cannot be planned; reopen it first")
        affected = sorted({r["asset_id"] for r in work.servers(conn, ws, key)})
        if not affected:
            raise ValueError(f"{key.cve_id} {key.component_name} has no open findings left")
        targets[key] = affected
    for key in unique:  # a planned item is Scheduled; items already further along keep their state
        saved = work.item(conn, ws, key)
        if saved is None or saved["state"] in ("new", "needs_validation", "accepted"):
            work.triage(conn, ws, key, actor, "scheduled", saved["applicability"] if saved else "unknown", owner or (saved["assignee"] if saved else ""), f"Planned in campaign '{name}'")
    ts = now_iso()
    with tx(conn):
        cid = conn.execute(
            """INSERT INTO campaigns (workspace_id, name, owner, window_start, window_end, ticket_id, backout_plan, status, created_at, created_by, updated_at, updated_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (ws, name, owner, window_start, window_end, ticket_id, backout_plan, "planned", ts, actor, ts, actor)).lastrowid
        servers_all: set[str] = set()
        for key, assets in targets.items():
            wid = work.item(conn, ws, key)["id"]
            conn.execute("INSERT INTO campaign_items (campaign_id, work_item_id) VALUES (?,?)", (cid, wid))
            conn.executemany("INSERT INTO campaign_targets (campaign_id, work_item_id, asset_id) VALUES (?,?,?)", [(cid, wid, a) for a in assets])
            servers_all.update(assets)
        conn.executemany("INSERT INTO campaign_servers (campaign_id, asset_id, updated_at, updated_by) VALUES (?,?,?,?)", [(cid, a, ts, actor) for a in sorted(servers_all)])
        _event(conn, cid, actor, "created", f"{len(unique)} item(s), {len(servers_all)} server(s)")
        audit(conn, actor, "campaign.create", f"campaign #{cid}", {"name": name, "items": len(unique), "servers": len(servers_all)}, ws)
    work.invalidate_summary()
    return cid


def update_details(conn: sqlite3.Connection, ws: int, campaign_id: int, actor: str, **fields: str | None) -> bool:
    """Edit the plan. Changing the window or the backout plan of an approved campaign withdraws the approval: the approver agreed to the old plan."""
    row = get(conn, ws, campaign_id)
    if row["status"] not in EDITABLE:
        raise ValueError("only planned or scheduled campaigns can be edited")
    clean = {}
    for name, value in fields.items():
        if value is None:
            continue
        if name == "name":
            clean[name] = _text(value, "name", NAME_MAX)
            if len(clean[name]) < 3:
                raise ValueError("give the campaign a name of at least 3 characters")
        elif name in ("window_start", "window_end"):
            clean[name] = _day(value, name.replace("_", " "))
        elif name in ("owner", "ticket_id"):
            clean[name] = _text(value, name.replace("_", " "), 120)
        elif name in ("backout_plan", "notes"):
            clean[name] = _text(value, name.replace("_", " "))
        else:
            raise ValueError(f"unknown field: {name}")
    changed = {k: v for k, v in clean.items() if row[k] != v}
    start, end = changed.get("window_start", row["window_start"]), changed.get("window_end", row["window_end"])
    if start and end and end < start:
        raise ValueError("the window cannot end before it starts")
    if not changed:
        return False
    withdraw = bool(row["approved_by"]) and ("window_start" in changed or "window_end" in changed or "backout_plan" in changed)
    ts = now_iso()
    with tx(conn):
        sets = ", ".join(f"{k}=?" for k in changed)
        extra = ", approved_by='', approved_at=NULL" if withdraw else ""
        conn.execute(f"UPDATE campaigns SET {sets}, updated_at=?, updated_by=?{extra} WHERE id=?", [*changed.values(), ts, actor, campaign_id])
        _event(conn, campaign_id, actor, "edited", ", ".join(sorted(changed)) + ("; approval withdrawn, approve again" if withdraw else ""))
        audit(conn, actor, "campaign.edit", f"campaign #{campaign_id}", {"fields": sorted(changed), "approval_withdrawn": withdraw}, ws)
    return True


def approve(conn: sqlite3.Connection, ws: int, campaign_id: int, actor: str) -> None:
    """Approval is a second pair of eyes: the person who made the plan cannot approve it, and it needs a backout plan."""
    row = get(conn, ws, campaign_id)
    if row["status"] not in EDITABLE:
        raise ValueError("only planned or scheduled campaigns can be approved")
    if row["created_by"] == actor:
        raise ValueError("the person who made the plan cannot approve it; ask someone else")
    if not row["backout_plan"]:
        raise ValueError("add a backout plan before approving")
    ts = now_iso()
    with tx(conn):
        conn.execute("UPDATE campaigns SET approved_by=?, approved_at=?, updated_at=?, updated_by=? WHERE id=?", (actor, ts, ts, actor, campaign_id))
        _event(conn, campaign_id, actor, "approved")
        audit(conn, actor, "campaign.approve", f"campaign #{campaign_id}", {}, ws)


def set_status(conn: sqlite3.Connection, ws: int, campaign_id: int, actor: str, status: str, note: str = "") -> None:
    row = get(conn, ws, campaign_id)
    if status not in STATUS_LABELS or status not in NEXT[row["status"]]:
        raise ValueError(f"a {STATUS_LABELS[row['status']].lower()} campaign cannot become {STATUS_LABELS.get(status, status).lower()}")
    note = _text(note, "note")
    if status == "cancelled" and len(note) < 3:
        raise ValueError("a reason is required to cancel a campaign")
    if status == "scheduled":
        missing = [m for m, ok in (("approval", row["approved_by"]), ("a backout plan", row["backout_plan"]), ("a change window", row["window_start"] and row["window_end"])) if not ok]
        if missing:
            raise ValueError("scheduling needs " + ", ".join(missing))
    ts = now_iso()
    with tx(conn):
        conn.execute("UPDATE campaigns SET status=?, updated_at=?, updated_by=? WHERE id=?", (status, ts, actor, campaign_id))
        _event(conn, campaign_id, actor, f"status: {row['status']} -> {status}", note)
        audit(conn, actor, "campaign.status", f"campaign #{campaign_id}", {"from": row["status"], "to": status, "note": note}, ws)


def report_servers(conn: sqlite3.Connection, ws: int, campaign_id: int, actor: str, asset_ids: list[str], status: str, note: str = "") -> int:
    """Record what a person did on servers. Results can only be reported once the campaign is scheduled or running."""
    row = get(conn, ws, campaign_id)
    if status not in REPORTED_LABELS:
        raise ValueError("unknown server status")
    if row["status"] not in ("scheduled", "in_progress"):
        raise ValueError("server results can be reported once the campaign is scheduled or in progress")
    note = _text(note, "note")
    if status in ("failed", "unreachable", "excepted") and len(note) < 3:
        raise ValueError(f"a note is required for {REPORTED_LABELS[status]}")
    ids = sorted({a for a in asset_ids if a})
    if not ids:
        raise ValueError("select at least one server")
    known = {r[0] for r in conn.execute("SELECT asset_id FROM campaign_servers WHERE campaign_id=?", (campaign_id,))}
    if set(ids) - known:
        raise ValueError("some selected servers are not part of this campaign")
    ts = now_iso()
    with tx(conn):
        conn.executemany("UPDATE campaign_servers SET reported_status=?, note=?, updated_at=?, updated_by=? WHERE campaign_id=? AND asset_id=?",
                         [(status, note, ts, actor, campaign_id, a) for a in ids])
        _event(conn, campaign_id, actor, f"reported {REPORTED_LABELS[status].lower()}", f"{len(ids)} server(s)" + (f": {note}" if note else ""))
        audit(conn, actor, "campaign.report", f"campaign #{campaign_id}", {"status": status, "servers": len(ids)}, ws)
    return len(ids)


def items(conn: sqlite3.Connection, campaign_id: int) -> list[dict]:
    rows = conn.execute(
        """SELECT w.*, (SELECT COUNT(*) FROM campaign_targets t WHERE t.campaign_id=ci.campaign_id AND t.work_item_id=w.id) AS server_count
           FROM campaign_items ci JOIN work_items w ON w.id=ci.work_item_id WHERE ci.campaign_id=? ORDER BY w.cve_id, w.component_name""", (campaign_id,)).fetchall()
    return [dict(r, key=work.Key(r["cve_id"], r["ecosystem"], r["component_name"], r["component_version"], r["fixed_version"])) for r in rows]


def progress(conn: sqlite3.Connection, ws: int, campaign_id: int) -> dict:
    """Per server: what was reported plus the evidence from snapshots, combined into one plain label.
    A server reported 'Updated' is Awaiting verification until a newer analyzed snapshot shows every planned CVE gone (Verified),
    or Still affected if any is still open. Servers nobody has reported on keep their reported label."""
    its = items(conn, campaign_id)
    targets: dict[int, list[str]] = {}
    for r in conn.execute("SELECT work_item_id, asset_id FROM campaign_targets WHERE campaign_id=?", (campaign_id,)):
        targets.setdefault(r["work_item_id"], []).append(r["asset_id"])
    still: dict[work.Key, set[str]] = {}
    cves = sorted({i["cve_id"] for i in its})
    if cves:  # one query for all items instead of one scan per item
        for r in conn.execute(
                f"""SELECT cve_id, ecosystem, component_name, component_version, COALESCE(fixed_version,'') AS fixed, asset_id FROM findings
                    WHERE workspace_id=? AND status='open' AND cve_id IN ({','.join('?' * len(cves))})""", [ws, *cves]):
            still.setdefault(work.Key(r["cve_id"], r["ecosystem"], r["component_name"], r["component_version"], r["fixed"]), set()).add(r["asset_id"])
    meta = {r["asset_id"]: r for r in conn.execute(
        "SELECT a.asset_id, a.owner, a.business_tier, a.maintenance_window, cs.reported_status, cs.note, cs.updated_at, cs.updated_by "
        "FROM campaign_servers cs LEFT JOIN assets a ON a.asset_id=cs.asset_id AND a.workspace_id=? WHERE cs.campaign_id=?", (ws, campaign_id))}
    by_server: dict[str, list[dict]] = {a: [] for a in meta}
    for it in its:
        for a in targets.get(it["id"], []):
            by_server.setdefault(a, []).append(it)
    rows = []
    per_item: dict[int, dict[str, str]] = {}
    for asset_id, m in sorted(meta.items()):
        reported = m["reported_status"]
        evidence, label = "", REPORTED_LABELS[reported]
        if reported == "updated":
            evs = [(it, work.server_evidence(conn, ws, asset_id, m["updated_at"], still.get(it["key"], set()))["status"]) for it in by_server.get(asset_id, [])]
            for it, st in evs:
                per_item.setdefault(it["id"], {})[asset_id] = st
            states = [st for _it, st in evs]
            evidence = "affected" if "affected" in states else "removed" if states and all(s == "removed" for s in states) else "waiting" if "waiting" in states else "clear"
            label = {"affected": "Still affected", "waiting": "Awaiting verification", "clear": "Verified", "removed": "Server removed"}[evidence]
        rows.append({"asset_id": asset_id, "owner": m["owner"] or "", "tier": m["business_tier"] or "", "window": m["maintenance_window"] or "", "reported": reported,
                     "label": label, "evidence": evidence, "note": m["note"], "updated_at": m["updated_at"], "updated_by": m["updated_by"], "items": len(by_server.get(asset_id, []))})
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["label"]] = counts.get(r["label"], 0) + 1
    return {"servers": rows, "counts": counts, "total": len(rows), "verified": counts.get("Verified", 0), "per_item": per_item, "targets": targets, "items": its}


def change_list(conn: sqlite3.Connection, ws: int, campaign_id: int) -> list[dict]:
    """One row per server and work item, ready for a change ticket or the person doing the work."""
    camp = get(conn, ws, campaign_id)
    prog = {r["asset_id"]: r for r in progress(conn, ws, campaign_id)["servers"]}
    out = []
    for r in conn.execute(
            """SELECT t.asset_id, w.cve_id, w.component_name, w.component_version, w.ecosystem, w.fixed_version FROM campaign_targets t
               JOIN work_items w ON w.id=t.work_item_id WHERE t.campaign_id=? ORDER BY t.asset_id, w.cve_id""", (campaign_id,)):
        p = prog.get(r["asset_id"], {})
        out.append({"server": r["asset_id"], "owner": p.get("owner", ""), "tier": p.get("tier", ""), "server_window": p.get("window", ""),
                    "campaign": camp["name"], "ticket": camp["ticket_id"], "window_start": camp["window_start"], "window_end": camp["window_end"],
                    "cve": r["cve_id"], "package": r["component_name"], "ecosystem": r["ecosystem"], "installed_version": r["component_version"],
                    "upstream_fix": r["fixed_version"] or "No fix known", "reported_status": REPORTED_LABELS.get(p.get("reported", "planned"), ""),
                    "progress": p.get("label", ""), "note": p.get("note", "")})
    return out


def list_campaigns(conn: sqlite3.Connection, ws: int, status: str = "") -> list[sqlite3.Row]:
    where, params = ("AND c.status=?", [status]) if status in STATUS_LABELS else ("", [])
    return conn.execute(
        f"""SELECT c.*, (SELECT COUNT(*) FROM campaign_items i WHERE i.campaign_id=c.id) AS item_count,
                   (SELECT COUNT(*) FROM campaign_servers s WHERE s.campaign_id=c.id) AS server_count,
                   (SELECT COUNT(*) FROM campaign_servers s WHERE s.campaign_id=c.id AND s.reported_status!='planned') AS reported_count
            FROM campaigns c WHERE c.workspace_id=? {where} ORDER BY CASE c.status WHEN 'in_progress' THEN 0 WHEN 'scheduled' THEN 1 WHEN 'planned' THEN 2 ELSE 3 END, c.window_start, c.id DESC LIMIT 300""",
        [ws, *params]).fetchall()


def history(conn: sqlite3.Connection, campaign_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM campaign_events WHERE campaign_id=? ORDER BY id DESC", (campaign_id,)).fetchall()


def auto_progress(conn: sqlite3.Connection, ws: int) -> dict:
    """For campaigns in progress: promote a work item to Verified once every server planned for it was reported updated and a newer analyzed
    snapshot shows it clear; complete the campaign once every server is Verified. Same evidence rule as work.verify_mitigated, nothing is assumed."""
    verified_items = completed = 0
    for camp in conn.execute("SELECT * FROM campaigns WHERE workspace_id=? AND status='in_progress'", (ws,)).fetchall():
        prog = progress(conn, ws, camp["id"])
        for it in prog["items"]:
            if it["state"] in ("verified", "deferred", "not_applicable"):
                continue
            servers_ = prog["targets"].get(it["id"], [])
            evidence = prog["per_item"].get(it["id"], {})
            counted = [a for a in servers_ if evidence.get(a) != "removed"]
            if counted and all(evidence.get(a) == "clear" for a in counted):
                row = conn.execute("SELECT * FROM work_items WHERE id=?", (it["id"],)).fetchone()
                snaps = [r[0] for r in conn.execute(
                    f"SELECT latest_snapshot_id FROM assets WHERE workspace_id=? AND asset_id IN ({','.join('?' * len(counted))}) AND latest_snapshot_id IS NOT NULL", [ws, *counted])]
                work.mark_verified(conn, ws, row, counted, snaps, f"Verified by campaign #{camp['id']} '{camp['name']}': fresh snapshots from {len(counted)} server(s) no longer show it.")
                verified_items += 1
        live = [r for r in prog["servers"] if r["label"] != "Server removed"]
        if live and all(r["label"] == "Verified" for r in live):
            set_status(conn, ws, camp["id"], work.VERIFIER, "completed", f"All {len(live)} server(s) verified by fresh snapshots.")
            completed += 1
    return {"items_verified": verified_items, "campaigns_completed": completed}


def conflicts(conn: sqlite3.Connection, ws: int, campaign_id: int) -> list[dict]:
    """Other open campaigns whose change window overlaps this one on the same servers (double booking). Informational: it does not block."""
    me = get(conn, ws, campaign_id)
    if not (me["window_start"] and me["window_end"]):
        return []
    out = []
    for o in conn.execute(
            """SELECT c.* FROM campaigns c WHERE c.workspace_id=? AND c.id!=? AND c.status IN ('planned','scheduled','in_progress')
               AND c.window_start!='' AND c.window_end!='' AND c.window_start<=? AND ?<=c.window_end""",
            (ws, campaign_id, me["window_end"], me["window_start"])).fetchall():
        shared = [r[0] for r in conn.execute(
            "SELECT a.asset_id FROM campaign_servers a JOIN campaign_servers b ON a.asset_id=b.asset_id WHERE a.campaign_id=? AND b.campaign_id=? ORDER BY 1", (campaign_id, o["id"]))]
        if shared:
            out.append({"id": o["id"], "name": o["name"], "status": o["status"], "window": f'{o["window_start"]} → {o["window_end"]}', "servers": shared})
    return out
