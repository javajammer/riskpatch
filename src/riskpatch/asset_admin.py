from __future__ import annotations

import json
import sqlite3

from riskpatch.db import audit, now_iso, tx

TIERS = {"tier1": "Tier 1", "tier2": "Tier 2", "tier3": "Tier 3"}
OWNERSHIP_FIELDS = ("owner", "business_tier", "service", "maintenance_window")
OWNERSHIP_MAX = 120


def _marks(values: list) -> str:
    return ",".join("?" * len(values))


def delete_assets(conn: sqlite3.Connection, workspace_id: int, asset_ids: list[str], actor: str) -> dict:
    """Permanently delete assets with everything derived from them. Audited with per-table row counts."""
    ids = sorted({a.strip() for a in asset_ids if a and a.strip()})
    if not ids:
        raise ValueError("no asset selected")
    found = conn.execute(
        f"SELECT id, asset_id FROM assets WHERE workspace_id=? AND asset_id IN ({_marks(ids)})", [workspace_id, *ids]
    ).fetchall()
    if not found:
        raise LookupError("no matching assets")
    for row in found:
        scope = json.dumps({"asset_id": row["asset_id"]}, sort_keys=True)
        busy = conn.execute(
            "SELECT id FROM jobs WHERE workspace_id=? AND scope_json=? AND status IN ('queued','running') LIMIT 1",
            (workspace_id, scope),
        ).fetchone()
        if busy:
            raise RuntimeError(f"analysis for {row['asset_id']} is queued or running; delete it again when that finishes")

    pks = [r["id"] for r in found]
    aids = [r["asset_id"] for r in found]
    counts: dict[str, int] = {}

    def run(label: str, sql: str, params: list) -> None:
        counts[label] = conn.execute(sql, params).rowcount

    with tx(conn):
        finding_ids = [r[0] for r in conn.execute(f"SELECT id FROM findings WHERE asset_pk IN ({_marks(pks)})", pks)]
        fmarks = _marks(finding_ids) if finding_ids else "NULL"
        run("alerts", f"DELETE FROM alerts WHERE workspace_id=? AND (asset_id IN ({_marks(aids)}) OR finding_id IN ({fmarks}))",
            [workspace_id, *aids, *finding_ids])
        run("finding_evidence", f"DELETE FROM finding_evidence WHERE finding_id IN ({fmarks})", finding_ids)
        run("search_index_findings", f"DELETE FROM search_index WHERE kind='finding' AND ref IN ({fmarks})", [str(x) for x in finding_ids])
        run("search_map_findings", f"DELETE FROM search_map WHERE kind='finding' AND ref IN ({fmarks})", [str(x) for x in finding_ids])
        run("findings", f"DELETE FROM findings WHERE asset_pk IN ({_marks(pks)})", pks)
        run("reports", f"DELETE FROM reports WHERE asset_pk IN ({_marks(pks)})", pks)
        snap_ids = [r[0] for r in conn.execute(f"SELECT id FROM snapshots WHERE asset_pk IN ({_marks(pks)})", pks)]
        smarks = _marks(snap_ids) if snap_ids else "NULL"
        run("snapshot_facts", f"DELETE FROM snapshot_facts WHERE snapshot_id IN ({smarks})", snap_ids)
        run("components", f"DELETE FROM components WHERE asset_pk IN ({_marks(pks)})", pks)
        run("snapshots", f"DELETE FROM snapshots WHERE asset_pk IN ({_marks(pks)})", pks)
        run("inventory_snapshots", f"DELETE FROM inventory_snapshots WHERE asset_pk IN ({_marks(pks)})", pks)
        entry_ids = [r[0] for r in conn.execute(
            f"SELECT id FROM cache_entries WHERE workspace_id=? AND scope_type='asset' AND scope_id IN ({_marks(aids)})", [workspace_id, *aids])]
        emarks = _marks(entry_ids) if entry_ids else "NULL"
        run("cache_state_events", f"DELETE FROM cache_state_events WHERE entry_id IN ({emarks})", entry_ids)
        run("cache_entries", f"DELETE FROM cache_entries WHERE id IN ({emarks})", entry_ids)
        run("refresh_jobs", f"DELETE FROM refresh_jobs WHERE workspace_id=? AND target IN ({_marks(aids)})", [workspace_id, *aids])
        run("search_index_assets", f"DELETE FROM search_index WHERE kind='asset' AND ref IN ({_marks(aids)})", aids)
        run("search_map_assets", f"DELETE FROM search_map WHERE kind='asset' AND ref IN ({_marks(aids)})", aids)
        run("assets", f"DELETE FROM assets WHERE id IN ({_marks(pks)})", pks)
        audit(conn, actor, "asset.delete", ", ".join(aids), {"assets": aids, "rows": counts}, workspace_id)
    return {"assets": aids, "rows": counts}


def _clean_ownership(fields: dict) -> dict[str, str]:
    unknown = set(fields) - set(OWNERSHIP_FIELDS)
    if unknown:
        raise ValueError(f"unknown field: {', '.join(sorted(unknown))}")
    new: dict[str, str] = {}
    for name, value in fields.items():
        if value is None:
            continue
        value = " ".join(str(value).split())  # trim and collapse whitespace
        if len(value) > OWNERSHIP_MAX:
            raise ValueError(f"{name} is longer than {OWNERSHIP_MAX} characters")
        if name == "business_tier" and value and value not in TIERS:
            raise ValueError("business_tier must be tier1, tier2, tier3 or empty")
        new[name] = value
    return new


def set_ownership(conn: sqlite3.Connection, workspace_id: int, asset_id: str, actor: str, **fields: str | None) -> dict[str, tuple[str, str]]:
    """Set who owns a server and how important it is. Only the given fields change (None = keep). Audited with old and new values.
    Returns {field: (old, new)} for the fields that actually changed."""
    new = _clean_ownership(fields)
    row = conn.execute("SELECT * FROM assets WHERE workspace_id=? AND asset_id=?", (workspace_id, asset_id)).fetchone()
    if row is None:
        raise LookupError("asset not found")
    changes = {k: (row[k], v) for k, v in new.items() if row[k] != v}
    if not changes:
        return {}
    ts = now_iso()
    with tx(conn):
        sets = ", ".join(f"{k}=?" for k in changes)
        conn.execute(f"UPDATE assets SET {sets}, ownership_updated_at=?, ownership_updated_by=?, updated_at=? WHERE id=?",
                     [*(v[1] for v in changes.values()), ts, actor, ts, row["id"]])
        audit(conn, actor, "asset.ownership", asset_id, {k: {"from": old, "to": to} for k, (old, to) in changes.items()}, workspace_id)
    return changes


BULK_MAX = 1000


def set_ownership_bulk(conn: sqlite3.Connection, workspace_id: int, asset_ids: list[str], actor: str, **fields: str | None) -> dict:
    """Apply the same ownership values to many servers. Unlike a single edit, an empty field means 'leave as is', so a bulk
    action can never blank out data by accident. One audit event lists the servers and the values."""
    new = {k: v for k, v in _clean_ownership(fields).items() if v != ""}
    if not new:
        raise ValueError("fill in at least one field; empty fields are left unchanged")
    ids = sorted({a.strip() for a in asset_ids if a and a.strip()})
    if not ids:
        raise ValueError("no server selected")
    if len(ids) > BULK_MAX:
        raise ValueError(f"too many servers at once (limit {BULK_MAX})")
    rows = conn.execute(f"SELECT * FROM assets WHERE workspace_id=? AND asset_id IN ({_marks(ids)})", [workspace_id, *ids]).fetchall()
    if not rows:
        raise LookupError("no matching servers")
    targets = [r for r in rows if any(r[k] != v for k, v in new.items())]
    ts = now_iso()
    with tx(conn):
        sets = ", ".join(f"{k}=?" for k in new)
        for r in targets:
            conn.execute(f"UPDATE assets SET {sets}, ownership_updated_at=?, ownership_updated_by=?, updated_at=? WHERE id=?",
                         [*new.values(), ts, actor, ts, r["id"]])
        if targets:
            audit(conn, actor, "asset.ownership.bulk", f"{len(targets)} assets",
                  {"fields": new, "assets": [r["asset_id"] for r in targets]}, workspace_id)
    return {"matched": len(rows), "changed": len(targets), "fields": new}
