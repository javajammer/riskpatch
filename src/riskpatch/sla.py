"""SLA targets per priority band and the due dates derived from them.

The clock starts when the group was first detected (earliest first_seen of its findings). It is never reset by reassignment,
a change of severity, or a new snapshot. Items that are mitigated, verified, deferred or not applicable are not counted as overdue.
Deferral has no expiry yet (Exceptions are a later phase), so it is shown as its own state rather than hidden.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from riskpatch.db import audit, get_setting, now_iso, set_setting, tx
from riskpatch.risk import BANDS

DEFAULTS = {"P1": (4, 7), "P2": (24, 30), "P3": (72, 90), "P4": (168, 180)}  # band: (acknowledge within hours, remediate within days)
PAUSED_STATES = frozenset({"mitigated", "verified", "deferred", "not_applicable"})
LIMITS = {"ack_hours": (1, 24 * 365), "fix_days": (1, 3650)}


def _key(band: str, field: str) -> str:
    return f"sla_{band.lower()}_{field}"


def load(conn: sqlite3.Connection) -> dict[str, tuple[int, int]]:
    out = {}
    for band, _m, _n in BANDS:
        ack, fix = DEFAULTS[band]
        for field, default in (("ack_hours", ack), ("fix_days", fix)):
            raw = get_setting(conn, _key(band, field))
            value = int(raw) if raw and raw.isdigit() else default
            if field == "ack_hours":
                ack = value
            else:
                fix = value
        out[band] = (ack, fix)
    return out


def save(conn: sqlite3.Connection, ws: int, actor: str, targets: dict[str, tuple[int, int]]) -> dict:
    """Validate and store targets (band: (ack hours, fix days)). Audited with old and new values."""
    before = load(conn)
    new = {}
    for band, _m, _n in BANDS:
        ack, fix = targets.get(band, before[band])
        for field, value in (("ack_hours", ack), ("fix_days", fix)):
            lo, hi = LIMITS[field]
            if not isinstance(value, int) or not lo <= value <= hi:
                raise ValueError(f"{band} {field.replace('_', ' ')} must be a whole number from {lo} to {hi}")
        new[band] = (ack, fix)
    # remediation must not be due before acknowledgement, and a more urgent band must not be slower than a less urgent one
    order = [b for b, _m, _n in BANDS]
    for hi_band, lo_band in zip(order, order[1:]):
        if new[hi_band][1] > new[lo_band][1] or new[hi_band][0] > new[lo_band][0]:
            raise ValueError(f"{hi_band} must not have longer targets than {lo_band}")
    for band, (ack, fix) in new.items():
        if ack > fix * 24:
            raise ValueError(f"{band}: acknowledgement cannot be due after remediation")
    changed = {b: {"from": before[b], "to": new[b]} for b in new if new[b] != before[b]}
    if changed:
        for band, (ack, fix) in new.items():
            set_setting(conn, _key(band, "ack_hours"), str(ack))
            set_setting(conn, _key(band, "fix_days"), str(fix))
        with tx(conn):
            audit(conn, actor, "sla.update", None, changed, ws)
    return changed



def evaluate(band: str, state: str, first_seen: datetime, acknowledged_at: datetime | None, targets: dict[str, tuple[int, int]], now: datetime) -> dict:
    """Due dates and whether each is breached. `acknowledged_at` is when the first decision was recorded."""
    ack_hours, fix_days = targets[band]
    ack_due, fix_due = first_seen + timedelta(hours=ack_hours), first_seen + timedelta(days=fix_days)
    paused = state in PAUSED_STATES
    return {
        "ack_due": ack_due, "fix_due": fix_due, "paused": paused,
        "ack_overdue": acknowledged_at is None and now > ack_due,
        "fix_overdue": not paused and now > fix_due,
    }
