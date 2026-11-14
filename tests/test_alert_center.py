import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient

from riskpatch import auth
from riskpatch.api import create_app
from riskpatch.config import get_settings
from riskpatch.db import connect, migrate
from tests.helpers import session_for


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("RISKPATCH_DB", str(tmp_path / "al.sqlite3"))
    monkeypatch.setenv("RISKPATCH_REPORTS", str(tmp_path / "r"))
    monkeypatch.setenv("RISKPATCH_CACHE", str(tmp_path / "c"))
    monkeypatch.setenv("RISKPATCH_OFFLINE", "1")
    settings = get_settings()
    conn = connect(settings.db_path)
    migrate(conn)
    with TestClient(create_app(settings)) as client:
        yield client, conn, settings


def seed(conn, asset, count, prefix, status="open"):
    now = datetime.now(timezone.utc)
    conn.executemany(
        "INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at, status, acknowledged_at, acknowledged_by) VALUES (1, ?, 'verdict', ?, ?, ?, ?, ?)",
        [(asset, f"{prefix} {i}", (now - timedelta(minutes=i)).isoformat(), status,
          now.isoformat() if status != "open" else None, "user:seed" if status != "open" else None) for i in range(count)],
    )
    conn.commit()


def alert_ids(text):
    return re.findall(r'name="alert_id" value="(\d+)"', text)


def status_of(conn, ids):
    return {i: conn.execute("SELECT status FROM alerts WHERE id=?", (i,)).fetchone()[0] for i in ids}


def bulk(client, conn, ids, action, note="", csrf=None):
    csrf = csrf or auth.csrf_for(client.cookies.get("rp_session"))
    return client.post("/ui/actions/alerts/bulk", data={"csrf": csrf, "action": action, "resolution_note": note, "alert_id": ids},
                       follow_redirects=False)


def test_alerts_are_paged_one_hundred_per_page(env):
    client, conn, _ = env
    seed(conn, "web-01", 230, "bulk")
    session_for(client, conn, "operator")
    first = client.get("/ui/alerts", params={"view": "open"}).text
    assert len(alert_ids(first)) == 100
    assert "230 results" in first and "offset=100" in first
    last = client.get("/ui/alerts", params={"view": "open", "offset": 200}).text
    assert len(alert_ids(last)) == 30


def test_alerts_can_be_filtered_to_one_asset(env):
    client, conn, _ = env
    seed(conn, "web-01", 120, "a")
    seed(conn, "web-02", 4, "b")
    session_for(client, conn, "operator")
    assert "124 results" in client.get("/ui/alerts", params={"view": "open"}).text
    only = client.get("/ui/alerts", params={"view": "open", "asset": "web-02"}).text
    assert "4 results" in only and len(alert_ids(only)) == 4
    assert '<option value="web-02" selected>' in only and "Clear filter" in only


def test_bulk_acknowledge_moves_only_open_alerts(env):
    client, conn, _ = env
    seed(conn, "web-01", 3, "x")
    seed(conn, "web-01", 1, "held", status="acknowledged")
    session_for(client, conn, "operator")
    ids = [int(i) for i in alert_ids(client.get("/ui/alerts", params={"view": "open"}).text)]
    assert len(ids) == 3
    held = conn.execute("SELECT id FROM alerts WHERE message='held 0'").fetchone()[0]
    done = bulk(client, conn, ids[:2] + [held], "acknowledge")
    location = unquote(done.headers["location"])
    assert "Acknowledged 2 alert(s)." in location and "Skipped 1 that were not open." in location
    assert set(status_of(conn, ids[:2]).values()) == {"acknowledged"}
    assert status_of(conn, [ids[2]])[ids[2]] == "open"


def test_bulk_mark_closed_requires_evidence_and_only_closes_in_assessment(env):
    client, conn, _ = env
    seed(conn, "web-01", 2, "closeme", status="acknowledged")
    seed(conn, "web-01", 1, "stillopen")
    session_for(client, conn, "operator")
    rows = conn.execute("SELECT id, message FROM alerts ORDER BY id").fetchall()
    assessed = [r["id"] for r in rows if r["message"].startswith("closeme")]
    still_open = [r["id"] for r in rows if r["message"].startswith("stillopen")][0]

    no_note = bulk(client, conn, assessed, "close", note=" ")
    assert "at least 3 characters" in unquote(no_note.headers["location"])
    assert set(status_of(conn, assessed).values()) == {"acknowledged"}

    done = bulk(client, conn, assessed + [still_open], "close", note="Patched to 2.4.1 and verified")
    assert "Closed 2 alert(s)." in unquote(done.headers["location"]) and "Skipped 1" in unquote(done.headers["location"])
    assert set(status_of(conn, assessed).values()) == {"closed"}
    assert status_of(conn, [still_open])[still_open] == "open"
    closed = conn.execute("SELECT resolution_note, closed_by FROM alerts WHERE id=?", (assessed[0],)).fetchone()
    assert closed["resolution_note"] == "Patched to 2.4.1 and verified" and closed["closed_by"].startswith("user:operator")
    detail = conn.execute("SELECT detail FROM audit_events WHERE action='alert.close' ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert str(assessed[0]) in detail and "Patched to 2.4.1" in detail


def test_closed_alerts_cannot_be_selected_and_bulk_is_capped(env):
    client, conn, _ = env
    seed(conn, "web-01", 2, "done", status="closed")
    seed(conn, "web-01", 1, "open")
    session_for(client, conn, "operator")
    page = client.get("/ui/alerts", params={"view": "all"}).text
    assert page.count('name="alert_id"') == 3
    assert page.count('disabled aria-label') + page.count('disabled>') >= 2
    assert "Acknowledge (open to in assessment)" in page and "Mark closed (in assessment to closed)" in page
    ids = [r[0] for r in conn.execute("SELECT id FROM alerts")]
    seed(conn, "web-02", 150, "many")
    many = [r[0] for r in conn.execute("SELECT id FROM alerts")]
    refused = bulk(client, conn, many, "acknowledge")
    assert "Select at most 100 alerts at a time." in unquote(refused.headers["location"])


def test_viewer_has_no_bulk_controls_and_cannot_post(env):
    client, conn, _ = env
    seed(conn, "web-01", 3, "v")
    session_for(client, conn, "viewer")
    page = client.get("/ui/alerts", params={"view": "open"}).text
    assert 'name="alert_id"' not in page and "Apply to selected" not in page
    ids = [r[0] for r in conn.execute("SELECT id FROM alerts")]
    assert bulk(client, conn, ids, "acknowledge").status_code == 403
    assert client.post("/ui/actions/alerts/bulk", data={"csrf": "bad", "action": "acknowledge", "alert_id": ids}, follow_redirects=False).status_code == 403
