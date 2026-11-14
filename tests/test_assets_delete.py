import re
from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient

from riskpatch import auth
from riskpatch.api import create_app
from riskpatch.api.app import dashboard_stats
from riskpatch.config import get_settings
from riskpatch.db import connect, migrate
from riskpatch.jobs import claim, enqueue, run_job
from tests.helpers import session_for
from tests.test_api import h, payload


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("RISKPATCH_DB", str(tmp_path / "d.sqlite3"))
    monkeypatch.setenv("RISKPATCH_REPORTS", str(tmp_path / "r"))
    monkeypatch.setenv("RISKPATCH_CACHE", str(tmp_path / "c"))
    monkeypatch.setenv("RISKPATCH_OFFLINE", "1")
    settings = get_settings()
    conn = connect(settings.db_path)
    migrate(conn)
    tokens = {s: auth.create_token(conn, f"t-{s}", [s]) for s in ("ingest", "operate", "admin")}
    with TestClient(create_app(settings)) as client:
        yield client, tokens, conn, settings


def drain(conn, settings):
    while (job := claim(conn, settings)) is not None:
        run_job(conn, settings, job)


def build(client, tokens, conn, settings, asset_id):
    body = payload()
    body["asset_id"] = asset_id
    body["facts"]["runtimes"][0]["version"] = "8.2.10"  # inside the bundled fixture range 8.2.0 to 8.2.20
    r = client.post("/api/v1/ingest/snapshots", json=body, headers=h(tokens["ingest"]))
    assert r.status_code in (200, 201), r.text
    enqueue(conn, "cve_sync", "test", {}, 1)
    drain(conn, settings)
    enqueue(conn, "analysis", "test", {"asset_id": asset_id}, 1)
    drain(conn, settings)


def counts_for(conn, asset_id):
    aid = conn.execute("SELECT id FROM assets WHERE asset_id=?", (asset_id,)).fetchone()
    if aid is None:
        return None
    pk = aid[0]
    return {
        "findings": conn.execute("SELECT COUNT(*) FROM findings WHERE asset_pk=?", (pk,)).fetchone()[0],
        "reports": conn.execute("SELECT COUNT(*) FROM reports WHERE asset_pk=?", (pk,)).fetchone()[0],
        "snapshots": conn.execute("SELECT COUNT(*) FROM snapshots WHERE asset_pk=?", (pk,)).fetchone()[0],
        "components": conn.execute("SELECT COUNT(*) FROM components WHERE asset_pk=?", (pk,)).fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM alerts WHERE asset_id=? OR finding_id IN (SELECT id FROM findings WHERE asset_pk=?)", (asset_id, pk)).fetchone()[0],
    }


def test_admin_api_deletes_asset_and_every_derived_row_and_keeps_others(env):
    client, tokens, conn, settings = env
    build(client, tokens, conn, settings, "web-01")
    build(client, tokens, conn, settings, "web-02")
    conn.execute("INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at) VALUES (1, 'web-01', 'kev', 'manual', '2026-01-01T00:00:00Z')")
    conn.commit()
    before = counts_for(conn, "web-01")
    other_before = counts_for(conn, "web-02")
    assert before["findings"] > 0 and before["reports"] > 0 and before["snapshots"] > 0 and before["alerts"] > 0

    r = client.post("/api/v1/assets/delete", json={"asset_ids": ["web-01"]}, headers=h(tokens["admin"]))
    assert r.status_code == 200, r.text
    assert r.json()["assets"] == ["web-01"] and r.json()["rows"]["findings"] == before["findings"]
    assert counts_for(conn, "web-01") is None
    assert conn.execute("SELECT COUNT(*) FROM search_index WHERE kind='asset' AND ref='web-01'").fetchone()[0] == 0
    assert counts_for(conn, "web-02") == other_before
    audit = conn.execute("SELECT detail FROM audit_events WHERE action='asset.delete'").fetchone()
    assert audit and '"findings"' in audit[0] and "web-01" in audit[0]
    assert dashboard_stats(conn, 1, settings)["findings_open"] == other_before["findings"]


def test_only_admin_can_delete_and_unknown_or_busy_assets_are_refused(env):
    client, tokens, conn, settings = env
    build(client, tokens, conn, settings, "web-01")
    assert client.post("/api/v1/assets/delete", json={"asset_ids": ["web-01"]}, headers=h(tokens["operate"])).status_code == 403
    assert client.post("/api/v1/assets/delete", json={"asset_ids": ["missing"]}, headers=h(tokens["admin"])).status_code == 404
    enqueue(conn, "analysis", "test", {"asset_id": "web-01"}, 1)
    busy = client.post("/api/v1/assets/delete", json={"asset_ids": ["web-01"]}, headers=h(tokens["admin"]))
    assert busy.status_code == 409 and counts_for(conn, "web-01") is not None


def test_ui_bulk_delete_is_admin_only_and_removes_selected_assets(env):
    client, tokens, conn, settings = env
    build(client, tokens, conn, settings, "web-01")
    build(client, tokens, conn, settings, "web-02")
    build(client, tokens, conn, settings, "web-03")

    session_for(client, conn, "operator")
    op_page = client.get("/ui/assets").text
    assert "Delete selected" not in op_page  # operators may bulk-assign owners but never see delete

    client.cookies.clear()
    session_for(client, conn, "admin")
    page = client.get("/ui/assets").text
    assert 'name="asset_id" value="web-01"' in page and "Delete selected" in page
    csrf = auth.csrf_for(client.cookies.get("rp_session"))
    done = client.post("/ui/actions/assets/delete", data={"csrf": csrf, "asset_id": ["web-01", "web-02"]}, follow_redirects=False)
    assert done.status_code == 303 and "Deleted 2 asset(s)" in unquote(done.headers["location"])
    assert counts_for(conn, "web-01") is None and counts_for(conn, "web-02") is None and counts_for(conn, "web-03") is not None

    assert client.post("/ui/actions/assets/delete", data={"csrf": "bad", "asset_id": ["web-03"]}, follow_redirects=False).status_code == 403


def test_deleted_asset_is_recreated_as_new_when_collector_reports_again(env):
    client, tokens, conn, settings = env
    build(client, tokens, conn, settings, "web-01")
    client.post("/api/v1/assets/delete", json={"asset_ids": ["web-01"]}, headers=h(tokens["admin"]))
    build(client, tokens, conn, settings, "web-01")
    assert counts_for(conn, "web-01")["findings"] > 0
