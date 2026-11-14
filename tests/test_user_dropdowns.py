import re
from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient

from riskpatch import auth
from riskpatch.api import create_app
from riskpatch.config import get_settings
from riskpatch.db import connect, migrate
from tests.helpers import PASSWORD, register, session_for


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("RISKPATCH_DB", str(tmp_path / "u.sqlite3"))
    monkeypatch.setenv("RISKPATCH_REPORTS", str(tmp_path / "r"))
    monkeypatch.setenv("RISKPATCH_CACHE", str(tmp_path / "c"))
    monkeypatch.setenv("RISKPATCH_OFFLINE", "1")
    settings = get_settings()
    conn = connect(settings.db_path)
    migrate(conn)
    with TestClient(create_app(settings)) as client:
        yield client, conn, settings


def options(html: str, field: str) -> list[str]:
    block = re.search(rf'<select name="{field}">(.*?)</select>', html, re.S)
    assert block, field
    return re.findall(r'<option value="([^"]*)"', block.group(1))


def test_assignee_and_owner_are_dropdowns_of_active_registered_users(env):
    client, conn, _ = env
    register(conn, "SOC", "Platform")
    auth.create_user(conn, "gone", PASSWORD, "viewer", "test")
    conn.execute("UPDATE users SET disabled_at='2026-01-01T00:00:00Z' WHERE username='gone'")
    conn.commit()
    session_for(client, conn, "operator")
    page = client.get("/ui/work").text
    assert "<input name=\"assignee\"" not in page
    names = options(page, "assignee")
    assert "" in names and "SOC" in names and "Platform" in names and "gone" not in names


def test_unregistered_assignee_is_refused_and_registered_one_is_accepted(env):
    client, conn, _ = env
    register(conn, "SOC")
    session_for(client, conn, "operator")
    csrf = auth.csrf_for(client.cookies.get("rp_session"))
    refused = client.post("/ui/actions/work/bulk", data={"csrf": csrf, "k": ["x"], "state": "needs_validation", "assignee": "Stranger"},
                          follow_redirects=False)
    assert "Choose a registered user" in unquote(refused.headers["location"])
    accepted = client.post("/ui/actions/work/bulk", data={"csrf": csrf, "k": ["x"], "state": "needs_validation", "assignee": "SOC"},
                           follow_redirects=False)
    assert "Choose a registered user" not in unquote(accepted.headers["location"])


def test_asset_owner_dropdown_is_offered_and_refused_when_unregistered(env):
    client, conn, _ = env
    register(conn, "Ops")
    conn.execute("INSERT INTO assets (workspace_id, asset_id, first_seen, last_seen, updated_at) VALUES (1, 'web-01', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')")
    conn.commit()
    session_for(client, conn, "admin")
    csrf = auth.csrf_for(client.cookies.get("rp_session"))
    detail = client.get("/ui/assets/web-01").text
    assert "Ops" in options(detail, "owner")
    refused = client.post("/ui/actions/assets/ownership", data={"csrf": csrf, "asset_id": "web-01", "owner": "Nobody"}, follow_redirects=False)
    assert "Choose a registered user" in unquote(refused.headers["location"])
