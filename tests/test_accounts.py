import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from riskpatch import auth
from riskpatch.api import create_app
from riskpatch.config import get_settings
from riskpatch.db import connect, migrate
from urllib.parse import unquote

from tests.helpers import PASSWORD, session_for


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("RISKPATCH_DB", str(tmp_path / "a.sqlite3"))
    monkeypatch.setenv("RISKPATCH_REPORTS", str(tmp_path / "r"))
    monkeypatch.setenv("RISKPATCH_CACHE", str(tmp_path / "c"))
    monkeypatch.setenv("RISKPATCH_OFFLINE", "1")
    settings = get_settings()
    conn = connect(settings.db_path)
    migrate(conn)
    with TestClient(create_app(settings)) as client:
        yield client, conn, settings


def csrf(client) -> str:
    return auth.csrf_for(client.cookies.get("rp_session"))


def test_viewer_sees_only_own_account_and_admin_posts_are_refused(env):
    client, conn, _ = env
    session_for(client, conn, "viewer")
    page = client.get("/ui/settings").text
    assert "My account" in page and "Change password" in page
    assert "Users" not in re.findall(r"<h2>([^<]+)</h2>", page)
    assert "API tokens" not in re.findall(r"<h2>([^<]+)</h2>", page)
    assert client.post("/ui/actions/users/create", data={"csrf": csrf(client), "username": "eve", "role": "admin", "password": PASSWORD},
                       follow_redirects=False).status_code == 403
    assert client.post("/ui/actions/tokens/create", data={"csrf": csrf(client), "name": "x", "scopes": ["read"]},
                       follow_redirects=False).status_code == 403


def test_operator_cannot_manage_users_or_tokens(env):
    client, conn, _ = env
    session_for(client, conn, "operator")
    headings = re.findall(r"<h2>([^<]+)</h2>", client.get("/ui/settings").text)
    assert "Users" not in headings and "API tokens" not in headings
    assert client.post("/ui/actions/users/create", data={"csrf": csrf(client), "username": "eve", "role": "viewer", "password": PASSWORD},
                       follow_redirects=False).status_code == 403


def test_admin_creates_user_who_can_sign_in_and_duplicates_are_refused(env):
    client, conn, _ = env
    session_for(client, conn, "admin")
    created = client.post("/ui/actions/users/create", data={"csrf": csrf(client), "username": "bob.ops", "role": "operator", "password": PASSWORD},
                          follow_redirects=False)
    assert created.status_code == 303 and "User bob.ops created" in unquote(created.headers["location"])
    duplicate = client.post("/ui/actions/users/create", data={"csrf": csrf(client), "username": "BOB.ops", "role": "viewer", "password": PASSWORD},
                            follow_redirects=False)
    assert "already" in unquote(duplicate.headers["location"])
    short = client.post("/ui/actions/users/create", data={"csrf": csrf(client), "username": "carol", "role": "viewer", "password": "short"},
                        follow_redirects=False)
    assert "at least" in unquote(short.headers["location"])

    client.cookies.clear()
    assert client.post("/ui/login", data={"username": "bob.ops", "password": PASSWORD}, follow_redirects=False).status_code == 303
    assert "Coverage" in client.get("/ui/coverage").text and "Refresh all" in client.get("/ui/coverage").text


def test_password_change_keeps_current_session_and_signs_out_others(env):
    client, conn, _ = env
    current = session_for(client, conn, "viewer")
    user_id = conn.execute("SELECT id FROM users WHERE role='viewer' ORDER BY id DESC LIMIT 1").fetchone()[0]
    other = auth.create_session(conn, user_id)
    wrong = client.post("/ui/actions/account/password", data={"csrf": csrf(client), "current_password": "nope-nope-nope",
                        "new_password": "brand new password 1", "confirm": "brand new password 1"}, follow_redirects=False)
    assert "Current password is incorrect" in unquote(wrong.headers["location"])
    changed = client.post("/ui/actions/account/password", data={"csrf": csrf(client), "current_password": PASSWORD,
                          "new_password": "brand new password 1", "confirm": "brand new password 1"}, follow_redirects=False)
    assert changed.status_code == 303 and "Password changed" in unquote(changed.headers["location"])
    assert auth.authenticate_session(conn, current) is not None
    assert auth.authenticate_session(conn, other) is None


def test_admin_cannot_disable_self_and_reset_signs_out_target(env):
    client, conn, _ = env
    session_for(client, conn, "admin")
    me = conn.execute("SELECT id FROM users WHERE role='admin' ORDER BY id DESC LIMIT 1").fetchone()[0]
    refused = client.post(f"/ui/actions/users/{me}/status", data={"csrf": csrf(client), "action": "disable"}, follow_redirects=False)
    assert "cannot disable your own account" in unquote(refused.headers["location"])
    target = auth.create_user(conn, "dave", PASSWORD, "viewer", "test")
    target_session = auth.create_session(conn, target)
    client.post(f"/ui/actions/users/{target}/password", data={"csrf": csrf(client), "new_password": "replacement password 2"}, follow_redirects=False)
    assert auth.authenticate_session(conn, target_session) is None
    assert auth.authenticate_password(conn, "dave", "replacement password 2") is not None


def test_disabled_user_cannot_sign_in_and_loses_active_sessions(env):
    client, conn, _ = env
    admin = session_for(client, conn, "admin")
    target = auth.create_user(conn, "frank", PASSWORD, "operator", "test")
    live = auth.create_session(conn, target)
    client.post(f"/ui/actions/users/{target}/status", data={"csrf": csrf(client), "action": "disable"}, follow_redirects=False)
    assert auth.authenticate_session(conn, live) is None
    assert auth.authenticate_password(conn, "frank", PASSWORD) is None
    assert auth.authenticate_session(conn, admin) is not None


def test_admin_token_shows_owner_purpose_once_and_revocation_blocks_api(env):
    client, conn, _ = env
    session_for(client, conn, "admin")
    created = client.post("/ui/actions/tokens/create", data={"csrf": csrf(client), "name": "awx-prod", "purpose": "AWX collector for prod",
                          "scopes": ["ingest"]})
    assert created.status_code == 200
    token = re.search(r"<pre>(rp_[^<]+)</pre>", created.text).group(1)
    row = conn.execute("SELECT name, purpose, owner_user_id FROM api_tokens WHERE name='awx-prod'").fetchone()
    assert row["purpose"] == "AWX collector for prod" and row["owner_user_id"] is not None

    listing = client.get("/ui/settings").text
    assert "awx-prod" in listing and "AWX collector for prod" in listing and token not in listing
    assert client.get("/api/v1/assets", headers={"Authorization": f"Bearer {token}"}).status_code == 403

    token_id = conn.execute("SELECT id FROM api_tokens WHERE name='awx-prod'").fetchone()[0]
    assert client.post(f"/ui/actions/tokens/{token_id}/revoke", data={"csrf": csrf(client)}, follow_redirects=False).status_code == 303
    assert conn.execute("SELECT revoked_at FROM api_tokens WHERE id=?", (token_id,)).fetchone()[0] is not None
    assert auth.authenticate(conn, token) is None


def test_logout_ends_the_session(env):
    client, conn, _ = env
    secret = session_for(client, conn, "viewer")
    client.post("/ui/logout", data={"csrf": csrf(client)}, follow_redirects=False)
    assert auth.authenticate_session(conn, secret) is None


def test_bootstrap_admin_is_created_once_from_environment(env):
    _, conn, _ = env
    assert auth.ensure_bootstrap_admin(conn, "root", PASSWORD) is True
    assert auth.ensure_bootstrap_admin(conn, "root2", PASSWORD) is False
    assert conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] == 1


def test_login_is_rate_limited_per_client(env):
    client, conn, _ = env
    statuses = [client.post("/ui/login", data={"username": "x", "password": "y"}, follow_redirects=False).status_code for _ in range(11)]
    assert statuses[-1] == 429 and 401 in statuses
