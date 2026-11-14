import csv
import gzip
import io
import json
import re
from datetime import datetime, timedelta, timezone
from html import unescape
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from riskpatch import auth
from riskpatch.api import create_app
from riskpatch.api.app import dashboard_stats
from riskpatch.config import get_settings
from riskpatch.db import connect, migrate
from riskpatch.jobs import claim, run_job
from riskpatch.scheduler import tick
from riskpatch.ui import label_of
from tests.helpers import session_for, register


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("RISKPATCH_DB", str(tmp_path / "t.sqlite3"))
    monkeypatch.setenv("RISKPATCH_REPORTS", str(tmp_path / "r"))
    monkeypatch.setenv("RISKPATCH_CACHE", str(tmp_path / "c"))
    monkeypatch.setenv("RISKPATCH_OFFLINE", "1")
    settings = get_settings()
    conn = connect(settings.db_path)
    migrate(conn)
    tokens = {s: auth.create_token(conn, f"t-{s}", [s]) for s in ("read", "ingest", "operate", "admin")}
    with TestClient(create_app(settings)) as client:
        yield client, tokens, conn, settings


def payload(**over):
    body = {
        "schema_version": "1.0", "asset_id": "web-01",
        "collected_at": datetime.now(timezone.utc).isoformat(), "collector_version": "0.1.0",
        "facts": {
            "os": {"name": "Ubuntu", "version": "20.04"},
            "runtimes": [{"name": "php", "version": "7.3.33", "sapi": "fpm"}],
            "config_facts": [{"source": "/etc/app.ini", "key": "db_password", "value": "hunter2"}],
            "exposure": {"exposure": "internet", "environment": "prod", "auth_boundary": "unauthenticated"},
        },
        "errors": [],
    }
    body.update(over)
    return body


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_health_open_and_openapi(env):
    client, *_ = env
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/ready").status_code in (200, 503)
    spec = client.get("/api/v1/openapi.json").json()
    assert "/api/v1/ingest/snapshots" in spec["paths"]


def test_auth_and_scopes(env):
    client, t, *_ = env
    assert client.get("/api/v1/assets").status_code == 401
    assert client.get("/api/v1/assets", headers=h("nope")).status_code == 401
    assert client.get("/api/v1/assets", headers=h(t["ingest"])).status_code == 403
    assert client.post("/api/v1/ingest/snapshots", json=payload(), headers=h(t["read"])).status_code == 403
    assert client.post("/api/v1/jobs/analysis/run", headers=h(t["read"])).status_code == 403


def test_ingest_idempotent_redacted_and_analysis(env):
    client, t, conn, settings = env
    body = payload()
    r = client.post("/api/v1/ingest/snapshots", json=body, headers=h(t["ingest"]))
    assert r.status_code in (200, 201, 202), r.text
    first = r.json()
    assert first["status"] == "accepted" and first["duplicate"] is False
    again = client.post("/api/v1/ingest/snapshots", json=body, headers=h(t["ingest"])).json()
    assert again["snapshot_id"] == first["snapshot_id"] and again["duplicate"] is True
    # gzip body accepted
    gz = client.post("/api/v1/ingest/snapshots", content=gzip.compress(json.dumps(body).encode()),
                     headers={**h(t["ingest"]), "Content-Encoding": "gzip", "Content-Type": "application/json"})
    assert gz.json()["snapshot_id"] == first["snapshot_id"]
    stored = conn.execute("SELECT payload_json FROM snapshot_facts WHERE snapshot_id=?", (first["snapshot_id"],)).fetchone()[0]
    assert "hunter2" not in stored and "[REDACTED]" in stored
    # invalid / stale payloads rejected
    assert client.post("/api/v1/ingest/snapshots", json=payload(schema_version="2.0"), headers=h(t["ingest"])).status_code == 422
    assert client.post("/api/v1/ingest/snapshots", json=payload(collected_at="2020-01-01T00:00:00Z"), headers=h(t["ingest"])).status_code == 422
    assert client.post("/api/v1/ingest/snapshots", json=payload(asset_id="../x"), headers=h(t["ingest"])).status_code == 422

    assets = client.get("/api/v1/assets", headers=h(t["read"])).json()
    assert assets["total"] == 1
    assert client.get("/api/v1/snapshots", headers=h(t["read"])).json()["total"] == 1
    assert client.get("/api/v1/search?q=web-01", headers=h(t["read"])).status_code == 200

    # manual analysis through API, executed by worker functions
    job = client.post("/api/v1/jobs/analysis/run", headers=h(t["operate"]))
    assert job.status_code == 202
    while (j := claim(conn, settings)) is not None:
        run_job(conn, settings, j)
    stats = dashboard_stats(conn, 1, settings)
    assert stats["assets"] == 1 and stats["assets_reporting_24h"] == 1
    assert stats["findings_open"] == conn.execute(
        "SELECT COUNT(*) FROM findings WHERE workspace_id=1 AND status='open'"
    ).fetchone()[0]
    assert stats["alerts_closed_period"] == 0
    jobs = client.get("/api/v1/jobs", headers=h(t["read"])).json()
    assert jobs["items"][0]["status"] in ("success", "partial")
    assert client.get("/api/v1/findings", headers=h(t["read"])).status_code == 200
    assert client.get("/api/v1/reports/latest", headers=h(t["read"])).status_code in (200, 404)
    assert client.get("/api/v1/aggregations/highest-risk-assets", headers=h(t["read"])).status_code == 200
    assert client.get("/api/v1/audit", headers=h(t["admin"])).status_code == 200
    assert client.get("/api/v1/audit", headers=h(t["read"])).status_code == 403


def test_scheduler_dedupes_by_bucket(env):
    _, _, conn, settings = env
    a = tick(conn, settings, now=1_000_000.0)
    b = tick(conn, settings, now=1_000_100.0)
    assert len(a) == 2 and b == []


def test_body_limit(env):
    client, t, *_ = env
    r = client.post("/api/v1/ingest/snapshots", content=b"x" * (settings_limit(env) + 10),
                    headers={**h(t["ingest"]), "Content-Type": "application/json"})
    assert r.status_code == 413


def settings_limit(env):
    return env[3].max_body_bytes


def test_ui_requires_login_and_serves(env):
    client, t, *_ = env
    # anonymous visitors see the Overview only; everything else sends them to the login page
    guest = client.get("/ui", follow_redirects=False)
    assert guest.status_code == 200 and "Sign in" in guest.text and 'href="/ui/assets"' not in guest.text.split('<ul class="nav">')[1].split("</ul>")[0]
    for path in ("/ui/assets", "/ui/findings", "/ui/alerts", "/ui/coverage", "/ui/reports", "/ui/cves", "/ui/status", "/ui/settings", "/ui/search?q=a",
                 "/ui/findings/export.csv", "/ui/alerts/export.csv", "/ui/assets/web-01"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/ui/login", path
    assert client.post("/ui/actions/analyze", data={"csrf": "x"}, follow_redirects=False).status_code == 303
    assert client.get("/ui/login").status_code == 200
    assert client.get("/ui/static/app.css").status_code == 200


def test_alert_assessment_and_closure_require_operate_scope_and_evidence(env):
    client, tokens, conn, *_ = env
    cur = conn.execute(
        "INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at) VALUES (1, ?, ?, ?, ?)",
        ("web-01", "kev", "Test alert", datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    alert_id = cur.lastrowid

    session_for(client, conn, "viewer")
    read_page = client.get("/ui/alerts")
    assert "read-only" in read_page.text
    assert f'action="/ui/actions/ack/{alert_id}"' not in read_page.text
    assert f'action="/ui/actions/close/{alert_id}"' not in read_page.text
    denied = client.post(
        f"/ui/actions/ack/{alert_id}",
        data={"csrf": auth.csrf_for(client.cookies.get("rp_session"))},
        follow_redirects=False,
    )
    assert denied.status_code == 403

    client.cookies.clear()
    session_for(client, conn, "operator")
    operate_page = client.get("/ui/alerts")
    form = re.search(
        rf'<form[^>]+action="/ui/actions/ack/{alert_id}"[^>]*>(.*?)</form>',
        operate_page.text,
    )
    assert form, "operate session should see the Acknowledge form"
    csrf = re.search(r'name="csrf" value="([^"]+)"', form.group(1))
    assert csrf and csrf.group(1) == auth.csrf_for(client.cookies.get("rp_session"))

    cannot_close_open = client.post(
        f"/ui/actions/close/{alert_id}",
        data={"csrf": csrf.group(1), "resolution_note": "Patched package"},
        follow_redirects=False,
    )
    assert cannot_close_open.status_code == 409

    assessing = client.post(
        f"/ui/actions/ack/{alert_id}",
        data={"csrf": csrf.group(1)},
        follow_redirects=False,
    )
    assert assessing.status_code == 303
    row = conn.execute(
        "SELECT status, acknowledged_at, acknowledged_by, closed_at FROM alerts WHERE id=?", (alert_id,)
    ).fetchone()
    assert row["status"] == "acknowledged"
    assert row["acknowledged_at"] and row["acknowledged_by"].startswith("user:operator")
    assert row["closed_at"] is None

    assessing_page = client.get("/ui/alerts?view=assessment")
    assert "In assessment" in assessing_page.text
    assert f'/ui/actions/close/{alert_id}' in assessing_page.text
    missing_evidence = client.post(
        f"/ui/actions/close/{alert_id}",
        data={"csrf": csrf.group(1), "resolution_note": "  "},
        follow_redirects=False,
    )
    assert missing_evidence.status_code == 400

    closed = client.post(
        f"/ui/actions/close/{alert_id}",
        data={"csrf": csrf.group(1), "resolution_note": "Patched to 2.4.1 and verified"},
        follow_redirects=False,
    )
    assert closed.status_code == 303
    row = conn.execute(
        "SELECT status, closed_at, closed_by, resolution_note FROM alerts WHERE id=?", (alert_id,)
    ).fetchone()
    assert row["status"] == "closed"
    assert row["closed_at"] and row["closed_by"].startswith("user:operator")
    assert row["resolution_note"] == "Patched to 2.4.1 and verified"
    closed_page = client.get("/ui/alerts?view=closed")
    assert "Patched to 2.4.1 and verified" in closed_page.text

    api_alert = conn.execute(
        "INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at) VALUES (1, ?, ?, ?, ?)",
        ("api-web", "kev", "API lifecycle test", datetime.now(timezone.utc).isoformat()),
    )
    api_alert_id = api_alert.lastrowid
    conn.commit()
    assert client.post(f"/api/v1/alerts/{api_alert_id}/ack", headers=h(tokens["read"])).status_code == 403
    api_ack = client.post(f"/api/v1/alerts/{api_alert_id}/ack", headers=h(tokens["operate"]))
    assert api_ack.status_code == 200 and api_ack.json()["status"] == "acknowledged"
    api_close = client.post(
        f"/api/v1/alerts/{api_alert_id}/close",
        headers=h(tokens["operate"]),
        json={"resolution_note": "Package patched and validated"},
    )
    assert api_close.status_code == 200 and api_close.json()["status"] == "closed"


def test_alerts_mirror_findings_and_survive_clean_slate(env):
    from riskpatch.analysis import sync_alerts
    from riskpatch.db import reset

    client, _, conn, settings = env
    now = datetime.now(timezone.utc).isoformat()
    asset_pk = conn.execute(
        "INSERT INTO assets (workspace_id, asset_id, first_seen, last_seen, updated_at) VALUES (1, 'mirror-test', ?, ?, ?)",
        (now, now, now),
    ).lastrowid
    rows = [
        ("CVE-2026-2001", "open", 1),
        ("CVE-2026-2002", "open", 0),
        ("CVE-2026-2003", "resolved", 0),
    ]
    for cve, status, kev in rows:
        conn.execute(
            "INSERT INTO findings (workspace_id, asset_pk, asset_id, component_key, component_name, component_version, ecosystem, cve_id, level, level_rank, action, confidence, exposure, reachability, one_line, verdict_json, ruleset_version, first_seen, last_seen, level_changed_at, updated_at, status, kev) VALUES (1, ?, 'mirror-test', 'php@7.3', 'php', '7.3', 'php', ?, 'high', 1, 'review', 'high', 'unknown', 'unknown', 'x', '{}', 'test', ?, ?, ?, ?, ?, ?)",
            (asset_pk, cve, now, now, now, now, status, kev),
        )
    conn.commit()
    asset = conn.execute("SELECT * FROM assets WHERE id=?", (asset_pk,)).fetchone()
    sync_alerts(conn, asset, now, {"alerts": 0})
    conn.commit()

    stats = dashboard_stats(conn, 1, settings)
    assert stats["findings_open"] == 2
    assert stats["open_alerts"] + stats["alerts_in_assessment"] == stats["findings_open"]
    assert stats["alerts_closed_period"] == 1 and stats["alerts"] == 3

    sync_alerts(conn, asset, now, {"alerts": 0})
    conn.commit()
    assert dashboard_stats(conn, 1, settings)["alerts"] == 3

    reset(conn)
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_alert_workflow_migration_preserves_legacy_closed_records(tmp_path):
    conn = connect(tmp_path / "legacy-alerts.sqlite3")
    conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (8, '2026-01-01T00:00:00Z')")
    conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, asset_id TEXT, kind TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL, acknowledged_at TEXT, acknowledged_by TEXT)")
    conn.execute("INSERT INTO alerts VALUES (1, 1, 'legacy', 'kev', 'Old alert', '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', 'token:old')")
    conn.execute("INSERT INTO alerts VALUES (2, 1, 'new', 'stale', 'Open alert', '2026-01-03T00:00:00Z', NULL, NULL)")
    conn.execute("CREATE TABLE assets (id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, asset_id TEXT NOT NULL)")
    conn.execute("CREATE TABLE api_tokens (id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL DEFAULT 1)")
    conn.execute("CREATE VIRTUAL TABLE search_index USING fts5(kind UNINDEXED, ref UNINDEXED, title, body)")
    conn.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, asset_pk INTEGER, asset_id TEXT, status TEXT, level TEXT, level_rank INTEGER, kev INTEGER, cvss_score REAL, first_seen TEXT)")

    assert migrate(conn) == 20
    old = conn.execute("SELECT status, closed_at, closed_by, resolution_note FROM alerts WHERE id=1").fetchone()
    new = conn.execute("SELECT status, closed_at, resolution_note FROM alerts WHERE id=2").fetchone()
    assert old["status"] == "closed"
    assert old["closed_at"] == "2026-01-02T00:00:00Z" and old["closed_by"] == "token:old"
    assert old["resolution_note"] == ""
    assert new["status"] == "open" and new["closed_at"] is None
    conn.close()


def test_alert_csv_exports_all_workspace_alerts(env):
    client, tokens, conn, *_ = env
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'other', ?)", (now,))
    conn.execute("INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at) VALUES (1, 'open-a', 'kev', '=SUM(1,1)', ?)", (now,))
    conn.execute("INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at, status, acknowledged_at, acknowledged_by) VALUES (1, 'assess-a', 'stale', 'Assessing', ?, 'acknowledged', ?, 'token:operator')", (now, now,))
    conn.execute("INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at, status, closed_at, closed_by, resolution_note) VALUES (1, 'closed-a', 'kev', 'Patched', ?, 'closed', ?, 'token:operator', 'Patched and verified')", (now, now))
    conn.execute("INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at) VALUES (2, 'other-a', 'kev', 'Other workspace', ?)", (now,))
    conn.commit()
    session_for(client, conn, "viewer")
    alert_page = client.get("/ui/alerts")
    assert 'href="/ui/alerts/export.csv"' in alert_page.text

    response = client.get("/ui/alerts/export.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment; filename=\"riskpatch-alerts.csv\"" in response.headers["content-disposition"]
    records = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert {row["asset_id"] for row in records} == {"open-a", "assess-a", "closed-a"}
    by_asset = {row["asset_id"]: row for row in records}
    assert by_asset["assess-a"]["status"] == "acknowledged"
    assert by_asset["closed-a"]["resolution_note"] == "Patched and verified"
    assert by_asset["open-a"]["message"] == "'=SUM(1,1)"


def test_overview_shows_supported_kpis_and_finding_filters(env):
    client, *_ = env
    overview = client.get("/ui")
    assert overview.status_code == 200
    assert "Needs attention" not in overview.text
    assert "Initial baseline for" not in overview.text
    assert "asset(s) have not reported" not in overview.text
    assert 'href="/ui/assets"' in overview.text
    assert 'href="/ui/findings?status=open"' in overview.text
    assert 'href="/ui/findings?status=open&amp;kev=true"' in overview.text
    assert 'href="/ui/cves"' in overview.text
    assert 'href="/ui/findings?status=open" class="kc-link"><article class="kc" style="--c:var(--red)"><div class="lab">CVE findings</div>' in overview.text
    assert 'Highest level: <b>-</b>' in overview.text
    assert '<div class="lab">Open findings</div>' not in overview.text
    assert "CVE Database" in overview.text
    assert "CVE catalog" not in overview.text
    assert "Finding movement · last 30 days" not in overview.text
    assert "Resolved by analysis" not in overview.text
    assert "In Progress" not in overview.text and "Not tracked" not in overview.text

    assert client.get("/ui/findings", params={"status": "open", "kev": "true"}).status_code == 200
    assert client.get(
        "/ui/findings",
        params={"status": "resolved", "updated_since": "2026-10-01T00:00:00Z"},
    ).status_code == 200


def test_overview_highest_cve_finding_level_tracks_open_findings(env):
    client, _, conn, settings = env
    now = datetime.now(timezone.utc).isoformat()
    asset_pk = conn.execute(
        "INSERT INTO assets (workspace_id, asset_id, first_seen, last_seen, updated_at) VALUES (1, 'severity-test', ?, ?, ?)",
        (now, now, now),
    ).lastrowid
    common = (1, asset_pk, "severity-test", "test:component", "component", "1.0", "python", "CVE-2026-1000", "review", "high", "unknown", "unknown", "Test finding", "{}", "test-rules", now, now, now, now)
    conn.execute(
        "INSERT INTO findings (workspace_id, asset_pk, asset_id, component_key, component_name, component_version, ecosystem, cve_id, level, level_rank, action, confidence, exposure, reachability, one_line, verdict_json, ruleset_version, first_seen, last_seen, level_changed_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'medium', 2, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        common,
    )
    critical = list(common)
    critical[3] = "test:critical-component"
    critical[4] = "critical-component"
    critical[7] = "CVE-2026-1001"
    conn.execute(
        "INSERT INTO findings (workspace_id, asset_pk, asset_id, component_key, component_name, component_version, ecosystem, cve_id, level, level_rank, action, confidence, exposure, reachability, one_line, verdict_json, ruleset_version, first_seen, last_seen, level_changed_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'critical', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        critical,
    )
    conn.commit()

    assert dashboard_stats(conn, 1, settings)["highest_level"] == "critical"
    page = client.get("/ui").text
    assert 'Highest level: <b>Critical</b>' in page

    conn.execute("UPDATE findings SET status='resolved' WHERE cve_id='CVE-2026-1001'")
    conn.commit()
    assert dashboard_stats(conn, 1, settings)["highest_level"] == "medium"
    assert 'Highest level: <b>Medium</b>' in client.get("/ui").text


def test_overview_alert_movement_uses_acknowledged_at(env):
    client, tokens, conn, settings = env
    now = datetime.now(timezone.utc)
    recent = now - timedelta(days=5)
    old = now - timedelta(days=45)
    conn.executemany(
        "INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at, status, acknowledged_at, acknowledged_by, closed_at, closed_by, resolution_note) VALUES (1, ?, 'kev', ?, ?, 'closed', ?, 'test', ?, 'test', 'patched and verified')",
        [
            ("recently-closed", "Recently closed alert", (now - timedelta(days=10)).isoformat(), (now - timedelta(days=6)).isoformat(), recent.isoformat()),
            ("old-closed", "Old closed alert", (now - timedelta(days=50)).isoformat(), (now - timedelta(days=46)).isoformat(), old.isoformat()),
        ],
    )
    conn.execute(
        "INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at) VALUES (1, ?, 'stale', ?, ?)",
        ("still-open", "Still open alert", now.isoformat()),
    )
    conn.execute(
        "INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at) VALUES (1, ?, 'stale', ?, ?)",
        ("old-open", "Old still-open alert", (now - timedelta(days=45)).isoformat()),
    )
    conn.execute(
        "INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at, status, acknowledged_at, acknowledged_by) VALUES (1, ?, 'kev', ?, ?, 'acknowledged', ?, 'token:assessor')",
        ("under-assessment", "Being assessed", now.isoformat(), (now - timedelta(hours=2)).isoformat()),
    )
    conn.commit()

    stats = dashboard_stats(conn, 1, settings)
    assert stats["open_alerts"] == 1
    assert stats["alerts_in_assessment"] == 1
    assert stats["alerts_closed_period"] == 1
    assert stats["alerts_remaining_period"] == 2
    assert dashboard_stats(conn, 1, settings, alert_period="7d")["alerts_closed_period"] == 0
    assert dashboard_stats(conn, 1, settings, alert_period="24h")["alerts_closed_period"] == 0
    assert dashboard_stats(conn, 1, settings, alert_period="7d")["alerts_remaining_period"] == 2
    assert dashboard_stats(conn, 1, settings, alert_period="24h")["alerts_remaining_period"] == 2

    session_for(client, conn, "viewer")
    overview = client.get("/ui")
    assert "created in the selected period (30 days)" in overview.text
    assert '<div class="fc-lab">Open alerts</div><div class="fc-val">1</div>' in overview.text
    assert '<div class="fc-lab">In assessment</div><div class="fc-val">1</div>' in overview.text
    assert '<div class="fc-lab">Closed · 30 days</div><div class="fc-val">1</div>' in overview.text
    assert '<div class="fc-lab">Remaining · 30 days</div><div class="fc-val">2</div>' in overview.text
    assert "Closed · all time" not in overview.text
    assert 'href="/ui/alerts?view=open&amp;since=' in overview.text
    assert 'href="/ui/alerts?view=assessment&amp;since=' in overview.text
    since_link = re.search(r'href="(/ui/alerts\?view=closed&amp;since=[^"]+)"', overview.text)
    assert since_link
    alert_filter = parse_qs(urlsplit(unescape(since_link.group(1))).query)

    closed_recent = client.get(
        "/ui/alerts",
        params={"view": "closed", "since": alert_filter["since"][0], "until": alert_filter["until"][0]},
    )
    assert closed_recent.status_code == 200
    assert "Recently closed alert" in closed_recent.text
    assert "Old closed alert" not in closed_recent.text

    remaining_link = re.search(r'href="(/ui/alerts\?view=remaining&amp;since=[^"]+)"', overview.text)
    assert remaining_link
    remaining_filter = parse_qs(urlsplit(unescape(remaining_link.group(1))).query)
    remaining = client.get(
        "/ui/alerts",
        params={"view": "remaining", "since": remaining_filter["since"][0], "until": remaining_filter["until"][0]},
    )
    assert "Still open alert" in remaining.text and "Being assessed" in remaining.text
    assert "Old still-open alert" not in remaining.text
    assert "Recently closed alert" not in remaining.text

    week = client.get("/ui", params={"period": "7d"})
    assert "created in the selected period (7 days)" in week.text
    assert 'value="7d" selected>Last 7 days' in week.text
    assert '<div class="fc-lab">Closed · 7 days</div><div class="fc-val">0</div>' in week.text
    assert '<div class="fc-lab">Remaining · 7 days</div><div class="fc-val">2</div>' in week.text

    day = client.get("/ui", params={"period": "24h"})
    assert "created in the selected period (24 hours)" in day.text
    assert '<div class="fc-lab">Closed · 24 hours</div><div class="fc-val">0</div>' in day.text
    assert '<div class="fc-lab">Remaining · 24 hours</div><div class="fc-val">2</div>' in day.text


def test_backup_restore(env, tmp_path):
    from riskpatch import db
    client, t, conn, settings = env
    client.post("/api/v1/ingest/snapshots", json=payload(), headers=h(t["ingest"]))
    dest = tmp_path / "bk.sqlite3"
    db.backup(conn, dest)
    target = tmp_path / "restored.sqlite3"
    db.restore(dest, target)
    c2 = connect(target)
    assert c2.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == 1


def test_alert_remaining_follows_selected_window_on_overview_and_alerts(env):
    client, tokens, conn, settings = env
    now = datetime.now(timezone.utc)

    def stamp(days=0, hours=0):
        return (now - timedelta(days=days, hours=hours)).isoformat(timespec="seconds").replace("+00:00", "Z")

    conn.executemany(
        "INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at, status, acknowledged_at, acknowledged_by, closed_at, closed_by, resolution_note) VALUES (1, ?, 'kev', ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ("open-2h", "Open created 2h ago", stamp(hours=2), "open", None, None, None, None, ""),
            ("ack-3d", "Assessing created 3d ago", stamp(days=3), "acknowledged", stamp(days=2), "token:op", None, None, ""),
            ("closed-10d", "Closed created 10d ago", stamp(days=10), "closed", stamp(days=3), "token:op", stamp(days=2), "token:op", "patched"),
            ("open-20d", "Open created 20d ago", stamp(days=20), "open", None, None, None, None, ""),
            ("open-60d", "Open created 60d ago", stamp(days=60), "open", None, None, None, None, ""),
        ],
    )
    conn.commit()
    session_for(client, conn, "viewer")  # the alerts list needs a signed-in account

    expected = {
        "24h": ("24 hours", 1, 0, {"Open created 2h ago"}),
        "7d": ("7 days", 2, 0, {"Open created 2h ago", "Assessing created 3d ago"}),
        "30d": ("30 days", 3, 1, {"Open created 2h ago", "Assessing created 3d ago", "Open created 20d ago"}),
    }
    sections = {}
    for period, (label, remaining, closed, visible) in expected.items():
        stats = dashboard_stats(conn, 1, settings, alert_period=period)
        assert stats["alerts_remaining_period"] == remaining
        assert stats["alerts_closed_period"] == closed

        page = client.get("/ui", params={"period": period}).text
        assert f'<div class="fc-lab">Remaining · {label}</div><div class="fc-val">{remaining}</div>' in page
        assert f'<div class="fc-lab">Closed · {label}</div><div class="fc-val">{closed}</div>' in page
        sections[period] = {
            name: re.search(rf"<h2>{name}</h2>.*?</section>", page, re.S).group(0)
            for name in ("Severity mix", "High-risk assets")
        }

        link = re.search(r'href="(/ui/alerts\?view=remaining&amp;since=[^"]+)"', page)
        assert link
        window = parse_qs(urlsplit(unescape(link.group(1))).query)
        listing = client.get(
            "/ui/alerts",
            params={"view": "remaining", "since": window["since"][0], "until": window["until"][0]},
        )
        assert f'<div class="fact"><span>Remaining created · selected window</span><b>{remaining}</b></div>' in listing.text
        for message in ("Open created 2h ago", "Assessing created 3d ago", "Closed created 10d ago", "Open created 20d ago", "Open created 60d ago"):
            assert (message in listing.text) == (message in visible), (period, message)
        open_list = client.get(
            "/ui/alerts",
            params={"view": "open", "since": window["since"][0], "until": window["until"][0]},
        )
        assert ("Open created 20d ago" in open_list.text) == ("Open created 20d ago" in visible), period
        assert "Open created 60d ago" not in open_list.text
        assert "Assessing created 3d ago" not in open_list.text

    assert sections["24h"] == sections["7d"] == sections["30d"]

    default = client.get("/ui/alerts", params={"view": "remaining"})
    assert '<div class="fact"><span>Remaining created · 30 days</span><b>3</b></div>' in default.text


def test_overview_asset_and_severity_panels_do_not_depend_on_alert_period(env):
    client, *_ = env
    page = client.get("/ui").text
    assert "does not change with the time range" in page
    assert "Top 6 by highest open severity" in page
    assert client.get("/ui", params={"period": "24h"}).text.count("<h2>Severity mix</h2>") == 1


def test_overview_long_period_options_cover_months_years_and_all_time(env):
    client, _, conn, settings = env
    now = datetime.now(timezone.utc)

    def stamp(days):
        return (now - timedelta(days=days)).isoformat(timespec="seconds").replace("+00:00", "Z")

    conn.executemany(
        "INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at, status, acknowledged_at, acknowledged_by, closed_at, closed_by, resolution_note) VALUES (1, ?, 'kev', ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            ("open-100d", "Open created 100d ago", stamp(100), "open", None, None, None, None, ""),
            ("open-200d", "Open created 200d ago", stamp(200), "open", None, None, None, None, ""),
            ("closed-400d", "Closed created 400d ago", stamp(400), "closed", stamp(399), "token:op", stamp(399), "token:op", "patched"),
        ],
    )
    conn.commit()

    expected = {
        "3m": ("3 months", 0, 0),
        "6m": ("6 months", 1, 0),
        "1y": ("1 year", 2, 0),
        "all": ("all time", 2, 1),
    }
    for period, (label, remaining, closed) in expected.items():
        stats = dashboard_stats(conn, 1, settings, alert_period=period)
        assert stats["alerts_remaining_period"] == remaining, period
        assert stats["alerts_closed_period"] == closed, period
        page = client.get("/ui", params={"period": period}).text
        assert f'value="{period}" selected>' in page
        assert f'<div class="fc-lab">Remaining · {label}</div><div class="fc-val">{remaining}</div>' in page
        assert f'<div class="fc-lab">Closed · {label}</div><div class="fc-val">{closed}</div>' in page
    assert ">Last 3 months<" in client.get("/ui").text
    assert ">Last 1 year<" in client.get("/ui").text
    assert ">All time<" in client.get("/ui").text


def _add_findings(conn, name, counts, cve_id=None, component=None):
    """counts: {level: how many open findings}; returns nothing."""
    from riskpatch.report import level_rank

    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute("SELECT id FROM assets WHERE workspace_id=1 AND asset_id=?", (name,)).fetchone()
    asset_pk = existing["id"] if existing else conn.execute(
        "INSERT INTO assets (workspace_id, asset_id, first_seen, last_seen, updated_at) VALUES (1, ?, ?, ?, ?)", (name, now, now, now)).lastrowid
    n = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    for level, how_many in counts.items():
        for _ in range(how_many):
            n += 1
            conn.execute(
                "INSERT INTO findings (workspace_id, asset_pk, asset_id, component_key, component_name, component_version, ecosystem, cve_id, level, level_rank, action, "
                "confidence, exposure, reachability, one_line, verdict_json, ruleset_version, first_seen, last_seen, level_changed_at, updated_at) "
                "VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (asset_pk, name, component or f"c{n}", component or f"c{n}", "1.0", "python", cve_id or f"CVE-2026-{n}", level, level_rank(level), "review", "high", "unknown", "unknown", "t", "{}", "r", now, now, now, now))


def test_overview_high_risk_assets_shows_top_six_by_level_then_critical_count(env):
    client, _, conn, _ = env
    _add_findings(conn, "crit-3", {"critical": 3})
    _add_findings(conn, "crit-5", {"critical": 5})
    _add_findings(conn, "crit-5-more", {"critical": 5, "low": 10})   # same critical count, more open findings
    _add_findings(conn, "high-20", {"high": 20})                      # lower highest level, many findings
    _add_findings(conn, "med-9", {"medium": 9})
    _add_findings(conn, "med-1", {"medium": 1})
    _add_findings(conn, "low-30", {"low": 30})
    _add_findings(conn, "low-2", {"low": 2})
    conn.commit()
    session_for(client, conn, "viewer")
    page = client.get("/ui").text
    panel = page[page.index("High-risk assets"):]
    shown = re.findall(r'href="/ui/assets/([^"]+)"', panel)
    assert shown == ["crit-5-more", "crit-5", "crit-3", "high-20", "med-9", "med-1"]


def test_asset_detail_open_findings_count_is_the_real_total_not_the_page_size(env):
    client, _, conn, _ = env
    _add_findings(conn, "big-asset", {"critical": 3, "low": 57})  # 60 > the 50 rows listed on the page
    conn.commit()
    session_for(client, conn, "viewer")
    page = client.get("/ui/assets/big-asset").text
    assert '<div class="fv">60</div>' in page or ">60<" in page
    assert "Showing 50 of 60 open findings" in page
    assert page.count('href="/ui/findings/') == 50
    assert "60 open findings" in page
    assert client.get("/ui/assets").text.count(">60<") >= 1  # same number the asset list shows


def test_coverage_page_explains_stale_in_plain_words(env):
    from riskpatch.ui import layer_why

    client, _, conn, _ = env
    session_for(client, conn, "viewer")
    page = client.get("/ui/coverage").text
    assert "How to read this page" in page and "Not an error" in page
    assert "layers within TTL" not in page  # no jargon in the health card

    inv = {"kind": "inventory", "state": "stale", "stale_entries": 3, "entries": 205, "ttl_seconds": 86400}
    assert "3 of 205 servers" in layer_why(inv) and "Run the collector" in layer_why(inv)
    cor = {"kind": "correlation", "state": "stale", "stale_entries": 202, "entries": 205, "ttl_seconds": None}
    assert "202 of 205 servers" in layer_why(cor) and "Refresh all" in layer_why(cor)
    assert layer_why({"kind": "feed", "state": "stale", "stale_entries": 1, "entries": 3, "ttl_seconds": 21600}).startswith("<b>Older than 6h")
    assert "failed" in layer_why({"kind": "feed", "state": "failed", "stale_entries": 0, "entries": 3, "ttl_seconds": 21600}).lower()
    assert layer_why({"kind": "feed", "state": "success", "stale_entries": 0, "entries": 3, "ttl_seconds": 21600}) == ""
    assert "Refresh all" not in layer_why(cor, can_refresh=False) and "operator" in layer_why(cor, can_refresh=False)
    assert "Refresh all" not in page  # read-only viewers are not pointed at a button they do not have


def test_coverage_risk_box_says_last_known_not_invalid_or_fixed(env):
    client, _, conn, _ = env
    session_for(client, conn, "viewer")
    page = client.get("/ui/coverage").text
    assert "Stale means last known, not wrong" in page
    assert "last known state" in page and "not a verified view" in page
    assert "invalid" not in page.lower().split("risk of leaving it as is")[1].split("</section>")[0]


def test_asset_ownership_is_audited_validated_and_survives_collector_ingest(env):
    from riskpatch.asset_admin import set_ownership

    client, tokens, conn, _ = env
    _add_findings(conn, "web-01", {"high": 1})
    conn.commit()
    changed = set_ownership(conn, 1, "web-01", "token:t", owner="  Platform   team ", business_tier="tier1", service="Portal", maintenance_window="Sun 02:00")
    assert changed["owner"] == ("", "Platform team") and changed["business_tier"] == ("", "tier1")
    assert set_ownership(conn, 1, "web-01", "token:t", owner="Platform team") == {}  # no change, no audit noise
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='asset.ownership'").fetchone()[0] == 1
    for bad in ({"business_tier": "tier9"}, {"owner": "x" * 121}, {"nope": "x"}):
        with pytest.raises(ValueError):
            set_ownership(conn, 1, "web-01", "token:t", **bad)
    with pytest.raises(LookupError):
        set_ownership(conn, 1, "ghost", "token:t", owner="x")

    # API: operate scope required, 404/422 handled, list filters work
    body = {"owner": "Ops", "business_tier": "tier2"}
    assert client.patch("/api/v1/assets/web-01/ownership", json=body, headers=h(tokens["read"])).status_code == 403
    ok = client.patch("/api/v1/assets/web-01/ownership", json=body, headers=h(tokens["operate"]))
    assert ok.status_code == 200 and ok.json()["owner"] == "Ops" and ok.json()["business_tier"] == "tier2" and ok.json()["service"] == "Portal"
    assert client.patch("/api/v1/assets/ghost/ownership", json=body, headers=h(tokens["operate"])).status_code == 404
    assert client.patch("/api/v1/assets/web-01/ownership", json={"business_tier": "tier9"}, headers=h(tokens["operate"])).status_code == 422
    _add_findings(conn, "no-owner-box", {"low": 1})
    conn.commit()
    names = lambda q: [a["asset_id"] for a in client.get("/api/v1/assets" + q, headers=h(tokens["read"])).json()["items"]]  # noqa: E731
    assert names("?owner=none") == ["no-owner-box"] and names("?owner=ops") == ["web-01"] and names("?business_tier=tier2") == ["web-01"]

    # a collector snapshot for the same asset must not wipe what people entered
    client.post("/api/v1/ingest/snapshots", json=payload(), headers=h(tokens["ingest"]))
    assert client.get("/api/v1/assets/web-01", headers=h(tokens["read"])).json()["owner"] == "Ops"


def test_asset_ownership_ui_edit_filter_and_unowned_note(env):
    client, tokens, conn, _ = env
    register(conn, "SOC", "Platform", "Platform team", "Ops", "Web team", "A", "B", "x")
    _add_findings(conn, "web-01", {"high": 1})
    _add_findings(conn, "db-01", {"low": 1})
    conn.commit()
    session_for(client, conn, "viewer")
    page = client.get("/ui/assets").text
    assert "2 servers without an owner" in page and "Owner / tier" in page and "Unassigned" in page
    detail = client.get("/ui/assets/web-01").text
    assert "<h2>Ownership</h2>" in detail and 'action="/ui/actions/assets/ownership"' not in detail  # read-only users cannot edit

    client.cookies.clear()
    session_for(client, conn, "operator")
    detail = client.get("/ui/assets/web-01").text
    csrf = re.search(r'action="/ui/actions/assets/ownership".*?name="csrf" value="([^"]+)"', detail, re.S).group(1)
    data = {"asset_id": "web-01", "owner": "Platform team", "business_tier": "tier1", "service": "Portal", "maintenance_window": "Sun 02:00-04:00"}
    assert client.post("/ui/actions/assets/ownership", data={**data, "csrf": "bad"}, follow_redirects=False).status_code == 403
    assert client.post("/ui/actions/assets/ownership", data={**data, "asset_id": "ghost", "csrf": csrf}, follow_redirects=False).status_code == 404
    bad = client.post("/ui/actions/assets/ownership", data={**data, "business_tier": "tier9", "csrf": csrf}, follow_redirects=False)
    assert bad.status_code == 303 and "error=" in bad.headers["location"]
    ok = client.post("/ui/actions/assets/ownership", data={**data, "csrf": csrf}, follow_redirects=False)
    assert ok.status_code == 303 and "notice=Ownership" in ok.headers["location"]
    page = client.get("/ui/assets").text
    assert "1 server without an owner" in page and "Platform team" in page and "Tier 1" in page
    assert [x for x in re.findall(r'href="/ui/assets/([^"]+)"', client.get("/ui/assets?owner=none").text) if x in ("web-01", "db-01")] == ["db-01"]
    assert "Sun 02:00-04:00" in client.get("/ui/assets/web-01").text


def test_bulk_ownership_service_leaves_empty_fields_alone_and_audits_once(env):
    from riskpatch.asset_admin import set_ownership, set_ownership_bulk

    _, _, conn, _ = env
    for n in ("a-1", "a-2", "a-3"):
        _add_findings(conn, n, {"low": 1})
    conn.commit()
    set_ownership(conn, 1, "a-1", "t", owner="Keep me", service="Old service")
    res = set_ownership_bulk(conn, 1, ["a-1", "a-2", "ghost"], "token:t", owner="", business_tier="tier2", service="Portal", maintenance_window="")
    assert res["matched"] == 2 and res["changed"] == 2 and res["fields"] == {"business_tier": "tier2", "service": "Portal"}
    row = {r["asset_id"]: r for r in conn.execute("SELECT * FROM assets")}
    assert row["a-1"]["owner"] == "Keep me" and row["a-1"]["service"] == "Portal" and row["a-1"]["business_tier"] == "tier2"  # empty owner did not blank it
    assert row["a-3"]["business_tier"] == ""
    events = conn.execute("SELECT target FROM audit_events WHERE action='asset.ownership.bulk'").fetchall()
    assert len(events) == 1 and events[0]["target"] == "2 assets"
    assert set_ownership_bulk(conn, 1, ["a-1"], "t", business_tier="tier2")["changed"] == 0  # idempotent, no new audit
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='asset.ownership.bulk'").fetchone()[0] == 1
    for args in (dict(owner="", service=""), dict(business_tier="tier9")):
        with pytest.raises(ValueError):
            set_ownership_bulk(conn, 1, ["a-1"], "t", **args)
    with pytest.raises(ValueError):
        set_ownership_bulk(conn, 1, [], "t", owner="x")
    with pytest.raises(LookupError):
        set_ownership_bulk(conn, 1, ["ghost"], "t", owner="x")


def test_bulk_ownership_ui_selected_rows_all_matching_filter_and_permissions(env):
    client, tokens, conn, _ = env
    register(conn, "SOC", "Platform", "Platform team", "Ops", "Web team", "A", "B", "x")
    for n in ("web-1", "web-2", "db-1"):
        _add_findings(conn, n, {"low": 1})
    conn.commit()
    session_for(client, conn, "viewer")
    assert 'name="asset_id"' not in client.get("/ui/assets").text  # read-only: no checkboxes, no bulk form

    client.cookies.clear()
    session_for(client, conn, "operator")
    page = client.get("/ui/assets").text
    assert "Set ownership for selected servers" in page and "Delete selected" not in page
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    url = "/ui/actions/assets/ownership-bulk"
    assert client.post(url, data={"csrf": "bad", "asset_id": ["web-1"], "owner": "x"}, follow_redirects=False).status_code == 403
    nothing = client.post(url, data={"csrf": csrf, "asset_id": ["web-1"]}, follow_redirects=False)
    assert "error=" in nothing.headers["location"]                         # nothing filled in
    unselected = client.post(url, data={"csrf": csrf, "owner": "Ops"}, follow_redirects=False)
    assert "error=" in unselected.headers["location"]                      # nothing selected
    ok = client.post(url, data={"csrf": csrf, "asset_id": ["web-1"], "owner": "Web team", "business_tier": "tier1"}, follow_redirects=False)
    assert "notice=Updated%201%20of%201" in ok.headers["location"]

    # "all matching the filter" applies to every server the filtered list shows, beyond the ticked rows
    allweb = client.post(url, data={"csrf": csrf, "apply_filter": "1", "f_q": "web", "owner": "Web team", "service": "Shop"}, follow_redirects=False)
    assert "notice=Updated%202%20of%202" in allweb.headers["location"]
    owners = {r["asset_id"]: (r["owner"], r["service"]) for r in conn.execute("SELECT asset_id, owner, service FROM assets")}
    assert owners["web-1"] == ("Web team", "Shop") and owners["web-2"] == ("Web team", "Shop") and owners["db-1"] == ("", "")

    client.cookies.clear()
    session_for(client, conn, "admin")
    assert "Delete selected" in client.get("/ui/assets").text  # admins keep the delete action in the same form


def test_findings_group_by_cve_package_and_asset(env):
    client, _, conn, _ = env
    _add_findings(conn, "web-1", {"critical": 1}, cve_id="CVE-2026-9001", component="openssl")
    _add_findings(conn, "web-2", {"critical": 1}, cve_id="CVE-2026-9001", component="openssl")
    _add_findings(conn, "web-2", {"low": 1}, cve_id="CVE-2026-9002", component="curl")
    _add_findings(conn, "db-1", {"high": 1}, cve_id="CVE-2026-9003", component="openssl")
    conn.commit()
    session_for(client, conn, "viewer")

    flat = client.get("/ui/findings").text
    assert "By CVE" in flat and "By package" in flat and "By asset" in flat and len(re.findall(r'href="/ui/findings/\d+"', flat)) == 4

    by_cve = client.get("/ui/findings?group=cve").text
    assert "3 CVEs" in by_cve and by_cve.index("CVE-2026-9001") < by_cve.index("CVE-2026-9003") < by_cve.index("CVE-2026-9002")  # critical, high, low
    row = re.search(r"CVE-2026-9001.*?</tr>", by_cve, re.S).group(0)
    assert ">2<" in row  # two servers
    assert 'href="/ui/findings?status=open&amp;cve_id=CVE-2026-9001"' in by_cve

    by_pkg = client.get("/ui/findings?group=package").text
    assert "2 packages" in by_pkg or "3 packages" in by_pkg
    assert "openssl 1.0" in by_pkg and "component=openssl" in by_pkg

    by_asset = client.get("/ui/findings?group=asset").text
    assert "3 servers" in by_asset and by_asset.index("web-1") < by_asset.index("db-1")  # critical before high

    # drill-down filters the flat list; filters carry into grouped views and the switch keeps them
    drill = client.get("/ui/findings?component=openssl").text
    assert len(re.findall(r'href="/ui/findings/\d+"', drill)) == 3 and "curl" not in drill
    filtered = client.get("/ui/findings?group=cve&severity=critical").text
    assert "1 CVEs" in filtered and "CVE-2026-9003" not in filtered
    assert "group=asset" in filtered and "severity=critical" in filtered
    assert len(re.findall(r'href="/ui/findings/\d+"', client.get("/ui/findings?group=bogus").text)) == 4  # unknown group falls back to flat


def test_findings_csv_download_matches_filters_groups_and_is_safe(env):
    client, _, conn, _ = env
    _add_findings(conn, "web-1", {"critical": 1}, cve_id="CVE-2026-9001", component="openssl")
    _add_findings(conn, "web-2", {"low": 1}, cve_id="CVE-2026-9002", component="=HYPERLINK(\"http://x\")")
    _add_findings(conn, "db-1", {"high": 1}, cve_id="CVE-2026-9003", component="openssl")
    conn.execute("UPDATE findings SET verdict_json='{\"min_safe_target\": \"3.0.15\"}' WHERE cve_id='CVE-2026-9001'")
    conn.execute("UPDATE assets SET owner='Web team', business_tier='tier1', service='Shop' WHERE asset_id='web-1'")
    conn.commit()
    anon = client.get("/ui/findings/export.csv", follow_redirects=False)  # anonymous visitors browse as read-only guests but cannot bulk-export
    assert anon.status_code == 303 and anon.headers["location"] == "/ui/login"
    assert client.get("/ui/alerts/export.csv", follow_redirects=False).status_code == 303

    session_for(client, conn, "viewer")
    flat = client.get("/ui/findings/export.csv")
    assert flat.status_code == 200 and flat.headers["content-type"].startswith("text/csv")
    assert 'attachment; filename="riskpatch-findings-' in flat.headers["content-disposition"]
    assert flat.text.startswith("﻿")
    rows = list(csv.reader(io.StringIO(flat.text.lstrip("﻿"))))
    head, body = rows[0], rows[1:]
    assert head[:3] == ["cve_id", "server", "owner"] and "fixed_version" in head and "evidence" in head
    assert [r[0] for r in body] == ["CVE-2026-9001", "CVE-2026-9003", "CVE-2026-9002"]          # critical, high, low
    first = dict(zip(head, body[0]))
    assert first["owner"] == "Web team" and first["business_tier"] == "Tier 1" and first["service"] == "Shop"
    assert first["fixed_version"] == "3.0.15" and first["kev"] == "no" and first["evidence"] == "Unverified"
    assert next(r for r in body if r[0] == "CVE-2026-9002")[head.index("package")].startswith("'=")  # formula neutralised

    only_critical = list(csv.reader(io.StringIO(client.get("/ui/findings/export.csv?severity=critical").text.lstrip("﻿"))))
    assert len(only_critical) == 2 and only_critical[1][0] == "CVE-2026-9001"                      # same filters as the list
    assert len(list(csv.reader(io.StringIO(client.get("/ui/findings/export.csv?component=openssl").text.lstrip("﻿"))))) == 3

    by_cve = list(csv.reader(io.StringIO(client.get("/ui/findings/export.csv?group=cve").text.lstrip("﻿"))))
    assert by_cve[0] == ["cve_id", "highest_level", "cvss", "kev", "servers", "findings"] and len(by_cve) == 4
    by_asset = list(csv.reader(io.StringIO(client.get("/ui/findings/export.csv?group=asset").text.lstrip("﻿"))))
    assert by_asset[0][:3] == ["server", "owner", "business_tier"] and by_asset[1][0] == "web-1" and by_asset[1][1] == "Web team"
    assert "by-asset" in client.get("/ui/findings/export.csv?group=asset").headers["content-disposition"]

    page = client.get("/ui/findings").text
    assert 'href="/ui/findings/export.csv?' in page and "Download CSV · 3 findings" in page
    assert "Download CSV · 3 servers" in client.get("/ui/findings?group=asset").text
    assert "severity=critical" in client.get("/ui/findings?severity=critical").text.split("export.csv?")[1].split('"')[0]  # download keeps the filters

    audit_rows = conn.execute("SELECT target, detail FROM audit_events WHERE action='findings.export' ORDER BY id").fetchall()
    assert len(audit_rows) >= 6 and json.loads(audit_rows[0]["detail"])["rows"] == 3
    assert json.loads(audit_rows[1]["detail"])["filters"] == {"status": "open", "severity": "critical"}
