from datetime import datetime, timedelta, timezone

import re

import pytest
from fastapi.testclient import TestClient

from riskpatch import auth, freshness
from riskpatch.api import create_app
from riskpatch.api.app import dashboard_stats
from riskpatch.config import get_settings
from riskpatch.db import connect, migrate
from tests.test_api import h, payload
from tests.helpers import session_for


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("RISKPATCH_DB", str(tmp_path / "f.sqlite3"))
    monkeypatch.setenv("RISKPATCH_REPORTS", str(tmp_path / "r"))
    monkeypatch.setenv("RISKPATCH_CACHE", str(tmp_path / "c"))
    monkeypatch.setenv("RISKPATCH_OFFLINE", "1")
    settings = get_settings()
    conn = connect(settings.db_path)
    migrate(conn)
    tokens = {s: auth.create_token(conn, f"t-{s}", [s]) for s in ("read", "ingest", "operate", "admin")}
    with TestClient(create_app(settings)) as client:
        yield client, tokens, conn, settings


def fmt(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def states(conn):
    return {(r["layer_key"], r["scope_id"]): r["state"] for r in conn.execute("SELECT layer_key, scope_id, state FROM cache_entries")}


def ingest(client, tokens):
    r = client.post("/api/v1/ingest/snapshots", json=payload(), headers=h(tokens["ingest"]))
    assert r.status_code in (200, 201, 202), r.text


def test_entries_go_stale_at_ttl_and_record_history(env):
    client, tokens, conn, _ = env
    ingest(client, tokens)
    now = datetime.now(timezone.utc)
    conn.execute("INSERT INTO provider_status (provider, last_success_at, records_last_run) VALUES ('nvd', ?, 5)", (fmt(now),))
    conn.commit()

    freshness.sweep(conn, 1, now)
    s = states(conn)
    assert s[("inventory", "web-01")] == "success"
    assert s[("feed", "nvd")] == "success"

    freshness.sweep(conn, 1, now + timedelta(hours=7))
    s = states(conn)
    assert s[("feed", "nvd")] == "stale"
    assert s[("inventory", "web-01")] == "success"

    freshness.sweep(conn, 1, now + timedelta(hours=25))
    assert states(conn)[("inventory", "web-01")] == "stale"
    reasons = conn.execute("SELECT COUNT(*) FROM cache_state_events WHERE to_state='stale'").fetchone()[0]
    assert reasons == 2


def test_correlation_goes_stale_when_inventory_hash_changes(env):
    client, tokens, conn, _ = env
    ingest(client, tokens)
    now = datetime.now(timezone.utc)
    asset_pk = conn.execute("SELECT id FROM assets WHERE asset_id='web-01'").fetchone()[0]
    conn.execute(
        "INSERT INTO reports (workspace_id, asset_pk, asset_id, generated_at, highest, stale, content_json, content_md) VALUES (1, ?, 'web-01', ?, 'low', 0, '{}', '')",
        (asset_pk, fmt(now)),
    )
    conn.commit()

    freshness.sweep(conn, 1, now)
    assert states(conn)[("correlation", "web-01")] == "success"

    conn.execute("UPDATE snapshots SET payload_hash='changed-hash' WHERE asset_pk=?", (asset_pk,))
    conn.commit()
    freshness.sweep(conn, 1, now)
    assert states(conn)[("correlation", "web-01")] == "stale"


def test_failed_refresh_retries_with_backoff_then_dead_letters(env):
    client, tokens, conn, _ = env
    now = datetime.now(timezone.utc)
    conn.execute("INSERT INTO provider_status (provider, last_success_at, records_last_run) VALUES ('nvd', ?, 5)", (fmt(now - timedelta(days=1)),))
    conn.commit()
    freshness.sweep(conn, 1, now)

    freshness.request_refresh(conn, 1, "token:t-operate", layer="feed")
    t = now
    for attempt in range(1, 4):
        rj = conn.execute("SELECT * FROM refresh_jobs ORDER BY id DESC LIMIT 1").fetchone()
        job = conn.execute("SELECT * FROM jobs WHERE id=?", (rj["job_id"],)).fetchone()
        conn.execute("UPDATE jobs SET status='failed' WHERE id=?", (job["id"],))
        conn.commit()
        freshness.complete_refresh(conn, job, "failed", "upstream 503", t)
        rj = conn.execute("SELECT * FROM refresh_jobs ORDER BY id DESC LIMIT 1").fetchone()
        if attempt < 3:
            assert rj["state"] == "retry_wait" and rj["retries"] == attempt
            assert rj["next_attempt_at"] == fmt(t + timedelta(seconds=60 * 2 ** (attempt - 1)))
            assert freshness.requeue_due(conn, t) == 0
            t = freshness.parse(rj["next_attempt_at"])
            assert freshness.requeue_due(conn, t) == 1

    rj = conn.execute("SELECT * FROM refresh_jobs ORDER BY id DESC LIMIT 1").fetchone()
    assert rj["state"] == "failed" and rj["dead_lettered"] == 1 and rj["error"] == "upstream 503"
    assert states(conn)[("feed", "nvd")] == "failed"
    events = conn.execute("SELECT reason FROM cache_state_events WHERE to_state='failed'").fetchall()
    assert any("retries exhausted" in e["reason"] for e in events)


def test_refresh_requests_are_idempotent_audited_and_skip_collector_layer(env):
    _, _, conn, _ = env
    first = freshness.request_refresh(conn, 1, "token:t-operate", layer="feed")
    second = freshness.request_refresh(conn, 1, "token:t-operate", layer="feed")
    assert first[0]["status"] == "queued" and second[0]["status"] == "already_queued"
    assert conn.execute("SELECT COUNT(*) FROM jobs WHERE type='freshness_refresh'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='freshness.refresh'").fetchone()[0] == 1
    skipped = freshness.request_refresh(conn, 1, "token:t-operate", layer="inventory", asset_id="web-01")
    assert skipped[0]["status"] == "skipped"


def test_layer_state_is_worst_of_its_entries_and_health_follows(env):
    client, tokens, conn, _ = env
    ingest(client, tokens)
    now = datetime.now(timezone.utc)
    conn.execute("INSERT INTO provider_status (provider, last_success_at, records_last_run) VALUES ('nvd', ?, 1)", (fmt(now),))
    conn.execute("INSERT INTO provider_status (provider, last_success_at, records_last_run) VALUES ('osv', ?, 1)", (fmt(now),))
    conn.commit()
    freshness.sweep(conn, 1, now)
    conn.execute("UPDATE cache_entries SET state='running' WHERE layer_key='feed' AND scope_id='nvd'")
    conn.execute("UPDATE cache_entries SET state='stale' WHERE layer_key='feed' AND scope_id='osv'")
    conn.commit()
    views = {v["key"]: v for v in freshness.layer_views(conn, 1, now)}
    assert views["feed"]["state"] == "stale"

    conn.execute("UPDATE cache_entries SET state='failed' WHERE layer_key='inventory'")
    conn.commit()
    summary = freshness.summary(conn, 1, now)
    assert summary["health"] == "Critical"
    assert summary["distribution"]["failed"] == 1
    assert set(summary["distribution"]) == {"success", "running", "stale", "pending", "failed"}


def test_assets_reporting_counts_heartbeat_or_recent_snapshot(env):
    client, tokens, conn, settings = env
    ingest(client, tokens)
    now = datetime.now(timezone.utc)
    conn.execute("INSERT INTO assets (workspace_id, asset_id, first_seen, last_seen, updated_at, last_heartbeat_at) VALUES (1, 'hb-only', ?, ?, ?, ?)",
                 (fmt(now), fmt(now), fmt(now), fmt(now)))
    conn.execute("INSERT INTO assets (workspace_id, asset_id, first_seen, last_seen, updated_at, last_heartbeat_at) VALUES (1, 'quiet', ?, ?, ?, ?)",
                 (fmt(now), fmt(now), fmt(now), fmt(now - timedelta(days=3))))
    conn.commit()
    assert freshness.assets_reporting(conn, 1, now) == 2
    assert dashboard_stats(conn, 1, settings)["assets_reporting_24h"] == 2


def test_freshness_api_permissions_contract_and_reconciliation(env):
    client, tokens, conn, settings = env
    ingest(client, tokens)
    assert client.get("/api/v1/freshness/summary", headers=h(tokens["read"])).status_code == 200
    assert client.get("/api/v1/freshness/summary").status_code == 401
    assert client.post("/api/v1/freshness/refresh", json={"layer": "feed"}, headers=h(tokens["read"])).status_code == 403
    assert client.post("/api/v1/freshness/refresh", json={"layer": "nope"}, headers=h(tokens["operate"])).status_code == 422
    assert client.post("/api/v1/freshness/refresh", json={"asset_id": "missing"}, headers=h(tokens["operate"])).status_code == 404

    first = client.post("/api/v1/freshness/refresh", json={"layer": "feed"}, headers=h(tokens["operate"]))
    assert first.status_code == 202 and first.json()["results"][0]["status"] == "queued"
    again = client.post("/api/v1/freshness/refresh", json={"layer": "feed"}, headers=h(tokens["operate"]))
    assert again.json()["results"][0]["status"] == "already_queued"
    assert client.post("/api/v1/freshness/invalidate-stale", headers=h(tokens["operate"])).status_code == 202

    jobs = client.get("/api/v1/freshness/jobs", headers=h(tokens["read"])).json()["items"]
    assert len(jobs) == 1 and jobs[0]["state"] == "queued"
    assert client.get("/api/v1/freshness/jobs?state=bogus", headers=h(tokens["read"])).status_code == 422
    triggers = client.get("/api/v1/freshness/triggers", headers=h(tokens["read"])).json()["items"]
    assert {"name": "Manual refresh", "scope": "Any layer or asset", "status": "Built"} in triggers
    gaps = [g["title"] for g in client.get("/api/v1/freshness/gaps", headers=h(tokens["read"])).json()["items"]]
    assert "Retry and dead-letter queue" not in gaps and "Agent heartbeat and stale alert" in gaps

    summary = client.get("/api/v1/freshness/summary", headers=h(tokens["read"])).json()
    assert summary["assets_reporting"]["reporting"] == dashboard_stats(conn, 1, settings)["assets_reporting_24h"]


def test_coverage_page_is_in_nav_and_tabs_persist_in_url(env):
    client, tokens, conn, _ = env
    session_for(client, conn, "viewer")
    page = client.get("/ui")
    assert page.status_code == 200
    assert 'href="/ui/jobs"' not in page.text and 'href="/ui/system"' not in page.text
    assert 'href="/ui/coverage"' in page.text and ">Coverage</a>" in page.text

    exec_page = client.get("/ui/coverage")
    assert exec_page.status_code == 200
    assert "Coverage &amp; Freshness" in exec_page.text or "Coverage & Freshness" in exec_page.text
    assert 'href="/ui/coverage?tab=tech"' in exec_page.text and 'aria-current="page">Executive summary' in exec_page.text
    assert "State distribution" in exec_page.text and "Freshness targets" in exec_page.text
    assert "Coverage refresh runs" not in exec_page.text

    tech = client.get("/ui/coverage", params={"tab": "tech"})
    assert "Coverage refresh runs" in tech.text and "Background jobs" in tech.text and "Schedules" in tech.text and "Invalidation triggers" in tech.text and "Gaps and next steps" in tech.text
    assert "Manual refresh" in tech.text and "Built" in tech.text
    assert "Retry and dead-letter queue" not in tech.text and "Agent heartbeat and stale alert" in tech.text
    assert "State distribution" not in tech.text


def test_coverage_actions_require_operate_scope_and_csrf(env):
    client, tokens, conn, _ = env
    session_for(client, conn, "viewer")
    read_page = client.get("/ui/coverage")
    assert "Refresh all" not in read_page.text and "Read-only" in read_page.text
    assert client.post("/ui/actions/coverage/refresh", data={"csrf": auth.csrf_for(client.cookies.get("rp_session"))}, follow_redirects=False).status_code == 403

    client.cookies.clear()
    session_for(client, conn, "operator")
    op_page = client.get("/ui/coverage")
    assert "Refresh all" in op_page.text and "Invalidate stale" in op_page.text
    form = re.search(r'<form[^>]+action="/ui/actions/coverage/refresh"[^>]*>(.*?)</form>', op_page.text, re.S)
    assert form
    csrf = re.search(r'name="csrf" value="([^"]+)"', form.group(1)).group(1)
    assert client.post("/ui/actions/coverage/refresh", data={"csrf": "bad"}, follow_redirects=False).status_code == 403

    queued = client.post("/ui/actions/coverage/refresh", data={"csrf": csrf}, follow_redirects=False)
    assert queued.status_code == 303 and queued.headers["location"].startswith("/ui/coverage?queued=")
    assert conn.execute("SELECT COUNT(*) FROM refresh_jobs WHERE state='queued'").fetchone()[0] >= 1
    notice = client.get("/ui/coverage", params={"queued": 1})
    assert "Refresh requested: 1 queued" in notice.text

    stale = client.post("/ui/actions/coverage/invalidate", data={"csrf": csrf}, follow_redirects=False)
    assert stale.status_code == 303


def test_coverage_numbers_match_overview_and_dynamic_text_is_escaped(env):
    client, tokens, conn, settings = env
    ingest(client, tokens)
    now = datetime.now(timezone.utc)
    freshness.enqueue_targets(conn, 1, "token:t-operate", [("correlation", "<img src=x>")], "manual")
    session_for(client, conn, "viewer")
    overview = client.get("/ui").text
    stats = dashboard_stats(conn, 1, settings)
    coverage = client.get("/ui/coverage", params={"tab": "tech"}).text
    assert f"{stats['assets_reporting_24h']} / {stats['assets']}" in coverage
    assert f"{stats['assets_reporting_24h']} reporting in the last 24h" in overview
    assert "<img src=x>" not in coverage and "&lt;img src=x&gt;" in coverage


def test_jobs_and_system_moved_into_coverage_with_schedule_controls(env):
    client, tokens, conn, _ = env
    session_for(client, conn, "operator")
    op = client.get("/ui/coverage", params={"tab": "tech"}).text
    assert "Admin scope required" in op and "Add schedule" not in op
    assert client.post("/ui/actions/job-schedule/create", data={"csrf": auth.csrf_for(client.cookies.get("rp_session")), "name": "x", "job_type": "cve_sync", "interval_seconds": "3600"}, follow_redirects=False).status_code == 403

    client.cookies.clear()
    session_for(client, conn, "admin")
    page = client.get("/ui/coverage", params={"tab": "tech"}).text
    assert "Background scheduler" in page and "Add schedule" in page and "Background jobs" in page
    form = re.search(r'<form[^>]+action="/ui/actions/job-schedule/create"[^>]*>(.*?)</form>', page, re.S)
    csrf = re.search(r'name="csrf" value="([^"]+)"', form.group(1)).group(1)

    created = client.post("/ui/actions/job-schedule/create", data={"csrf": csrf, "name": "Hourly CVE sync", "job_type": "cve_sync", "interval_seconds": "3600"}, follow_redirects=False)
    assert created.status_code == 303 and created.headers["location"] == "/ui/coverage?tab=tech"
    page = client.get("/ui/coverage", params={"tab": "tech"}).text
    assert "Hourly CVE sync" in page and "Every hour" in page and "Run now" in page and "Delete" in page
    sid = conn.execute("SELECT id FROM job_schedules WHERE name='Hourly CVE sync'").fetchone()[0]
    from riskpatch.jobs import enqueue
    enqueue(conn, "cve_sync", "schedule", {"scheduled": True}, 1)
    scheduled_page = client.get("/ui/coverage", params={"tab": "tech"}).text
    assert ">Scheduled</td>" in scheduled_page and "within 30 days" not in scheduled_page

    assert client.post(f"/ui/actions/job-schedule/{sid}/toggle", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert conn.execute("SELECT enabled FROM job_schedules WHERE id=?", (sid,)).fetchone()[0] == 0
    assert client.post(f"/ui/actions/job-schedule/{sid}/run", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert conn.execute("SELECT COUNT(*) FROM jobs WHERE type='cve_sync' AND trigger_source='ui'").fetchone()[0] >= 1
    assert client.post(f"/ui/actions/job-schedule/{sid}/delete", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert conn.execute("SELECT COUNT(*) FROM job_schedules WHERE id=?", (sid,)).fetchone()[0] == 0

    assert client.post("/ui/actions/system-config/disable", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert "Stopped" in client.get("/ui/coverage", params={"tab": "tech"}).text

    old_jobs = client.get("/ui/jobs", follow_redirects=False)
    old_system = client.get("/ui/system", follow_redirects=False)
    assert old_jobs.status_code == 303 and old_jobs.headers["location"] == "/ui/coverage?tab=tech&offset=0"
    assert old_system.status_code == 303 and old_system.headers["location"] == "/ui/coverage?tab=tech"



def test_ingest_queues_analysis_for_the_new_asset(env):
    client, tokens, conn, _ = env
    ingest(client, tokens)
    queued = conn.execute(
        "SELECT scope_json, status FROM jobs WHERE type='analysis' AND trigger_source='ingest.snapshot'"
    ).fetchall()
    assert len(queued) == 1
    assert queued[0]["scope_json"] == '{"asset_id": "web-01"}' and queued[0]["status"] == "queued"


def test_login_uses_username_and_password_and_rejects_bad_credentials(env):
    client, tokens, conn, _ = env
    from tests.helpers import PASSWORD
    auth.create_user(conn, "alice", PASSWORD, "viewer", "test")
    bad = client.post("/ui/login", data={"username": "alice", "password": "wrong-password-here"}, follow_redirects=False)
    assert bad.status_code == 401 and "Invalid username or password." in bad.text
    assert client.cookies.get("rp_session") is None
    unknown = client.post("/ui/login", data={"username": "nobody", "password": PASSWORD}, follow_redirects=False)
    assert unknown.status_code == 401 and "Invalid username or password." in unknown.text

    good = client.post("/ui/login", data={"username": "alice", "password": PASSWORD}, follow_redirects=False)
    assert good.status_code == 303
    assert client.cookies.get("rp_session", "").startswith("rpu_")
    assert "Read-only" in client.get("/ui/coverage").text
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='user.login_failed'").fetchone()[0] == 2


def test_analysis_keeps_unaffected_assets_from_looking_stale_after_a_catalog_change(env):
    from riskpatch.analysis import run_analysis

    client, tokens, conn, settings = env
    ingest(client, tokens)
    run_analysis(conn, settings, 1, {}, None)
    freshness.sweep(conn, 1, datetime.now(timezone.utc))
    assert states(conn)[("correlation", "web-01")] == "success"

    # a CVE sync changed the catalog: the stored fingerprint no longer matches, as in production after every sync
    conn.execute("UPDATE cache_entries SET input_fingerprint='fingerprint-from-an-older-catalog' WHERE layer_key='correlation'")
    conn.commit()
    freshness.sweep(conn, 1, datetime.now(timezone.utc))
    assert states(conn)[("correlation", "web-01")] == "stale"

    # nothing affects web-01, so the analysis run re-analyzes nobody, yet its findings are confirmed current
    counts = run_analysis(conn, settings, 1, {}, None)
    assert counts["assets"] == 0
    assert states(conn)[("correlation", "web-01")] == "success"


def test_scoped_analysis_only_confirms_its_own_asset_and_inventory_staleness_still_wins(env):
    from riskpatch.analysis import run_analysis

    client, tokens, conn, settings = env
    ingest(client, tokens)
    run_analysis(conn, settings, 1, {}, None)
    conn.execute("UPDATE cache_entries SET input_fingerprint='old' WHERE layer_key='correlation'")
    conn.commit()
    assert freshness.mark_correlation_current(conn, 1, datetime.now(timezone.utc), ["other-asset"]) == 0
    assert states(conn)[("correlation", "web-01")] == "stale"
    assert freshness.mark_correlation_current(conn, 1, datetime.now(timezone.utc), ["web-01"], frozenset({"web-01"})) == 0  # failed analysis stays stale
    assert states(conn)[("correlation", "web-01")] == "stale"
    freshness.mark_correlation_current(conn, 1, datetime.now(timezone.utc), ["web-01"])
    assert states(conn)[("correlation", "web-01")] == "success"

    # a stale inventory still marks the results stale even though they were just confirmed
    later = datetime.now(timezone.utc) + timedelta(hours=30)
    freshness.sweep(conn, 1, later)
    assert states(conn)[("inventory", "web-01")] == "stale" and states(conn)[("correlation", "web-01")] == "stale"


def test_coverage_lists_servers_needing_attention_with_reason_and_findings(env):
    client, tokens, conn, _ = env
    ingest(client, tokens)
    session_for(client, conn, "viewer")
    assert "Every server’s data is up to date." in client.get("/ui/coverage").text

    old = fmt(datetime.now(timezone.utc) - timedelta(days=3))
    conn.execute("UPDATE snapshots SET collected_at=?", (old,))
    conn.commit()
    page = client.get("/ui/coverage").text
    assert "Servers needing attention" in page
    assert 'href="/ui/assets/web-01"' in page and "No snapshot within the target" in page
    assert "Run the collector on these servers" in page and "last known" in page

    rows, total = freshness.attention_assets(conn, 1)
    assert total == 1 and rows[0]["asset_id"] == "web-01" and rows[0]["inventory_problem"] and rows[0]["target_seconds"] == 86400


def test_cve_sync_queues_one_followup_analysis(env):
    from riskpatch.jobs import queue_followup_analysis

    _, _, conn, _ = env
    queue_followup_analysis(conn, 1)
    queue_followup_analysis(conn, 1)  # an identical queued job is reused, not duplicated
    rows = conn.execute("SELECT type, trigger_source, status FROM jobs WHERE type='analysis'").fetchall()
    assert [(r["type"], r["trigger_source"], r["status"]) for r in rows] == [("analysis", "cve_sync.followup", "queued")]


def test_summary_splits_open_findings_into_confirmed_and_old_data(env):
    from tests.test_api import _add_findings

    client, tokens, conn, _ = env
    ingest(client, tokens)
    now = datetime.now(timezone.utc)
    asset_pk = conn.execute("SELECT id FROM assets WHERE asset_id='web-01'").fetchone()[0]
    conn.execute("INSERT INTO reports (workspace_id, asset_pk, asset_id, generated_at, highest, stale, content_json, content_md) VALUES (1, ?, 'web-01', ?, 'low', 0, '{}', '')", (asset_pk, fmt(now)))
    _add_findings(conn, "web-01", {"critical": 3})
    _add_findings(conn, "never-checked", {"high": 2})  # no cache entries: counted in the total only
    conn.commit()

    freshness.sweep(conn, 1, now)
    s = freshness.summary(conn, 1, now)
    assert s["findings_open_total"] == 5 and s["findings_confirmed"] == 3 and s["findings_old_data"] == 0

    later = now + timedelta(hours=30)  # inventory target (24h) has passed
    freshness.sweep(conn, 1, later)
    s = freshness.summary(conn, 1, later)
    assert s["findings_open_total"] == 5 and s["findings_confirmed"] == 0 and s["findings_old_data"] == 3


def test_checkpoint_wal_truncates_the_log(tmp_path):
    import os

    from riskpatch.db import checkpoint_wal

    conn = connect(tmp_path / "w.sqlite3")
    conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    for i in range(200):
        conn.execute("INSERT INTO t (v) VALUES (?)", ("x" * 2000,))
    wal = tmp_path / "w.sqlite3-wal"
    assert wal.exists() and os.path.getsize(wal) > 0
    result = checkpoint_wal(conn)
    assert result["busy"] is False
    assert os.path.getsize(wal) == 0
    assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 200


def test_prune_reports_keeps_newest_per_asset_and_markdown(env):
    from riskpatch.jobs import prune_reports

    client, tokens, conn, _ = env
    ingest(client, tokens)
    a1 = conn.execute("SELECT id FROM assets WHERE asset_id='web-01'").fetchone()[0]
    a2 = conn.execute("INSERT INTO assets (workspace_id, asset_id, first_seen, last_seen, updated_at) VALUES (1,'db-01','x','x','x')").lastrowid
    now = fmt(datetime.now(timezone.utc))
    for pk, name, n in ((a1, "web-01", 5), (a2, "db-01", 2)):
        for i in range(n):
            conn.execute("INSERT INTO reports (workspace_id, asset_pk, asset_id, generated_at, highest, stale, content_json, content_md) VALUES (1,?,?,?, 'low', 0, ?, ?)",
                         (pk, name, now, '{"big": "' + "x" * 1000 + '"}', f"# report {i}"))
    conn.commit()

    assert prune_reports(conn, keep=3) == 2  # only web-01 has more than 3
    full = {r["asset_id"]: r["n"] for r in conn.execute("SELECT asset_id, COUNT(*) n FROM reports WHERE content_json != '{}' GROUP BY asset_id")}
    assert full == {"web-01": 3, "db-01": 2}
    newest = conn.execute("SELECT content_json FROM reports WHERE asset_id='web-01' ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert newest.startswith('{"big"')
    assert conn.execute("SELECT COUNT(*) FROM reports WHERE content_md LIKE '# report%'").fetchone()[0] == 7  # markdown is kept
    assert prune_reports(conn, keep=3) == 0  # idempotent


def _correlation_only_stale(client, tokens, conn):
    """web-01 has a fresh inventory but its findings need a re-check (the catalog changed since the last check)."""
    ingest(client, tokens)
    now = datetime.now(timezone.utc)
    pk = conn.execute("SELECT id FROM assets WHERE asset_id='web-01'").fetchone()[0]
    conn.execute("INSERT INTO reports (workspace_id, asset_pk, asset_id, generated_at, highest, stale, content_json, content_md) VALUES (1, ?, 'web-01', ?, 'low', 0, '{}', '')", (pk, fmt(now)))
    conn.commit()
    freshness.sweep(conn, 1, now)
    conn.execute("UPDATE cache_entries SET input_fingerprint='older-catalog' WHERE layer_key='correlation'")
    conn.commit()


def test_attention_table_offers_recheck_to_operators_only_and_shows_refresh_status(env):
    client, tokens, conn, _ = env
    _correlation_only_stale(client, tokens, conn)

    session_for(client, conn, "viewer")
    page = client.get("/ui/coverage").text
    assert "Findings need a re-check" in page and "An operator can re-check" in page and "Re-check now" not in page

    client.cookies.clear()
    session_for(client, conn, "operator")
    page = client.get("/ui/coverage").text
    form = re.search(r'<form[^>]+action="/ui/actions/coverage/refresh-asset"[^>]*>(.*?)</form>', page, re.S)
    assert form and 'value="web-01"' in form.group(1) and "Re-check now" in page
    csrf = re.search(r'name="csrf" value="([^"]+)"', form.group(1)).group(1)
    assert client.post("/ui/actions/coverage/refresh-asset", data={"csrf": "bad", "asset_id": "web-01"}, follow_redirects=False).status_code == 403
    assert client.post("/ui/actions/coverage/refresh-asset", data={"csrf": csrf, "asset_id": "nope"}, follow_redirects=False).status_code == 404
    ok = client.post("/ui/actions/coverage/refresh-asset", data={"csrf": csrf, "asset_id": "web-01"}, follow_redirects=False)
    assert ok.status_code == 303 and "queued=1" in ok.headers["location"]
    assert conn.execute("SELECT COUNT(*) FROM refresh_jobs WHERE target='web-01' AND layer_key='correlation' AND state='queued'").fetchone()[0] == 1
    assert "Re-check queued" in client.get("/ui/coverage").text


def test_assets_and_findings_show_freshness_chips_and_clear_timestamp_labels(env):
    from tests.test_api import _add_findings

    client, tokens, conn, _ = env
    _correlation_only_stale(client, tokens, conn)
    _add_findings(conn, "web-01", {"high": 1})
    conn.commit()
    freshness.sweep(conn, 1, datetime.now(timezone.utc))  # the worker does this every few seconds
    session_for(client, conn, "viewer")
    assets = client.get("/ui/assets").text
    assert "Last snapshot" in assets and "Last seen" not in assets
    assert "Data</th>" in assets and "Stale" in assets and 'href="/ui/coverage"' in assets
    findings = client.get("/ui/findings").text
    assert "Last checked" in findings and "Data</th>" in findings and "Stale" in findings
    detail = client.get("/ui/assets/web-01").text
    assert "Last snapshot received" in detail and "Findings last checked" in detail

    assert freshness.asset_freshness(conn, 1, ["web-01", "ghost"]) == {"web-01": ("stale", False), "ghost": ("pending", False)}


def test_status_page_shows_feed_runs_with_change_vs_previous_run(env):
    import json

    client, tokens, conn, _ = env
    session_for(client, conn, "viewer")
    assert "Intel feed runs" in client.get("/ui/status").text  # empty state still renders

    def job(i, nvd, created, status="success", ok=True):
        conn.execute(
            "INSERT INTO jobs (workspace_id, type, status, trigger_source, scope_json, queued_at, finished_at, counts_json, provider_status_json, updated_at) VALUES (1,'cve_sync',?,'schedule','{}',?,?,?,?,?)",
            (status, f"2026-11-11T1{i}:00:00Z", f"2026-11-11T1{i}:01:00Z", json.dumps({"created": created, "updated": 2, "unchanged": 5, "failed": 0}),
             json.dumps({"kev": {"ok": True, "records": 0}, "nvd": {"ok": ok, "records": nvd}, "osv": {"ok": True, "records": 3}}), "x"))
    job(1, 77, 30)
    job(2, 8, 7)
    job(3, 20, 1, status="partial", ok=False)
    conn.commit()
    page = client.get("/ui/status").text
    assert "Change vs previous" in page and "Sources that failed" in page and "not counted individually yet" in page
    # received per run: run3 = 20+3 = 23, run2 = 8+3 = 11, run1 = 77+3 = 80 (oldest, so no previous run)
    assert "+12" in page   # run 3 vs run 2: 23 - 11
    assert "-69" in page   # run 2 vs run 1: 11 - 80
    assert page.count("nvd") >= 1


def test_backfill_fills_fixed_version_from_verdict_json_in_batches(env):
    from riskpatch.jobs import backfill_fixed_versions
    from tests.test_api import _add_findings

    _, _, conn, _ = env
    _add_findings(conn, "web-1", {"high": 5})
    conn.execute("UPDATE findings SET fixed_version=NULL")  # as after the migration, before the backfill
    conn.execute("UPDATE findings SET verdict_json='{\"min_safe_target\": \"2.4.1\"}' WHERE id IN (1,3,5)")
    conn.commit()
    assert backfill_fixed_versions(conn, batch=2) == 5          # several small batches
    values = [r[0] for r in conn.execute("SELECT fixed_version FROM findings ORDER BY id")]
    assert values == ["2.4.1", "", "2.4.1", "", "2.4.1"]        # '' = no fixed version known, never NULL afterwards
    assert backfill_fixed_versions(conn) == 0                    # nothing left to do, cheap to re-run


def test_analysis_stores_fixed_version_on_findings(env):
    import json as _json

    from riskpatch.analysis import run_analysis

    client, tokens, conn, settings = env
    ingest(client, tokens)
    run_analysis(conn, settings, 1, {}, None)
    # offline test data may produce no findings; whatever was written must carry a non-NULL fixed_version consistent with its verdict
    for r in conn.execute("SELECT fixed_version, verdict_json FROM findings"):
        assert r["fixed_version"] is not None and r["fixed_version"] == (_json.loads(r["verdict_json"]).get("min_safe_target") or "")


def test_fixed_version_is_derived_from_the_affected_range_that_contains_the_installed_version():
    from riskpatch.facts import VersionBound
    from riskpatch.match import derive_fixed_versions

    ranges = [VersionBound(start_including="6.2", end_excluding="8.8"), VersionBound(start_including="9.0", end_excluding="9.3"),
              VersionBound(end_including="7.0"), VersionBound(exact="8.1"), VersionBound(end_excluding="not-comparable")]
    assert derive_fixed_versions("8.2", ranges) == ["8.8"]          # only the range that contains 8.2; end_including / exact say nothing about a fix
    assert derive_fixed_versions("9.1", ranges) == ["9.3"]
    assert derive_fixed_versions("5.0", ranges) == []               # below every range that has a fix
    assert derive_fixed_versions("not-a-version", ranges) == []     # never guess for versions that cannot be compared


def test_backfill_fixed_from_ranges_uses_stored_evidence_once(env):
    import json as _json

    from riskpatch.jobs import FIXED_FROM_RANGES_MARKER, backfill_fixed_from_ranges
    from tests.test_api import _add_findings

    _, _, conn, _ = env
    _add_findings(conn, "web-1", {"high": 3})
    conn.execute("UPDATE findings SET fixed_version='', component_version='8.2'")
    evidence = {1: [{"start_including": "6.2", "end_excluding": "8.8"}], 2: [{"end_including": "9.9"}], 3: [{"end_excluding": "not-comparable"}]}
    for fid, ranges in evidence.items():
        conn.execute("INSERT INTO finding_evidence (finding_id, kind, detail, created_at) VALUES (?, 'affected_range', ?, 'x')", (fid, _json.dumps({"ranges": ranges})))
    conn.commit()
    assert backfill_fixed_from_ranges(conn, batch=2) == 1
    rows = {r["id"]: (r["fixed_version"], _json.loads(r["verdict_json"]).get("min_safe_target")) for r in conn.execute("SELECT id, fixed_version, verdict_json FROM findings")}
    assert rows[1] == ("8.8", "8.8") and rows[2] == ("", None) and rows[3] == ("", None)
    assert conn.execute("SELECT value FROM system_settings WHERE key=?", (FIXED_FROM_RANGES_MARKER,)).fetchone()[0] == "done"
    conn.execute("INSERT INTO finding_evidence (finding_id, kind, detail, created_at) VALUES (2, 'affected_range', ?, 'x')", (_json.dumps({"ranges": [{"end_excluding": "9.10"}]}),))
    assert backfill_fixed_from_ranges(conn) == 0                     # marker set: never re-run on restart
