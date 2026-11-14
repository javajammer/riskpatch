import csv
import io
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest

from riskpatch import campaigns, work
from tests.helpers import session_for, register
from tests.test_api import _add_findings, env  # noqa: F401  (env fixture)
from tests.test_work import CURL, OPENSSL, _fix, _seed, _snapshot


def _plan(conn, keys=None, **kw):
    kw.setdefault("owner", "Platform team")
    kw.setdefault("backout_plan", "Reinstall the previous package from the local mirror")
    kw.setdefault("window_start", "2026-12-01")
    kw.setdefault("window_end", "2026-12-03")
    return campaigns.create(conn, 1, "user:ana", kw.pop("name", "Q4 openssl upgrade"), [OPENSSL] if keys is None else keys, **kw)


def test_create_plans_items_servers_and_schedules_the_work(env):
    _, _, conn, _ = env
    _seed(conn)
    cid = _plan(conn, [OPENSSL, CURL], ticket_id="CHG-1042")
    camp = campaigns.get(conn, 1, cid)
    assert (camp["status"], camp["owner"], camp["ticket_id"], camp["created_by"]) == ("planned", "Platform team", "CHG-1042", "user:ana")
    assert [i["cve_id"] for i in campaigns.items(conn, cid)] == ["CVE-2026-9001", "CVE-2026-9002"] and campaigns.items(conn, cid)[0]["server_count"] == 3
    prog = campaigns.progress(conn, 1, cid)
    assert prog["total"] == 3 and prog["counts"] == {"Planned": 3} and {r["asset_id"] for r in prog["servers"]} == {"web-1", "web-2", "db-1"}
    row = work.item(conn, 1, OPENSSL)
    assert row["state"] == "scheduled" and row["assignee"] == "Platform team"          # planning schedules the work item
    assert "campaign 'Q4 openssl upgrade'" in work.history(conn, row["id"])[0]["note"]
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='campaign.create'").fetchone()[0] == 1
    assert campaigns.list_campaigns(conn, 1)[0]["item_count"] == 2 and campaigns.list_campaigns(conn, 1, "scheduled") == []

    for bad in (dict(name="ab"), dict(keys=[]), dict(window_start="x"), dict(window_start="2026-12-05", window_end="2026-12-01"), dict(ticket_id="x" * 121)):
        with pytest.raises(ValueError):
            _plan(conn, **{"keys": [CURL], **bad} if "keys" not in bad else bad)
    work.triage(conn, 1, CURL, "u", "not_applicable", note="feature disabled")
    with pytest.raises(ValueError, match="cannot be planned"):
        _plan(conn, [CURL], name="Another")
    with pytest.raises(ValueError, match="no open findings"):
        _plan(conn, [work.Key("CVE-0", "pypi", "x", "1", "")], name="Ghost")
    assert len(campaigns.list_campaigns(conn, 1)) == 1                                  # failed attempts created nothing


def test_approval_scheduling_and_editing_rules(env):
    _, _, conn, _ = env
    _seed(conn)
    cid = _plan(conn)
    with pytest.raises(ValueError, match="approval"):
        campaigns.set_status(conn, 1, cid, "user:ana", "scheduled")
    with pytest.raises(ValueError, match="cannot approve"):
        campaigns.approve(conn, 1, cid, "user:ana")                                     # not by the author
    campaigns.approve(conn, 1, cid, "user:root")
    assert campaigns.get(conn, 1, cid)["approved_by"] == "user:root"
    campaigns.set_status(conn, 1, cid, "user:ana", "scheduled")

    assert campaigns.update_details(conn, 1, cid, "user:ana", notes="Run after the freeze") is True
    assert campaigns.get(conn, 1, cid)["approved_by"] == "user:root"                    # notes do not need re-approval
    assert campaigns.update_details(conn, 1, cid, "user:ana", window_end="2026-12-10") is True
    assert campaigns.get(conn, 1, cid)["approved_by"] == "" and campaigns.update_details(conn, 1, cid, "user:ana", window_end="2026-12-10") is False
    assert "approval withdrawn" in campaigns.history(conn, cid)[0]["detail"]
    with pytest.raises(ValueError, match="before it starts"):
        campaigns.update_details(conn, 1, cid, "u", window_end="2020-01-01")
    with pytest.raises(ValueError, match="unknown field"):
        campaigns.update_details(conn, 1, cid, "u", status="completed")

    with pytest.raises(ValueError, match="cannot become"):
        campaigns.set_status(conn, 1, cid, "u", "completed")                            # must run first
    with pytest.raises(ValueError, match="reason"):
        campaigns.set_status(conn, 1, cid, "u", "cancelled")
    campaigns.set_status(conn, 1, cid, "user:ana", "in_progress")
    campaigns.set_status(conn, 1, cid, "user:ana", "completed")
    with pytest.raises(ValueError, match="only planned or scheduled"):
        campaigns.update_details(conn, 1, cid, "u", notes="late")
    assert [e["action"] for e in campaigns.history(conn, cid)][:2] == ["status: in_progress -> completed", "status: scheduled -> in_progress"]
    bare = _plan(conn, [CURL], name="No backout", backout_plan="")
    with pytest.raises(ValueError, match="backout"):
        campaigns.approve(conn, 1, bare, "user:root")


def test_server_reports_and_snapshot_evidence_decide_verified(env):
    _, _, conn, _ = env
    _seed(conn)
    for a in ("web-1", "web-2", "db-1"):
        _snapshot(conn, a, "2020-01-01T00:00:00Z")
    cid = _plan(conn)
    with pytest.raises(ValueError, match="scheduled or in progress"):
        campaigns.report_servers(conn, 1, cid, "u", ["web-1"], "updated")
    campaigns.approve(conn, 1, cid, "user:root")
    campaigns.set_status(conn, 1, cid, "user:ana", "scheduled")
    campaigns.set_status(conn, 1, cid, "user:ana", "in_progress")
    with pytest.raises(ValueError, match="note is required"):
        campaigns.report_servers(conn, 1, cid, "u", ["web-1"], "failed")
    with pytest.raises(ValueError, match="not part"):
        campaigns.report_servers(conn, 1, cid, "u", ["ghost"], "updated")

    assert campaigns.report_servers(conn, 1, cid, "user:ops", ["web-1", "web-2", "db-1"], "updated") == 3
    counts = campaigns.progress(conn, 1, cid)["counts"]
    assert counts == {"Awaiting verification": 3}                                        # reporting is not proof

    _fix(conn, "web-1"); _snapshot(conn, "web-1", "2999-01-01T00:00:00Z")                 # new analyzed snapshot, finding gone
    _snapshot(conn, "db-1", "2999-01-01T00:00:00Z")                                      # new snapshot but the finding is still open
    labels = {r["asset_id"]: r["label"] for r in campaigns.progress(conn, 1, cid)["servers"]}
    assert labels == {"web-1": "Verified", "web-2": "Awaiting verification", "db-1": "Still affected"}
    campaigns.report_servers(conn, 1, cid, "user:ops", ["web-2"], "unreachable", "host is powered off")
    assert {r["asset_id"]: r["label"] for r in campaigns.progress(conn, 1, cid)["servers"]}["web-2"] == "Unreachable"
    assert campaigns.progress(conn, 1, cid)["verified"] == 1

    rows = campaigns.change_list(conn, 1, cid)
    assert [(r["server"], r["cve"], r["progress"]) for r in rows] == [("db-1", "CVE-2026-9001", "Still affected"), ("web-1", "CVE-2026-9001", "Verified"), ("web-2", "CVE-2026-9001", "Unreachable")]
    assert rows[1]["owner"] == "Web team" and rows[1]["tier"] == "tier1" and rows[1]["upstream_fix"] == "3.0.16" and rows[1]["ticket"] == "" and rows[1]["window_start"] == "2026-12-01"


def test_campaign_pages_permissions_and_change_list_download(env):
    client, _, conn, _ = env
    register(conn, "SOC", "Platform", "Platform team", "Ops", "Web team", "A", "B", "x")
    _seed(conn)
    assert client.get("/ui/campaigns", follow_redirects=False).status_code == 303 and client.get("/ui/campaigns/1/change-list.csv", follow_redirects=False).status_code == 303
    session_for(client, conn, "operator")
    queue = client.get("/ui/work").text
    assert "Plan a campaign from the selected items" in queue
    csrf = re.search(r'name="csrf" value="([^"]+)"', queue).group(1)
    base = {"csrf": csrf, "k": [quote(OPENSSL.encode())], "name": "Q4 openssl upgrade", "owner": "Platform team", "window_start": "2026-12-01", "window_end": "2026-12-03",
            "ticket_id": "CHG-7", "backout_plan": "Reinstall previous package"}
    assert client.post("/ui/actions/campaigns/create", data={**base, "csrf": "bad"}, follow_redirects=False).status_code == 403
    assert "error=" in client.post("/ui/actions/campaigns/create", data={**base, "k": []}, follow_redirects=False).headers["location"]
    ok = client.post("/ui/actions/campaigns/create", data=base, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"].startswith("/ui/campaigns/1")

    listing = client.get("/ui/campaigns").text
    assert "Q4 openssl upgrade" in listing and "Planned" in listing and "CHG-7" in listing and 'href="/ui/campaigns/1"' in listing
    detail = client.get("/ui/campaigns/1").text
    assert "Servers" in detail and "web-1" in detail and "Download change list" in detail and "Backout plan" in detail and "Awaiting approval" in detail
    assert 'action="/ui/actions/campaigns/1/approve"' not in detail                                  # operators cannot approve
    assert "Plan a campaign from the selected items" in client.get("/ui/work").text
    assert client.get("/ui/campaigns/99", follow_redirects=False).status_code == 404

    csv_resp = client.get("/ui/campaigns/1/change-list.csv")
    assert csv_resp.status_code == 200 and csv_resp.headers["content-type"].startswith("text/csv") and "riskpatch-campaign-1-" in csv_resp.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(csv_resp.text.lstrip("﻿"))))
    assert rows[0][:3] == ["server", "owner", "tier"] and len(rows) == 4 and {r[0] for r in rows[1:]} == {"web-1", "web-2", "db-1"}
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='campaign.export'").fetchone()[0] == 1

    own_csrf = re.search(r'name="csrf" value="([^"]+)"', detail).group(1)
    assert client.post("/ui/actions/campaigns/1/approve", data={"csrf": own_csrf}, follow_redirects=False).status_code == 403   # admin only

    client.cookies.clear()
    session_for(client, conn, "admin")
    detail = client.get("/ui/campaigns/1").text
    admin_csrf = re.search(r'action="/ui/actions/campaigns/1/approve".*?name="csrf" value="([^"]+)"', detail, re.S).group(1)
    assert client.post("/ui/actions/campaigns/1/approve", data={"csrf": admin_csrf}, follow_redirects=False).status_code == 303
    assert "Approved by" in client.get("/ui/campaigns/1").text

    client.cookies.clear()
    session_for(client, conn, "operator")
    page = client.get("/ui/campaigns/1").text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    sched = client.post("/ui/actions/campaigns/1/status", data={"csrf": csrf, "status": "scheduled"}, follow_redirects=False)
    assert "notice=" in sched.headers["location"]
    assert "error=" in client.post("/ui/actions/campaigns/1/status", data={"csrf": csrf, "status": "completed"}, follow_redirects=False).headers["location"]
    client.post("/ui/actions/campaigns/1/status", data={"csrf": csrf, "status": "in_progress"}, follow_redirects=False)
    rep = client.post("/ui/actions/campaigns/1/report", data={"csrf": csrf, "asset_id": ["web-1", "web-2"], "status": "updated", "note": ""}, follow_redirects=False)
    assert "notice=" in rep.headers["location"] and "Awaiting verification" in client.get("/ui/campaigns/1").text
    assert "error=" in client.post("/ui/actions/campaigns/1/report", data={"csrf": csrf, "asset_id": ["web-1"], "status": "failed", "note": ""}, follow_redirects=False).headers["location"]
    edit = client.post("/ui/actions/campaigns/1/edit", data={"csrf": csrf, "notes": "freeze until the 1st"}, follow_redirects=False)
    assert "error=" in edit.headers["location"]                                                       # in progress campaigns are no longer editable


def _running(conn, keys=None, **kw):
    cid = _plan(conn, keys, **kw)
    campaigns.approve(conn, 1, cid, "user:root")
    campaigns.set_status(conn, 1, cid, "user:ana", "scheduled")
    campaigns.set_status(conn, 1, cid, "user:ana", "in_progress")
    return cid


def test_campaign_completes_and_verifies_its_items_only_from_evidence(env):
    _, _, conn, _ = env
    _seed(conn)
    for a in ("web-1", "web-2", "db-1"):
        _snapshot(conn, a, "2020-01-01T00:00:00Z")
    cid = _running(conn)
    assert campaigns.auto_progress(conn, 1) == {"items_verified": 0, "campaigns_completed": 0}          # nothing reported yet
    campaigns.report_servers(conn, 1, cid, "user:ops", ["web-1", "web-2", "db-1"], "updated")
    assert campaigns.auto_progress(conn, 1) == {"items_verified": 0, "campaigns_completed": 0}          # reporting is not proof

    _fix(conn, "web-1"); _snapshot(conn, "web-1", "2999-01-01T00:00:00Z")
    _fix(conn, "web-2"); _snapshot(conn, "web-2", "2999-01-01T00:00:00Z")
    assert campaigns.auto_progress(conn, 1) == {"items_verified": 0, "campaigns_completed": 0}          # db-1 has not reported again
    assert work.item(conn, 1, OPENSSL)["state"] == "scheduled" and campaigns.get(conn, 1, cid)["status"] == "in_progress"

    _fix(conn, "db-1"); _snapshot(conn, "db-1", "2999-01-01T00:00:00Z")
    assert campaigns.auto_progress(conn, 1) == {"items_verified": 1, "campaigns_completed": 1}
    row = work.item(conn, 1, OPENSSL)
    assert row["state"] == "verified" and row["updated_by"] == "system:verification"
    last = work.history(conn, row["id"])[0]
    assert (last["from_state"], last["to_state"], last["server_count"]) == ("scheduled", "verified", 3) and f"campaign #{cid}" in last["note"]
    camp = campaigns.get(conn, 1, cid)
    assert camp["status"] == "completed" and camp["updated_by"] == "system:verification"
    assert "All 3 server(s) verified" in campaigns.history(conn, cid)[0]["detail"]
    assert campaigns.auto_progress(conn, 1) == {"items_verified": 0, "campaigns_completed": 0}          # completed campaigns are left alone


def test_a_failed_server_keeps_the_campaign_open(env):
    _, _, conn, _ = env
    _seed(conn)
    for a in ("web-1", "web-2", "db-1"):
        _snapshot(conn, a, "2020-01-01T00:00:00Z")
    cid = _running(conn)
    campaigns.report_servers(conn, 1, cid, "u", ["web-1", "web-2"], "updated")
    campaigns.report_servers(conn, 1, cid, "u", ["db-1"], "failed", "package conflict")
    for a in ("web-1", "web-2"):
        _fix(conn, a); _snapshot(conn, a, "2999-01-01T00:00:00Z")
    assert campaigns.auto_progress(conn, 1) == {"items_verified": 0, "campaigns_completed": 0}
    assert campaigns.progress(conn, 1, cid)["counts"] == {"Verified": 2, "Failed": 1}


def test_overlapping_campaigns_on_the_same_servers_are_flagged_but_not_blocked(env):
    client, _, conn, _ = env
    _seed(conn)
    first = _plan(conn, [OPENSSL], name="First", window_start="2026-12-01", window_end="2026-12-05")
    assert campaigns.conflicts(conn, 1, first) == []
    # the second one shares web-1 (curl runs on web-1 only) and overlaps in time
    second = _plan(conn, [CURL], name="Second", window_start="2026-12-04", window_end="2026-12-08")
    hit = campaigns.conflicts(conn, 1, second)
    assert [(c["name"], c["servers"]) for c in hit] == [("First", ["web-1"])] and campaigns.conflicts(conn, 1, first)[0]["name"] == "Second"
    later = _plan(conn, [OPENSSL], name="Later", window_start="2027-01-01", window_end="2027-01-03")
    assert campaigns.conflicts(conn, 1, later) == []                                   # no overlap in time
    campaigns.update_details(conn, 1, first, "user:ana", window_start="", window_end="")
    assert campaigns.conflicts(conn, 1, second) == [] and campaigns.conflicts(conn, 1, first) == []   # no window, nothing to compare
    campaigns.update_details(conn, 1, first, "user:ana", window_start="2026-12-01", window_end="2026-12-05")
    campaigns.set_status(conn, 1, first, "user:ana", "cancelled", "not needed")
    assert campaigns.conflicts(conn, 1, second) == []                                  # cancelled campaigns do not conflict

    session_for(client, conn, "viewer")
    other = _plan(conn, [OPENSSL], name="Third", window_start="2026-12-06", window_end="2026-12-07")
    page = client.get(f"/ui/campaigns/{second}").text
    assert "Schedule conflicts" in page and "Third" in page and "web-1" in page and "Nothing is blocked" in page
    assert "Schedule conflicts" not in client.get(f"/ui/campaigns/{later}").text


def test_overview_shows_deferrals_ending_soon(env):
    from tests.test_work import _defer

    client, _, conn, _ = env
    _seed(conn)
    _defer(conn, OPENSSL, days=5)
    _defer(conn, CURL, days=20)
    work.invalidate_summary()
    assert work.summary(conn, 1)["deferrals_soon"] == 1                                 # only the one within 14 days
    session_for(client, conn, "viewer")
    page = client.get("/ui").text
    assert "Deferrals ending soon" in page and 'href="/ui/exceptions?view=soon"' in page
