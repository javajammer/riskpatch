import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest

from riskpatch import work
from tests.helpers import session_for, register
from tests.test_api import _add_findings, env  # noqa: F401  (env fixture)


def _seed(conn):
    # openssl 3.0.13 -> fix 3.0.16 on three servers (one critical, KEV), curl without a known fix on one server
    for name in ("web-1", "web-2", "db-1"):
        _add_findings(conn, name, {"critical": 1}, cve_id="CVE-2026-9001", component="openssl")
    _add_findings(conn, "web-1", {"low": 1}, cve_id="CVE-2026-9002", component="curl")
    conn.execute("UPDATE findings SET component_version='3.0.13', fixed_version='3.0.16', kev=1 WHERE cve_id='CVE-2026-9001'")
    conn.execute("UPDATE findings SET component_version='8.0', fixed_version='' WHERE cve_id='CVE-2026-9002'")
    conn.execute("UPDATE assets SET owner='Web team', business_tier='tier1' WHERE asset_id='web-1'")
    conn.commit()


OPENSSL = work.Key("CVE-2026-9001", "python", "openssl", "3.0.13", "3.0.16")
CURL = work.Key("CVE-2026-9002", "python", "curl", "8.0", "")


def test_queue_groups_findings_into_work_items_worst_first(env):
    _, _, conn, _ = env
    _seed(conn)
    rows, total = work.queue(conn, 1)
    assert total == 2 and [r["cve_id"] for r in rows] == ["CVE-2026-9001", "CVE-2026-9002"]
    assert rows[0]["servers"] == 3 and rows[0]["fixed"] == "3.0.16" and rows[0]["kev"] == 3 and rows[0]["state"] == "new" and rows[0]["assignee"] == ""
    assert [r["cve_id"] for r in work.queue(conn, 1, "kev")[0]] == ["CVE-2026-9001"]
    assert [r["cve_id"] for r in work.queue(conn, 1, "no_fix")[0]] == ["CVE-2026-9002"]
    assert work.queue(conn, 1, "needs_validation")[1] == 0 and work.queue(conn, 1, "mine", me="nobody")[1] == 0
    assert Key_roundtrip(OPENSSL)


def Key_roundtrip(k):
    return work.Key.decode(k.encode()) == k and work.Key.decode(work.Key("CVE-1", "pypi", "a|b%c", "1", "").encode()).component_name == "a|b%c"


def test_triage_records_state_history_snapshots_and_audit(env):
    _, _, conn, _ = env
    _seed(conn)
    conn.execute("UPDATE assets SET latest_snapshot_id=7 WHERE asset_id='web-1'")
    conn.commit()
    res = work.triage(conn, 1, OPENSSL, "user:ana", "needs_validation", "potential", "  Platform   team ", "check the build")
    assert res == {"work_id": 1, "servers": 3, "from": "new", "to": "needs_validation"}
    work.triage(conn, 1, OPENSSL, "user:ben", "accepted", "confirmed", "Platform team")
    row = work.item(conn, 1, OPENSSL)
    assert row["state"] == "accepted" and row["assignee"] == "Platform team" and row["updated_by"] == "user:ben" and row["created_by"] == "user:ana"
    events = work.history(conn, row["id"])
    assert [(e["from_state"], e["to_state"], e["actor"]) for e in events] == [("needs_validation", "accepted", "user:ben"), ("new", "needs_validation", "user:ana")]
    assert events[1]["server_count"] == 3 and events[1]["snapshot_ids"] == "[7]" and events[1]["note"] == "check the build"
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='work.triage'").fetchone()[0] == 2
    rows, _ = work.queue(conn, 1)
    assert (rows[0]["state"], rows[0]["assignee"], rows[0]["applicability"]) == ("accepted", "Platform team", "confirmed")
    assert work.queue(conn, 1, "mine", me="Platform team")[1] == 1


def test_triage_rules_are_enforced(env):
    _, _, conn, _ = env
    _seed(conn)
    for state in ("deferred", "not_applicable", "mitigated"):
        with pytest.raises(ValueError, match="reason"):
            work.triage(conn, 1, OPENSSL, "u", state)
    with pytest.raises(ValueError, match="fresh snapshot"):
        work.triage(conn, 1, OPENSSL, "u", "verified", note="trust me")
    for bad in (dict(state="nope"), dict(state="accepted", applicability="maybe"), dict(state="accepted", assignee="x" * 121)):
        with pytest.raises(ValueError):
            work.triage(conn, 1, OPENSSL, "u", **bad)
    with pytest.raises(LookupError):
        work.triage(conn, 1, work.Key("CVE-0", "pypi", "x", "1", ""), "u", "accepted")
    assert work.triage(conn, 1, CURL, "u", "not_applicable", "confirmed", note="built without the feature")["to"] == "not_applicable"
    assert work.item(conn, 1, CURL)["applicability"] == "not_applicable"      # forced to match the state
    assert conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0] == 1  # rejected attempts created nothing


def test_bulk_triage_updates_each_item_and_skips_gone_groups(env):
    _, _, conn, _ = env
    _seed(conn)
    gone = work.Key("CVE-0", "pypi", "x", "1", "")
    res = work.triage_bulk(conn, 1, [OPENSSL, CURL, gone, OPENSSL], "user:ana", "needs_validation", assignee="SOC")
    assert res == {"updated": 2, "skipped": 1, "servers": 4}
    assert conn.execute("SELECT COUNT(*) FROM work_events").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='work.triage.bulk'").fetchone()[0] == 1
    with pytest.raises(ValueError):
        work.triage_bulk(conn, 1, [], "u", "accepted")
    with pytest.raises(ValueError):
        work.triage_bulk(conn, 1, [OPENSSL], "u", "deferred")                    # reason missing: nothing changes
    assert work.item(conn, 1, OPENSSL)["state"] == "needs_validation"


def test_work_pages_permissions_and_flow(env):
    client, _, conn, _ = env
    register(conn, "SOC", "Platform", "Platform team", "Ops", "Web team", "A", "B", "x")
    _seed(conn)
    assert client.get("/ui/work", follow_redirects=False).status_code == 303          # guests are sent to login

    session_for(client, conn, "viewer")
    page = client.get("/ui/work").text
    assert "2 work items" in page and "CVE-2026-9001" in page and "No fix known" in page and "Decide for the selected items" not in page
    assert page.index("CVE-2026-9001") < page.index("CVE-2026-9002")
    assert "CVE-2026-9002" not in client.get("/ui/work?view=kev").text and "CVE-2026-9002" in client.get("/ui/work?view=no_fix").text
    link = re.search(r'href="(/ui/work/item\?k=[^"]+)"', page).group(1)
    detail = client.get(link).text
    assert "Affected servers" in detail and "web-1" in detail and "db-1" in detail and "Web team" in detail and "No decision recorded yet" in detail
    assert "Save decision" not in detail                                           # read-only
    assert client.get("/ui/work/item?k=garbage").status_code == 404

    client.cookies.clear()
    session_for(client, conn, "operator")
    detail = client.get(link).text
    csrf = re.search(r'name="csrf" value="([^"]+)"', detail).group(1)
    k = quote(OPENSSL.encode())
    form = {"k": k, "state": "needs_validation", "applicability": "potential", "assignee": "SOC", "note": "", "csrf": csrf}
    assert client.post("/ui/actions/work/triage", data={**form, "csrf": "bad"}, follow_redirects=False).status_code == 403
    bad = client.post("/ui/actions/work/triage", data={**form, "state": "deferred"}, follow_redirects=False)
    assert bad.status_code == 303 and "error=" in bad.headers["location"]
    ok = client.post("/ui/actions/work/triage", data=form, follow_redirects=False)
    assert ok.status_code == 303 and "notice=" in ok.headers["location"]
    after = client.get(ok.headers["location"]).text
    assert "Decision saved for 3 server(s)" in after and "Needs validation" in after and "SOC" in after and "History" in after
    assert "My work" in client.get("/ui/work").text
    assert "CVE-2026-9001" in client.get("/ui/work?view=needs_validation").text

    listing = client.get("/ui/work").text
    assert "Decide for the selected items" in listing
    csrf2 = re.search(r'name="csrf" value="([^"]+)"', listing).group(1)
    bulk = client.post("/ui/actions/work/bulk", data={"csrf": csrf2, "k": [quote(OPENSSL.encode()), quote(CURL.encode())], "state": "accepted", "assignee": "Platform"}, follow_redirects=False)
    assert "notice=Updated%202%20work%20item" in bulk.headers["location"]
    assert client.post("/ui/actions/work/bulk", data={"csrf": csrf2, "state": "accepted"}, follow_redirects=False).headers["location"].startswith("/ui/work?error=")
    assert client.post("/ui/actions/work/bulk", data={"csrf": "bad", "k": [quote(CURL.encode())], "state": "accepted"}, follow_redirects=False).status_code == 403


def _age(conn, days):
    old = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds").replace("+00:00", "Z")
    conn.execute("UPDATE findings SET first_seen=?", (old,))
    conn.commit()


def test_risk_score_is_a_sum_of_visible_reasons_with_a_band():
    from riskpatch import risk

    top = risk.score("critical", True, True, "tier1", True, 100, False)
    assert top.points == 40 + 25 + 10 + 10 + 5 + 5 == 95 and top.band == "P1"
    assert [label for label, _ in top.reasons] == ["Critical severity", "Known exploited (KEV)", "Internet-facing server", "Tier 1 server", "Fix is known", "open 90+ days"]
    assert top.explain().endswith("= 95") and "Known exploited (KEV) +25" in top.explain()
    assert risk.score("high", False, False, "", False, 5, False).points == 30 and risk.score("high", False, False, "", False, 5, False).band == "P4"
    assert risk.score("high", False, True, "tier2", True, 40, False).points == 30 + 10 + 5 + 5 + 3 == 53 and risk.score("high", False, True, "tier2", True, 40, False).band == "P3"
    low = risk.score("unverified", False, False, "", False, 0, True)
    assert low.points == 0 and low.band == "P4"                                  # penalty cannot go below zero
    assert risk.score("critical", True, True, "tier1", True, 365, False).points <= 100
    assert risk.score("critical", False, False, "", False, 0, False).band == "P3"  # severity alone is not top priority


def test_sla_targets_validate_persist_and_are_audited(env):
    from riskpatch import sla

    _, _, conn, _ = env
    assert sla.load(conn) == {"P1": (4, 7), "P2": (24, 30), "P3": (72, 90), "P4": (168, 180)}
    changed = sla.save(conn, 1, "user:admin", {"P1": (2, 3)})
    assert changed == {"P1": {"from": (4, 7), "to": (2, 3)}} and sla.load(conn)["P1"] == (2, 3)
    assert sla.save(conn, 1, "user:admin", {"P1": (2, 3)}) == {}
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='sla.update'").fetchone()[0] == 1
    for bad in ({"P1": (0, 3)}, {"P2": (24, 100000)}, {"P1": (1, 31)}, {"P4": (1, 1)}, {"P3": (5000, 90)}):
        with pytest.raises(ValueError):
            sla.save(conn, 1, "u", bad)
    assert sla.load(conn)["P1"] == (2, 3)                                         # rejected input changed nothing
    first = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ev = lambda state, ack, now: sla.evaluate("P1", state, first, ack, {"P1": (4, 7)}, now)  # noqa: E731
    assert ev("new", None, first + timedelta(hours=3))["ack_overdue"] is False and ev("new", None, first + timedelta(hours=5))["ack_overdue"] is True
    assert ev("new", first + timedelta(hours=1), first + timedelta(days=2))["ack_overdue"] is False
    assert ev("accepted", None, first + timedelta(days=8))["fix_overdue"] is True and ev("accepted", None, first + timedelta(days=6))["fix_overdue"] is False
    assert ev("deferred", None, first + timedelta(days=30)) ["fix_overdue"] is False and ev("deferred", None, first + timedelta(days=30))["paused"] is True


def test_queue_scores_sets_due_dates_and_flags_overdue_work(env):
    _, _, conn, _ = env
    _seed(conn)
    _age(conn, 40)
    rows, _ = work.queue(conn, 1)
    top = rows[0]
    assert top["band"] == "P1" and top["score"] >= 80 and "Known exploited (KEV) +25" in top["why"] and "Tier 1 server +10" in top["why"]
    assert top["fix_overdue"] is True and top["ack_overdue"] is True and top["paused"] is False
    assert [r["cve_id"] for r in work.queue(conn, 1, "past_sla")[0]][0] == "CVE-2026-9001"
    work.invalidate_summary()
    assert work.summary(conn, 1)["past_sla"] >= 1

    # a decision acknowledges it; reassignment does not restart the clock; mitigated stops it counting as overdue
    work.triage(conn, 1, OPENSSL, "u", "accepted", assignee="A")
    before = work.queue(conn, 1)[0][0]["fix_due"]
    work.triage(conn, 1, OPENSSL, "u", "accepted", assignee="B")
    after = next(r for r in work.queue(conn, 1)[0] if r["cve_id"] == "CVE-2026-9001")
    assert after["fix_due"] == before and after["ack_overdue"] is False and after["fix_overdue"] is True
    work.triage(conn, 1, OPENSSL, "u", "mitigated", note="patched by ops")
    rows, _ = work.queue(conn, 1)
    assert rows[-1]["cve_id"] == "CVE-2026-9001" and rows[-1]["paused"] is True and rows[-1]["fix_overdue"] is False  # decided items sink to the bottom


def test_work_page_settings_and_overview_show_priority_and_sla(env):
    client, _, conn, _ = env
    _seed(conn)
    _age(conn, 40)
    session_for(client, conn, "viewer")
    page = client.get("/ui/work").text
    assert "Priority</th>" in page and "Fix due</th>" in page and "P1 ·" in page and "Overdue" in page and "Past SLA" in page
    assert "Known exploited (KEV) +25" in page                                     # the reasons are in the tooltip
    assert "CVE-2026-9001" in client.get("/ui/work?view=past_sla").text
    item = client.get(re.search(r'href="(/ui/work/item\?k=[^"]+)"', page).group(1)).text
    assert "Why this priority" in item and "Acknowledge by" in item and "do not restart" in item

    work.invalidate_summary()
    overview = client.get("/ui").text
    assert "Work past its SLA" in overview and "without an owner" in overview and "Work awaiting a decision" in overview

    settings = client.get("/ui/settings").text
    assert "Priority and SLA" in settings and "Known exploited +25" in settings and "4 hours" in settings and 'name="p1_ack"' not in settings   # read-only for non-admins

    client.cookies.clear()
    session_for(client, conn, "admin")
    settings = client.get("/ui/settings").text
    csrf = re.search(r'action="/ui/actions/settings/sla".*?name="csrf" value="([^"]+)"', settings, re.S).group(1)
    data = dict(p1_ack="2", p1_fix="5", p2_ack="24", p2_fix="30", p3_ack="72", p3_fix="90", p4_ack="168", p4_fix="180")
    assert client.post("/ui/actions/settings/sla", data={**data, "csrf": "bad"}, follow_redirects=False).status_code == 403
    assert "error=" in client.post("/ui/actions/settings/sla", data={**data, "csrf": csrf, "p1_fix": "40"}, follow_redirects=False).headers["location"]
    assert "error=" in client.post("/ui/actions/settings/sla", data={**data, "csrf": csrf, "p1_ack": "abc"}, follow_redirects=False).headers["location"]
    ok = client.post("/ui/actions/settings/sla", data={**data, "csrf": csrf}, follow_redirects=False)
    assert "notice=SLA" in ok.headers["location"] and 'value="2"' in client.get("/ui/settings").text

    client.cookies.clear()
    session_for(client, conn, "operator")
    assert client.post("/ui/actions/settings/sla", data={**data, "csrf": csrf}, follow_redirects=False).status_code == 403   # admin only


def test_groups_cache_is_invalidated_by_decisions_and_new_findings_but_not_by_reads(env):
    _, _, conn, _ = env
    _seed(conn)
    first = work.groups(conn, 1)
    assert work.groups(conn, 1) is first                                   # a repeat read is served from the cache
    work.triage(conn, 1, OPENSSL, "u", "needs_validation")                 # a decision changes the stamp, so another process would also recompute
    second = work.groups(conn, 1)
    assert second is not first and next(g for g in second if g["cve_id"] == "CVE-2026-9001")["state"] == "needs_validation"
    _add_findings(conn, "web-9", {"low": 1}, cve_id="CVE-2026-9777", component="zlib")
    conn.commit()
    assert any(g["cve_id"] == "CVE-2026-9777" for g in work.groups(conn, 1))  # new findings show up without waiting for the TTL
    one = work.groups(conn, 1, key=OPENSSL)
    assert len(one) == 1 and one[0]["servers"] == 3 and one[0]["state"] == "needs_validation"
    assert work.groups(conn, 1, key=work.Key("CVE-0", "pypi", "x", "1", "")) == []


def _alert_for(conn, cve_id, status="open"):
    fid = conn.execute("SELECT id FROM findings WHERE cve_id=? LIMIT 1", (cve_id,)).fetchone()[0]
    asset = conn.execute("SELECT asset_id FROM findings WHERE id=?", (fid,)).fetchone()[0]
    conn.execute("INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at, finding_id, status) VALUES (1, ?, 'verdict', ?, ?, ?, ?)",
                 (asset, f"{cve_id} alert", datetime.now(timezone.utc).isoformat(), fid, status))
    conn.commit()
    return fid


def test_alerts_link_to_their_work_item_and_back(env):
    client, _, conn, _ = env
    _seed(conn)
    f_openssl, f_curl = _alert_for(conn, "CVE-2026-9001"), _alert_for(conn, "CVE-2026-9002")
    conn.execute("INSERT INTO alerts (workspace_id, asset_id, kind, message, created_at) VALUES (1, 'web-1', 'stale', 'old style alert', ?)", (datetime.now(timezone.utc).isoformat(),))
    conn.commit()
    links = work.for_findings(conn, 1, [f_openssl, f_curl, 0])
    assert links[f_openssl] == (OPENSSL, "new") and links[f_curl] == (CURL, "new") and 0 not in links

    session_for(client, conn, "viewer")
    page = client.get("/ui/alerts?view=all").text
    assert "Work item</th>" in page
    row = re.search(r"CVE-2026-9001 alert.*?</tr>", page, re.S).group(0)
    assert f'href="/ui/work/item?k={quote(OPENSSL.encode())}"' in row and "New" in row
    assert "old style alert" in page and re.search(r"old style alert.*?<span class=\"muted\">-</span>", page, re.S)   # alerts without a finding have nothing to open

    work.triage(conn, 1, OPENSSL, "user:ana", "needs_validation")
    assert "Needs validation" in re.search(r"CVE-2026-9001 alert.*?</tr>", client.get("/ui/alerts?view=all").text, re.S).group(0)

    only = client.get("/ui/alerts?view=all&cve=CVE-2026-9001").text
    assert "CVE-2026-9001 alert" in only and "CVE-2026-9002 alert" not in only and "Clear filter" in only
    assert 'name="cve" value="CVE-2026-9001"' in only                         # filtering by asset keeps the CVE filter

    item = client.get(f"/ui/work/item?k={quote(OPENSSL.encode())}").text
    assert "Alerts for this item: 1 open · 0 in assessment · 0 closed" in item and "cve=CVE-2026-9001" in item and "does not change this item" in item
    assert work.alert_counts(conn, 1, CURL) == {"open": 1} and work.alert_counts(conn, 1, work.Key("CVE-0", "x", "y", "1", "")) == {}

    # a resolved finding with no decision has no work item to open; a triaged one still does
    conn.execute("UPDATE findings SET status='resolved' WHERE id=?", (f_curl,))
    conn.commit()
    work.invalidate_summary()
    assert work.for_findings(conn, 1, [f_curl])[f_curl] is None
    work.triage(conn, 1, OPENSSL, "u", "needs_validation")
    conn.execute("UPDATE findings SET status='resolved' WHERE cve_id='CVE-2026-9001'")
    conn.commit()
    assert work.for_findings(conn, 1, [f_openssl])[f_openssl] == (OPENSSL, "needs_validation")


def _snapshot(conn, asset_id, collected_at, status="analyzed"):
    pk = conn.execute("SELECT id FROM assets WHERE asset_id=?", (asset_id,)).fetchone()[0]
    sid = conn.execute(
        "INSERT INTO snapshots (workspace_id, asset_pk, asset_id, collected_at, received_at, schema_version, payload_hash, idempotency_key, analysis_status, updated_at) "
        "VALUES (1, ?, ?, ?, ?, '1.0', ?, ?, ?, ?)", (pk, asset_id, collected_at, collected_at, f"h-{asset_id}-{collected_at}", f"k-{asset_id}-{collected_at}", status, collected_at)).lastrowid
    conn.execute("UPDATE assets SET latest_snapshot_id=? WHERE id=?", (sid, pk))
    conn.commit()
    return sid


def _fix(conn, asset_id):
    """What analysis does after the fix: the finding disappears from the new snapshot's results."""
    conn.execute("UPDATE findings SET status='resolved' WHERE asset_id=? AND cve_id='CVE-2026-9001'", (asset_id,))
    conn.commit()


def test_mitigated_becomes_verified_only_from_fresh_analyzed_snapshots(env):
    from riskpatch.jobs import now_iso  # noqa: F401  (same clock the service uses)

    _, _, conn, _ = env
    _seed(conn)
    before = "2020-01-01T00:00:00Z"
    for a in ("web-1", "web-2", "db-1"):
        _snapshot(conn, a, before)
    work.triage(conn, 1, OPENSSL, "user:ana", "mitigated", note="upgraded openssl via ansible")
    ev = work.latest_mitigation(conn, work.item(conn, 1, OPENSSL)["id"])
    assert sorted(__import__("json").loads(ev["servers"])) == ["db-1", "web-1", "web-2"]
    after = "2999-01-01T00:00:00Z"                                   # any snapshot collected after the mitigation was recorded

    assert work.verify_mitigated(conn, 1) == 0                       # nobody re-reported: silence is not proof
    status = work.verification(conn, 1, OPENSSL, ev["at"], ["web-1", "web-2", "db-1", "gone"])
    assert status["waiting"] == 3 and status["clear"] == 0 and status["verified"] is False
    assert [r["status"] for r in status["servers"]].count("removed") == 1

    _fix(conn, "web-1"); _snapshot(conn, "web-1", after)
    _snapshot(conn, "web-2", after, status="pending")                # new snapshot but not analyzed yet
    _snapshot(conn, "db-1", after)                                    # new, analyzed, but the finding is still open -> the fix did not work
    res = work.verification(conn, 1, OPENSSL, ev["at"], ["web-1", "web-2", "db-1"])
    assert {r["asset_id"]: r["status"] for r in res["servers"]} == {"web-1": "clear", "web-2": "waiting", "db-1": "affected"}
    assert res["clear"] == 1 and res["affected"] == 1 and work.verify_mitigated(conn, 1) == 0
    assert work.item(conn, 1, OPENSSL)["state"] == "mitigated"

    _fix(conn, "db-1"); _fix(conn, "web-2")
    conn.execute("UPDATE snapshots SET analysis_status='analyzed' WHERE asset_id='web-2'")
    conn.commit()
    assert work.verify_mitigated(conn, 1) == 1
    row = work.item(conn, 1, OPENSSL)
    assert row["state"] == "verified" and row["updated_by"] == "system:verification"
    last = work.history(conn, row["id"])[0]
    assert (last["from_state"], last["to_state"], last["actor"], last["server_count"]) == ("mitigated", "verified", "system:verification", 3)
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='work.verified'").fetchone()[0] == 1
    assert work.verify_mitigated(conn, 1) == 0                       # already verified: nothing to redo
    with pytest.raises(ValueError, match="fresh snapshot"):
        work.triage(conn, 1, OPENSSL, "u", "verified")               # still cannot be set by hand


def test_old_mitigations_without_a_server_list_are_not_guessed(env):
    _, _, conn, _ = env
    _seed(conn)
    work.triage(conn, 1, OPENSSL, "u", "mitigated", note="done")
    conn.execute("UPDATE work_events SET servers='[]'")              # as recorded before servers were tracked
    conn.commit()
    assert work.verify_mitigated(conn, 1) == 0 and work.item(conn, 1, OPENSSL)["state"] == "mitigated"


def test_verification_panel_shows_evidence_per_server(env):
    client, _, conn, _ = env
    _seed(conn)
    for a in ("web-1", "web-2", "db-1"):
        _snapshot(conn, a, "2020-01-01T00:00:00Z")
    work.triage(conn, 1, OPENSSL, "user:ana", "mitigated", note="upgraded")
    _fix(conn, "web-1"); _snapshot(conn, "web-1", "2999-01-01T00:00:00Z")
    session_for(client, conn, "viewer")
    page = client.get(f"/ui/work/item?k={quote(OPENSSL.encode())}").text
    assert "<h2>Verification</h2>" in page and "1 of 3 covered server(s) confirmed clear" in page and "Confirmed clear" in page and "Waiting for a new snapshot" in page
    assert page.index("Waiting for a new snapshot") < page.index("Confirmed clear")       # problems and waiting first
    assert "Nothing is assumed from silence" in page
    assert "becomes Verified when fresh snapshots confirm" in client.get("/ui/work").text    # tooltip on the Mitigated pill in the queue
    assert "<h2>Verification</h2>" not in client.get(f"/ui/work/item?k={quote(CURL.encode())}").text
    for a in ("web-2", "db-1"):
        _fix(conn, a); _snapshot(conn, a, "2999-01-02T00:00:00Z")
    work.verify_mitigated(conn, 1)
    assert "Verified: all 3 covered server(s) were re-checked after the fix and are clear." in client.get(f"/ui/work/item?k={quote(OPENSSL.encode())}").text


def _defer(conn, key=None, days=30, note="waiting for the vendor patch", control="WAF rule blocks the exploit path", actor="user:ana"):
    until = (datetime.now(timezone.utc).date() + timedelta(days=days)).isoformat()
    work.triage(conn, 1, key or OPENSSL, actor, "deferred", note=note, expires_on=until, control=control)
    return until


def test_deferral_needs_a_valid_expiry_and_creates_an_exception(env):
    _, _, conn, _ = env
    _seed(conn)
    today = datetime.now(timezone.utc).date()
    for bad in ("", "tomorrow", today.isoformat(), (today - timedelta(days=1)).isoformat(), (today + timedelta(days=181)).isoformat()):
        with pytest.raises(ValueError, match="expiry|future|at most"):
            work.triage(conn, 1, OPENSSL, "u", "deferred", note="reason", expires_on=bad)
    with pytest.raises(ValueError, match="control"):
        work.triage(conn, 1, OPENSSL, "u", "deferred", note="reason", expires_on=(today + timedelta(days=5)).isoformat(), control="x" * 501)
    assert work.item(conn, 1, OPENSSL) is None and conn.execute("SELECT COUNT(*) FROM work_exceptions").fetchone()[0] == 0   # rejected attempts leave nothing behind

    until = _defer(conn)
    exc = work.exceptions(conn, 1)[0]
    assert (exc["expires_on"], exc["server_count"], exc["status"], exc["requested_by"]) == (until, 3, "active", "user:ana")
    assert exc["compensating_control"].startswith("WAF") and exc["days_left"] == 30 and exc["key"] == OPENSSL
    assert f"deferred until {until}" in work.history(conn, work.item(conn, 1, OPENSSL)["id"])[0]["note"]
    assert work.queue(conn, 1)[0][-1]["paused"] is True                                    # deferred items are paused, not hidden

    work.triage(conn, 1, OPENSSL, "user:ben", "accepted", assignee="Platform")              # changing the decision retires the exception
    assert work.exceptions(conn, 1) == [] and work.exceptions(conn, 1, "closed")[0]["status"] == "superseded"
    # the expiry date is ignored for other states
    work.triage(conn, 1, OPENSSL, "u", "scheduled", expires_on="not-a-date")
    assert work.item(conn, 1, OPENSSL)["state"] == "scheduled"


def test_expired_deferrals_reopen_the_item_without_resetting_the_sla(env):
    _, _, conn, _ = env
    _seed(conn)
    _age(conn, 40)                                                                           # first detected 40 days ago: P1 fix target is 7 days
    _defer(conn, days=2)
    _defer(conn, CURL, days=100)
    today = datetime.now(timezone.utc).date()
    assert work.expire_exceptions(conn, 1, today) == 0                                       # not yet
    assert work.exceptions(conn, 1, "soon")[0]["key"] == OPENSSL and len(work.exceptions(conn, 1, "soon")) == 1

    assert work.expire_exceptions(conn, 1, today + timedelta(days=3)) == 1
    row = work.item(conn, 1, OPENSSL)
    assert row["state"] == "needs_validation" and row["updated_by"] == "system:exceptions"
    last = work.history(conn, row["id"])[0]
    assert (last["from_state"], last["to_state"], last["actor"]) == ("deferred", "needs_validation", "system:exceptions") and "expired" in last["note"]
    assert work.exceptions(conn, 1, "closed")[0]["status"] == "expired" and work.item(conn, 1, CURL)["state"] == "deferred"
    back = next(g for g in work.groups(conn, 1, now=datetime.now(timezone.utc)) if g["cve_id"] == "CVE-2026-9001")
    assert back["paused"] is False and back["fix_overdue"] is True                           # overdue at once: the clock never stopped counting from detection
    assert work.expire_exceptions(conn, 1, today + timedelta(days=3)) == 0                   # idempotent
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='work.exception.expired'").fetchone()[0] == 1


def test_revoking_an_exception_requires_a_reason_and_reopens_the_item(env):
    _, _, conn, _ = env
    _seed(conn)
    _defer(conn)
    exc_id = work.exceptions(conn, 1)[0]["id"]
    for note in ("", "ok"):
        with pytest.raises(ValueError, match="reason"):
            work.revoke_exception(conn, 1, exc_id, "user:root", note)
    with pytest.raises(LookupError):
        work.revoke_exception(conn, 1, 999, "user:root", "no such")
    work.revoke_exception(conn, 1, exc_id, "user:root", "risk no longer acceptable")
    assert work.item(conn, 1, OPENSSL)["state"] == "needs_validation" and work.exceptions(conn, 1, "closed")[0]["status"] == "revoked"
    with pytest.raises(LookupError):
        work.revoke_exception(conn, 1, exc_id, "user:root", "again")                          # already closed


def test_exceptions_page_forms_and_permissions(env):
    client, _, conn, _ = env
    _seed(conn)
    assert client.get("/ui/exceptions", follow_redirects=False).status_code == 303
    _defer(conn, days=5)
    _defer(conn, CURL, days=120, control="")

    session_for(client, conn, "viewer")
    page = client.get("/ui/exceptions").text
    assert "2 exceptions" in page and "CVE-2026-9001" in page and "WAF rule blocks the exploit path" in page and "None recorded" in page
    assert "(5 days left)" in page and "Soon" in page and "Revoke" not in page
    assert "CVE-2026-9002" not in client.get("/ui/exceptions?view=soon").text and "CVE-2026-9001" in client.get("/ui/exceptions?view=soon").text
    assert "0 exceptions" in client.get("/ui/exceptions?view=closed").text
    item = client.get(f"/ui/work/item?k={quote(OPENSSL.encode())}").text
    assert "Deferred until" in item and "WAF rule blocks the exploit path" in item and "SLA is not reset" in item

    client.cookies.clear()
    session_for(client, conn, "operator")
    detail = client.get(f"/ui/work/item?k={quote(OPENSSL.encode())}").text
    assert 'name="expires_on" type="date"' in detail and "Compensating control" in detail
    csrf = re.search(r'name="csrf" value="([^"]+)"', detail).group(1)
    form = {"k": quote(OPENSSL.encode()), "state": "deferred", "note": "waiting", "csrf": csrf}
    missing = client.post("/ui/actions/work/triage", data=form, follow_redirects=False)
    assert "error=" in missing.headers["location"] and "expiry" in missing.headers["location"].lower()
    until = (datetime.now(timezone.utc).date() + timedelta(days=20)).isoformat()
    ok = client.post("/ui/actions/work/triage", data={**form, "expires_on": until, "control": "network isolation"}, follow_redirects=False)
    assert "notice=" in ok.headers["location"] and "network isolation" in client.get("/ui/exceptions").text
    bulk = client.post("/ui/actions/work/bulk", data={"csrf": csrf, "k": [quote(CURL.encode())], "state": "deferred", "note": "later", "expires_on": until}, follow_redirects=False)
    assert "notice=" in bulk.headers["location"]
    exc_id = work.exceptions(conn, 1)[0]["id"]
    assert client.post("/ui/actions/exceptions/revoke", data={"csrf": csrf, "exception_id": exc_id, "note": "no longer ok"}, follow_redirects=False).status_code == 403  # admin only

    client.cookies.clear()
    session_for(client, conn, "admin")
    page = client.get("/ui/exceptions").text
    admin_csrf = re.search(r'action="/ui/actions/exceptions/revoke".*?name="csrf" value="([^"]+)"', page, re.S).group(1)
    assert "Revoke</button>" in page
    short = client.post("/ui/actions/exceptions/revoke", data={"csrf": admin_csrf, "exception_id": exc_id, "note": "x"}, follow_redirects=False)
    assert "error=" in short.headers["location"]
    done = client.post("/ui/actions/exceptions/revoke", data={"csrf": admin_csrf, "exception_id": exc_id, "note": "risk no longer acceptable"}, follow_redirects=False)
    assert "notice=" in done.headers["location"] and "Revoked" in client.get("/ui/exceptions?view=closed").text
    assert "error=" in client.post("/ui/actions/exceptions/revoke", data={"csrf": admin_csrf, "exception_id": exc_id, "note": "again again"}, follow_redirects=False).headers["location"]
