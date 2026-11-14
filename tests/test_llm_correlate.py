import json

import httpx
import pytest
from fastapi.testclient import TestClient

from riskpatch import auth, llm
from riskpatch.api import create_app
from riskpatch.config import get_settings
from riskpatch.cvestore import upsert_record
from riskpatch.facts import VersionBound, VulnFact
from riskpatch.providers import CveRecord
from riskpatch.db import connect, migrate
from riskpatch.jobs import claim, run_job
from riskpatch.rules import CveVerdict
from tests.test_api import h, payload
from tests.helpers import session_for

KEY = "kilo-secret-key-0123456789"


@pytest.fixture(autouse=True)
def llm_env(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://ai-gateway.kilo.ai/api/v1")
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_MODEL", "kilo-auto/free")
    for name in ("LLM_CHAT_PATH", "LLM_TIMEOUT_SECONDS", "LLM_AUTH_HEADER", "LLM_AUTH_SCHEME", "LLM_KILO_MODE"):
        monkeypatch.delenv(name, raising=False)


def chat_body(content):
    return {"choices": [{"message": {"content": content if isinstance(content, str) else json.dumps(content)}}]}


def client_for(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def verdict(i, level="tinggi", kev=False):
    return CveVerdict(cve_id=f"CVE-2024-{1000 + i}", summary="s", cvss_score=7.5, cvss_severity="HIGH", attack_vector="NETWORK", cwe=[], kev=kev,
                      references=[], patched_versions=[], source="t", level=level, action="segera", exposure="internet", exposure_assumed=False,
                      reachability="r", one_line="satu")


def test_attach_single_request_and_levels_untouched():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=chat_body({"narratives": {"0": "narasi nol", "1": "narasi satu", "2": "x"}}))

    vs = [verdict(i) for i in range(3)]
    with client_for(handler) as c:
        assert llm.attach(vs, c) is None
    assert len(seen) == 1
    req = seen[0]
    assert str(req.url) == "https://ai-gateway.kilo.ai/api/v1/chat/completions"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    assert json.loads(req.content)["model"] == "kilo-auto/free"
    assert [v.narrative for v in vs] == ["narasi nol", "narasi satu", "x"]
    assert all(v.level == "tinggi" and v.action == "segera" and v.narrative_source == "llm" for v in vs)


def test_config_path_and_auth_header(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "https://gw.example/v1/")
    monkeypatch.setenv("LLM_CHAT_PATH", "custom/chat")
    monkeypatch.setenv("LLM_AUTH_HEADER", "x-api-key")
    monkeypatch.setenv("LLM_AUTH_SCHEME", "")
    cfg = llm.load_config()
    assert cfg.url == "https://gw.example/v1/custom/chat"
    assert cfg.headers()["x-api-key"] == KEY
    monkeypatch.setenv("LLM_BASE_URL", "https://gw.example/v1/chat/completions")
    monkeypatch.delenv("LLM_CHAT_PATH")
    assert llm.load_config().url == "https://gw.example/v1/chat/completions"


def test_unconfigured(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY")
    assert not llm.configured()
    vs = [verdict(0)]
    with client_for(lambda r: pytest.fail("no request expected")) as c:
        assert llm.attach(vs, c) is None
    assert vs[0].narrative_source == "none"


def test_401_diagnostic_does_not_leak_key():
    def handler(request):
        return httpx.Response(401, json={"error": f"invalid key {KEY}"})

    with client_for(handler) as c, pytest.raises(llm.LLMError) as exc:
        llm.chat([{"role": "user", "content": "hi"}], c)
    assert exc.value.code == "unauthorized" and exc.value.status == 401
    assert KEY not in str(exc.value) and KEY not in json.dumps(exc.value.as_dict())
    assert "LLM_API_KEY" in exc.value.hint

    vs = [verdict(0)]
    with client_for(handler) as c:
        assert llm.attach(vs, c) == "unauthorized"
    assert vs[0].narrative == "" and vs[0].narrative_source == "none"


def test_retry_on_429_then_success_and_timeout():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(429) if len(calls) == 1 else httpx.Response(200, json=chat_body("ok"))

    with client_for(handler) as c:
        assert llm.chat([], c, sleep=lambda s: None) == "ok"
    assert len(calls) == 2

    def slow(request):
        raise httpx.ReadTimeout("t", request=request)

    with client_for(slow) as c, pytest.raises(llm.LLMError) as exc:
        llm.chat([], c, sleep=lambda s: None)
    assert exc.value.code == "timeout"


def test_bad_responses_and_base_url():
    with client_for(lambda r: httpx.Response(200, text="<html>")) as c, pytest.raises(llm.LLMError) as exc:
        llm.chat([], c)
    assert exc.value.code == "bad_response"
    with client_for(lambda r: httpx.Response(302, headers={"location": "http://evil"})) as c, pytest.raises(llm.LLMError) as exc:
        llm.chat([], c)
    assert exc.value.code == "redirect"
    with client_for(lambda r: httpx.Response(200, json=chat_body("not json"))) as c:
        vs = [verdict(0)]
        assert llm.attach(vs, c) == "bad_output"
    cfg = llm.load_config()
    bad = llm.LLMConfig(**{**cfg.__dict__, "base_url": "ftp://x"})
    with pytest.raises(llm.LLMError) as exc:
        llm.validate(bad)
    assert exc.value.code == "bad_base_url"


# ---- correlation endpoint ----

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("RISKPATCH_DB", str(tmp_path / "t.sqlite3"))
    monkeypatch.setenv("RISKPATCH_REPORTS", str(tmp_path / "r"))
    monkeypatch.setenv("RISKPATCH_CACHE", str(tmp_path / "c"))
    monkeypatch.setenv("RISKPATCH_OFFLINE", "1")
    settings = get_settings()
    conn = connect(settings.db_path)
    migrate(conn)
    tokens = {s: auth.create_token(conn, f"t-{s}", [s]) for s in ("read", "ingest", "operate")}
    with TestClient(create_app(settings)) as client:
        client.post("/api/v1/ingest/snapshots", json=payload(), headers=h(tokens["ingest"]))
        keys = [r[0] for r in conn.execute("SELECT DISTINCT match_key FROM components")]
        fact = VulnFact(cve_id="CVE-2024-4577", summary="test cve", cvss_score=9.8, cvss_severity="CRITICAL", attack_vector="NETWORK", kev=True, source="nvd")
        upsert_record(conn, CveRecord(fact=fact, source="nvd", url="u", affected={k: [VersionBound(end_excluding="99.0")] for k in keys}), keep_raw=False)
        client.post("/api/v1/jobs/analysis/run", headers=h(tokens["operate"]))
        while (j := claim(conn, settings)) is not None:
            run_job(conn, settings, j)
        yield client, tokens, conn


def mock_post(monkeypatch, handler):
    """Swap the httpx module seen by the app/UI for one whose Client uses a MockTransport (TestClient keeps the real one)."""
    import types

    from riskpatch import ui
    from riskpatch.api import app as api_app

    sent = []

    def transport(request):
        sent.append(request)
        return handler(str(request.url), {"json": json.loads(request.content)})

    fake = types.SimpleNamespace(Client=lambda **kw: httpx.Client(transport=httpx.MockTransport(transport)))
    monkeypatch.setattr(api_app, "httpx", fake)
    monkeypatch.setattr(ui, "httpx", fake)
    return sent


def snapshot_findings(conn):
    return [tuple(r) for r in conn.execute("SELECT id, level, action, status, confidence, kev FROM findings ORDER BY id")]


def test_correlate_endpoint(env, monkeypatch):
    client, t, conn = env
    before = snapshot_findings(conn)
    assert before, "fixture analysis must produce findings"
    ref = f"F{before[0][0]}"

    def handler(url, kw):
        assert KEY not in json.dumps(kw["json"])
        return httpx.Response(200, json=chat_body({
            "narrative": "Semua temuan ada di web-01. Level seharusnya rendah.",
            "correlations": [{"title": "ok", "claim": "ada di web-01", "evidence": [ref, "F99999"]},
                             {"title": "tanpa evidence", "claim": "klaim liar", "evidence": ["F99999"]}],
            "uncertainty": ["exposure asumsi"],
            "level": "rendah", "findings": [{"id": 1, "level": "rendah"}],
        }))

    sent = mock_post(monkeypatch, handler)
    assert client.post("/api/v1/correlations/ai", headers=h(t["read"])).status_code == 403
    assert client.post("/api/v1/correlations/ai").status_code == 401
    r = client.post("/api/v1/correlations/ai", json={"asset_id": "web-01"}, headers=h(t["operate"]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(sent) == 1  # one summarized request, not one per finding
    assert body["ai"]["status"] == "ok" and body["ai"]["model"] == "kilo-auto/free"
    assert [c["evidence"] for c in body["ai"]["correlations"]] == [[ref]]
    assert body["ai"]["dropped_claims"] == 1
    assert "exposure asumsi" in body["ai"]["uncertainty"]
    # deterministic verdicts come from the DB, not the model
    levels = {f"F{i}": (lv, ac, st) for i, lv, ac, st, *_ in before}
    for v in body["deterministic"]["verdicts"]:
        assert (v["level"], v["action"], v["status"]) == levels[v["ref"]]
    assert snapshot_findings(conn) == before
    assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE action='correlation.ai'").fetchone()[0] == 1
    assert client.post("/api/v1/correlations/ai", json={"asset_id": "nope"}, headers=h(t["operate"])).status_code == 404


def test_correlate_401_and_unconfigured(env, monkeypatch):
    client, t, conn = env
    before = snapshot_findings(conn)
    mock_post(monkeypatch, lambda url, kw: httpx.Response(401, json={"error": KEY}))
    r = client.post("/api/v1/correlations/ai", headers=h(t["operate"]))
    assert r.status_code == 200
    ai = r.json()["ai"]
    assert ai["status"] == "error" and ai["error"]["code"] == "unauthorized" and ai["narrative"] == ""
    assert KEY not in r.text
    assert r.json()["deterministic"]["verdicts"]
    monkeypatch.delenv("LLM_API_KEY")
    r = client.post("/api/v1/correlations/ai", headers=h(t["operate"]))
    assert r.json()["ai"]["status"] == "unconfigured" and KEY not in r.text
    assert snapshot_findings(conn) == before


def test_ui_correlate_requires_csrf(env, monkeypatch):
    client, t, conn = env
    mock_post(monkeypatch, lambda url, kw: httpx.Response(200, json=chat_body({"narrative": "n", "correlations": [], "uncertainty": []}),
                                                          ))
    session_for(client, conn, "operator")
    assert client.post("/ui/actions/correlate", data={"csrf": "bad"}).status_code == 403
    r = client.post("/ui/actions/correlate", data={"csrf": auth.csrf_for(client.cookies.get("rp_session"))})
    assert r.status_code == 200 and "Deterministic verdict" in r.text


def test_defaults_and_mode_header(monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL")
    monkeypatch.delenv("LLM_MODEL")
    cfg = llm.load_config()
    assert cfg.url == "https://ai-gateway.kilo.ai/api/v1/chat/completions" and cfg.model == "kilo-auto/free"
    assert "x-kilocode-mode" not in cfg.headers()
    monkeypatch.setenv("LLM_KILO_MODE", "ask")
    assert llm.load_config().headers()["x-kilocode-mode"] == "ask"


def test_diagnose_models_without_key_and_chat_probe(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "kilo-auto/free"}]})
        return httpx.Response(401, json={"error": KEY})

    monkeypatch.delenv("LLM_API_KEY")
    with client_for(handler) as c:
        out = llm.diagnose(c)
    assert out["models"] == {"ok": True, "count": 1, "model_listed": True, "error": None} and out["key_configured"] is False
    assert "authorization" not in seen[0].headers
    monkeypatch.setenv("LLM_API_KEY", KEY)
    with client_for(handler) as c:
        out = llm.diagnose(c, chat_probe=True)
    assert out["chat"] == {"ok": False, "error": "unauthorized: HTTP 401"} and KEY not in json.dumps(out)
