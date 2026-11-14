from riskpatch.facts import VulnFact
from riskpatch.sources.shodan import enrich


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeClient:
    def get(self, url, params=None):
        if "cvedb" in url:
            return FakeResponse({"kev": True, "epss": 0.91, "cvss_v3": 9.8, "ransomware_campaign": "Known"})
        return FakeResponse({"total": 2})


def test_enrich_sets_kev_without_key(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    fact = VulnFact(cve_id="CVE-2024-0001", source="nvd", kev=False)
    assert enrich([fact], FakeClient())[0].kev is False


def test_enrich_uses_cvedb(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "test-key")
    fact = VulnFact(cve_id="CVE-2024-0001", source="nvd", kev=False, cvss_score=None)
    enriched = enrich([fact], FakeClient())[0]
    assert enriched.kev is True
    assert enriched.epss == 0.91
    assert enriched.cvss_score == 9.8
    assert "Shodan exploit index: 2" in enriched.match_note
