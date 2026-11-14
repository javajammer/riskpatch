from __future__ import annotations

import httpx

from riskpatch.facts import VulnFact
from riskpatch.textclip import clip_text
from riskpatch.providers import CveQuery, CveRecord

name = "circl"
URL = "https://cve.circl.lu/api"


def parse_cve(item: dict, url: str) -> CveRecord | None:
    meta = item.get("cveMetadata") or {}
    cve_id = meta.get("cveId") or item.get("id")
    if not cve_id:
        return None
    cna = (item.get("containers") or {}).get("cna") or {}
    summary = next((d.get("value", "") for d in cna.get("descriptions") or [] if d.get("lang", "en").startswith("en")), "")
    score = severity = vector = None
    for block in cna.get("metrics") or []:
        for key in ("cvssV3_1", "cvssV3_0"):
            data = block.get(key)
            if data:
                score, severity, vector = data.get("baseScore"), data.get("baseSeverity"), data.get("attackVector")
    if score is None and isinstance(item.get("cvss3"), (int, float)):
        score = float(item["cvss3"])
    fact = VulnFact(cve_id=cve_id, summary=clip_text(summary or item.get("summary") or ""), cvss_score=score, cvss_severity=severity, attack_vector=vector, source="circl")
    return CveRecord(fact=fact, source="circl", url=url, raw=item)


class CirclProvider:
    """No-key fallback. Used for enrichment (CVSS/summary); version ranges stay with NVD/OSV."""

    name = "circl"

    def __init__(self, client: httpx.Client):
        self.client = client

    def search(self, query: CveQuery) -> list[CveRecord]:
        return []

    def get(self, cve_id: str) -> CveRecord | None:
        response = self.client.get(f"{URL}/cve/{cve_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return parse_cve(response.json(), f"{URL}/cve/{cve_id}")
