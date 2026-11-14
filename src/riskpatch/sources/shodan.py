from __future__ import annotations

import os

import httpx

from riskpatch.facts import VulnFact

CVEDB = "https://cvedb.shodan.io/cve"
EXPLOITS = "https://exploits.shodan.io/api/search"


def enrich(facts: list[VulnFact], client: httpx.Client) -> list[VulnFact]:
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        return facts
    for fact in facts:
        if not fact.cve_id.startswith("CVE-"):
            continue
        _apply_cvedb(fact, client)
        _apply_exploit_count(fact, client, key)
    return facts


def _apply_cvedb(fact: VulnFact, client: httpx.Client) -> None:
    try:
        response = client.get(f"{CVEDB}/{fact.cve_id}")
        response.raise_for_status()
        data = response.json()
    except Exception:
        return
    if not isinstance(data, dict):
        return
    score = data.get("cvss_v3") or data.get("cvss")
    if fact.cvss_score is None and isinstance(score, (int, float)):
        fact.cvss_score = float(score)
    epss = data.get("epss")
    if isinstance(epss, (int, float)):
        fact.epss = float(epss)
    if data.get("kev") is True:
        fact.kev = True
    campaign = data.get("ransomware_campaign")
    if isinstance(campaign, str):
        fact.ransomware = campaign
    if "shodan" not in fact.source:
        fact.source = f"{fact.source}+shodan"


def _apply_exploit_count(fact: VulnFact, client: httpx.Client, key: str) -> None:
    try:
        response = client.get(EXPLOITS, params={"query": f"cve:{fact.cve_id}", "key": key})
        response.raise_for_status()
        total = response.json().get("total")
    except Exception:
        return
    if isinstance(total, int) and total > 0:
        fact.match_note = (fact.match_note + " " if fact.match_note else "") + f"Shodan exploit index: {total}"
