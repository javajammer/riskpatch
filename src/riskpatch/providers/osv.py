from __future__ import annotations

import httpx

from riskpatch.facts import VersionBound, VulnFact
from riskpatch.textclip import clip_text
from riskpatch.providers import CveQuery, CveRecord

name = "osv"
URL = "https://api.osv.dev/v1"


def _cve_id(item: dict) -> str:
    for alias in item.get("aliases") or []:
        if str(alias).startswith("CVE-"):
            return alias
    return item.get("id") or "UNKNOWN"


def parse_vuln(item: dict, ecosystem: str, pkg_name: str, url: str) -> CveRecord:
    bounds: list[VersionBound] = []
    fixed: list[str] = []
    for affected in item.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name", "").lower() != pkg_name.lower():
            continue
        for block in affected.get("ranges") or []:
            start = None
            for event in block.get("events") or []:
                if "introduced" in event:
                    start = event["introduced"]
                if "fixed" in event or "last_affected" in event:
                    bound = VersionBound(start_including=None if start in {None, "0"} else start)
                    if "fixed" in event:
                        bound.end_excluding = event["fixed"]
                        fixed.append(event["fixed"])
                    else:
                        bound.end_including = event["last_affected"]
                    bounds.append(bound)
                    start = None
        bounds.extend(VersionBound(exact=v) for v in affected.get("versions") or [])
    fact = VulnFact(
        cve_id=_cve_id(item),
        summary=clip_text(item.get("summary") or item.get("details") or ""),
        references=[r["url"] for r in item.get("references") or [] if r.get("url")][:20],
        patched_versions=fixed,
        source="osv",
    )
    return CveRecord(fact=fact, affected={f"{ecosystem}:{pkg_name}": bounds}, source="osv", url=url, raw=item)


class OsvProvider:
    name = "osv"

    def __init__(self, client: httpx.Client):
        self.client = client

    def search(self, query: CveQuery) -> list[CveRecord]:
        response = self.client.post(f"{URL}/query", json={"package": {"name": query.name, "ecosystem": query.ecosystem}, "version": query.version})
        response.raise_for_status()
        return [parse_vuln(v, query.ecosystem, query.name, f"{URL}/vulns/{v.get('id')}") for v in response.json().get("vulns") or []]

    def get(self, cve_id: str) -> CveRecord | None:
        response = self.client.get(f"{URL}/vulns/{cve_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        item = response.json()
        return CveRecord(fact=VulnFact(cve_id=_cve_id(item), summary=clip_text(item.get("summary") or item.get("details") or ""), source="osv"), source="osv", url=f"{URL}/vulns/{cve_id}", raw=item)
