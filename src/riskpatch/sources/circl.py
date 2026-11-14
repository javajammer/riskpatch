from __future__ import annotations

import httpx

from riskpatch.facts import VersionBound, VulnFact
from riskpatch.textclip import clip_text
from riskpatch.inventory import Component
from riskpatch.match import affected_by_ranges, cpe_version


def _summary(item: dict) -> str:
    summary = item.get("summary") or item.get("description") or ""
    if isinstance(summary, dict):
        return clip_text(str(summary.get("summary") or ""))
    return clip_text(str(summary))


def _score(item: dict) -> tuple[float | None, str | None, str | None]:
    cvss = item.get("cvss") or item.get("cvss3")
    if isinstance(cvss, (int, float)):
        return float(cvss), None, None
    if isinstance(item.get("cvss3"), dict):
        data = item["cvss3"]
        return data.get("baseScore"), data.get("baseSeverity"), data.get("attackVector")
    return None, None, None


def query_circl(component: Component, client: httpx.Client) -> list[VulnFact]:
    vendor = component.vendor or "unknown"
    product = component.product or component.name
    response = client.get(f"https://cve.circl.lu/api/search/{vendor}/{product}")
    response.raise_for_status()
    payload = response.json()
    rows = payload if isinstance(payload, list) else payload.get("data") or payload.get("results") or []
    facts: list[VulnFact] = []
    for item in rows[:50]:
        if not isinstance(item, dict):
            continue
        bounds: list[VersionBound] = []
        for access in item.get("vulnerable_configuration") or item.get("vulnerable_product") or []:
            if isinstance(access, str) and access.startswith("cpe:"):
                version = cpe_version(access)
                if version and version not in {"*", "-"}:
                    bounds.append(VersionBound(exact=version))
        affected = affected_by_ranges(component.version, bounds) if bounds else None
        score, severity, vector = _score(item)
        cve_id = item.get("id") or item.get("cve") or "UNKNOWN"
        facts.append(
            VulnFact(
                cve_id=str(cve_id),
                summary=_summary(item),
                cvss_score=score,
                cvss_severity=severity,
                attack_vector=vector,
                kev=bool(item.get("kev") or item.get("cisa")),
                references=[item["href"]] if item.get("href") else [],
                ranges=bounds,
                affected=affected,
                source="circl",
            )
        )
    return [fact for fact in facts if fact.affected is not False]
