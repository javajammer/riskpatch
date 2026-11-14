from __future__ import annotations

import os
import time

import httpx

from riskpatch.facts import VersionBound, VulnFact
from riskpatch.textclip import clip_text
from riskpatch.inventory import Component
from riskpatch.match import cpe_version

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _metric(cve: dict) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        block = metrics.get(key) or []
        if not block:
            continue
        data = block[0].get("cvssData") or {}
        return data.get("baseScore"), data.get("baseSeverity"), data.get("attackVector")
    return None, None, None


def _bounds_from_match(match: dict) -> VersionBound:
    criteria = match.get("criteria") or ""
    version = cpe_version(criteria)
    exact = None if version in {None, "*", "-"} else version
    return VersionBound(
        exact=exact,
        start_including=match.get("versionStartIncluding"),
        start_excluding=match.get("versionStartExcluding"),
        end_including=match.get("versionEndIncluding"),
        end_excluding=match.get("versionEndExcluding"),
    )


def _ranges(cve: dict) -> list[VersionBound]:
    bounds: list[VersionBound] = []
    for node in (cve.get("configurations") or []):
        for child in node.get("nodes") or []:
            for match in child.get("cpeMatch") or []:
                if match.get("vulnerable"):
                    bounds.append(_bounds_from_match(match))
    return bounds


def _fact(item: dict) -> VulnFact:
    cve = item.get("cve") or item
    descriptions = cve.get("descriptions") or []
    summary = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            summary = desc.get("value") or ""
            break
    if not summary and descriptions:
        summary = descriptions[0].get("value") or ""
    score, severity, vector = _metric(cve)
    kev = bool((cve.get("cisaExploitAdd") or cve.get("cisaRequiredAction")))
    return VulnFact(
        cve_id=cve.get("id") or "UNKNOWN",
        summary=clip_text(summary),
        cvss_score=score,
        cvss_severity=severity,
        attack_vector=vector,
        cwe=[
            (weak.get("description") or [{}])[0].get("value", "")
            for weak in cve.get("weaknesses") or []
        ],
        kev=kev,
        references=[ref.get("url", "") for ref in cve.get("references") or [] if ref.get("url")],
        ranges=_ranges(cve),
        affected=True,
        source="nvd",
        match_note="NVD cpeName/virtualMatchString considers this CVE relevant",
    )


def query_nvd(component: Component, client: httpx.Client) -> list[VulnFact]:
    params: dict[str, str] = {"resultsPerPage": "50"}
    if component.cpe:
        params["cpeName"] = component.cpe
    else:
        params["virtualMatchString"] = f"cpe:2.3:a:{component.vendor}:{component.product}:{component.version}:*:*:*:*:*:*:*"
    headers = {}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    delay = 1.0
    last_error: Exception | None = None
    for _ in range(4):
        response = client.get(NVD_URL, params=params, headers=headers)
        if response.status_code in {403, 429, 503}:
            last_error = httpx.HTTPStatusError("nvd rate limit", request=response.request, response=response)
            time.sleep(delay)
            delay *= 2
            continue
        response.raise_for_status()
        return [_fact(item) for item in response.json().get("vulnerabilities") or []]
    if last_error:
        raise last_error
    return []
