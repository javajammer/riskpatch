from __future__ import annotations

import httpx

from riskpatch.facts import VersionBound, VulnFact
from riskpatch.textclip import clip_text
from riskpatch.inventory import Component, Ecosystem

OSV_ECOSYSTEM = {
    Ecosystem.packagist: "Packagist",
    Ecosystem.debian: "Debian",
    Ecosystem.ubuntu: "Ubuntu",
    Ecosystem.pypi: "PyPI",
    Ecosystem.npm: "npm",
    Ecosystem.go: "Go",
    Ecosystem.crates: "crates.io",
}


def _ranges(item: dict) -> list[VersionBound]:
    bounds: list[VersionBound] = []
    for affected in item.get("affected") or []:
        for block in affected.get("ranges") or []:
            events = block.get("events") or []
            start = None
            for event in events:
                if "introduced" in event:
                    start = event["introduced"]
                if "fixed" in event or "last_affected" in event:
                    bound = VersionBound(start_including=None if start in {None, "0"} else start)
                    if "fixed" in event:
                        bound.end_excluding = event["fixed"]
                    else:
                        bound.end_including = event["last_affected"]
                    bounds.append(bound)
                    start = None
        for version in (affected.get("versions") or []):
            bounds.append(VersionBound(exact=version))
    return bounds


def _cve_id(item: dict) -> str:
    for alias in item.get("aliases") or []:
        if str(alias).startswith("CVE-"):
            return alias
    return item.get("id") or "UNKNOWN"


def query_osv(component: Component, client: httpx.Client) -> list[VulnFact]:
    ecosystem = OSV_ECOSYSTEM.get(component.ecosystem)
    if ecosystem is None:
        return []
    response = client.post(
        "https://api.osv.dev/v1/query",
        json={
            "package": {"name": component.package_name, "ecosystem": ecosystem},
            "version": component.version,
        },
    )
    response.raise_for_status()
    facts: list[VulnFact] = []
    for item in response.json().get("vulns") or []:
        severity = None
        score = None
        for entry in item.get("severity") or []:
            if entry.get("type") == "CVSS_V3" and entry.get("score"):
                severity = entry["score"]
        facts.append(
            VulnFact(
                cve_id=_cve_id(item),
                summary=clip_text(item.get("summary") or item.get("details") or ""),
                cvss_score=score,
                cvss_severity=severity,
                references=[ref.get("url", "") for ref in item.get("references") or [] if ref.get("url")],
                ranges=_ranges(item),
                affected=True,
                source="osv",
                match_note="OSV returns vuln for sent version",
            )
        )
    return facts
