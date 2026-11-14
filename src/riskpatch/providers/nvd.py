from __future__ import annotations

import os
import time

import httpx

from riskpatch.facts import VersionBound, VulnFact
from riskpatch.textclip import clip_text
from riskpatch.match import cpe_version
from riskpatch.providers import CveQuery, CveRecord
from riskpatch.sources.nvd import NVD_URL, _metric

name = "nvd"


def _ranges_by_product(cve: dict) -> dict[str, list[VersionBound]]:
    out: dict[str, list[VersionBound]] = {}
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria") or ""
                parts = criteria.split(":")
                if len(parts) < 6 or parts[2] not in {"a", "o", "h"}:
                    continue
                version = cpe_version(criteria)
                out.setdefault(f"generic:{parts[3]}:{parts[4]}", []).append(
                    VersionBound(
                        exact=None if version in {None, "*", "-"} else version,
                        start_including=match.get("versionStartIncluding"),
                        start_excluding=match.get("versionStartExcluding"),
                        end_including=match.get("versionEndIncluding"),
                        end_excluding=match.get("versionEndExcluding"),
                    )
                )
    return out


def parse_item(item: dict, url: str) -> CveRecord:
    cve = item.get("cve") or item
    summary = ""
    for desc in cve.get("descriptions") or []:
        if desc.get("lang") == "en":
            summary = desc.get("value") or ""
            break
    score, severity, vector = _metric(cve)
    fact = VulnFact(
        cve_id=cve.get("id") or "UNKNOWN",
        summary=clip_text(summary),
        cvss_score=score,
        cvss_severity=severity,
        attack_vector=vector,
        cwe=[d["value"] for w in cve.get("weaknesses") or [] for d in w.get("description") or [] if d.get("value", "").startswith("CWE-")],
        kev=bool(cve.get("cisaExploitAdd")),
        references=[r["url"] for r in cve.get("references") or [] if r.get("url")][:20],
        source="nvd",
    )
    return CveRecord(fact=fact, affected=_ranges_by_product(cve), source="nvd", url=url, raw=cve)


class NvdProvider:
    name = "nvd"

    def __init__(self, client: httpx.Client, delay: float | None = None):
        self.client = client
        self.delay = float(os.environ.get("NVD_REQUEST_DELAY", "0" if os.environ.get("NVD_API_KEY") else "6")) if delay is None else delay
        self._last = 0.0

    def _get(self, params: dict) -> dict:
        headers = {}
        key = os.environ.get("NVD_API_KEY", "").strip()
        if key:
            headers["apiKey"] = key
        backoff = 2.0
        for attempt in range(4):
            wait = self.delay - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            response = self.client.get(NVD_URL, params=params, headers=headers)
            if response.status_code in {403, 429, 503}:
                time.sleep(backoff * (attempt + 1))
                continue
            response.raise_for_status()
            return response.json()
        raise httpx.HTTPError("nvd rate limited or unavailable")

    def search(self, query: CveQuery) -> list[CveRecord]:
        cpe = f"cpe:2.3:a:{query.vendor}:{query.product}:{query.version}:*:*:*:*:*:*:*"
        body = self._get({"virtualMatchString": cpe, "resultsPerPage": "200"})
        return [parse_item(i, f"{NVD_URL}?virtualMatchString={cpe}") for i in body.get("vulnerabilities") or []]

    def get(self, cve_id: str) -> CveRecord | None:
        body = self._get({"cveId": cve_id})
        items = body.get("vulnerabilities") or []
        return parse_item(items[0], f"{NVD_URL}?cveId={cve_id}") if items else None

    def modified(self, start: str, end: str, index: int, page: int = 2000) -> tuple[list[CveRecord], int]:
        """One page of CVEs modified in [start, end]. Returns (records, totalResults)."""
        params = {"lastModStartDate": start, "lastModEndDate": end, "startIndex": str(index), "resultsPerPage": str(page)}
        body = self._get(params)
        url = f"{NVD_URL}?lastModStartDate={start}&lastModEndDate={end}"
        return [parse_item(i, url) for i in body.get("vulnerabilities") or []], int(body.get("totalResults") or 0)
