from __future__ import annotations

import httpx

name = "kev"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch(client: httpx.Client, etag: str = "") -> tuple[set[str], str, bool]:
    """Returns (cve ids, etag, modified). Uses a conditional request when an etag is known."""
    headers = {"If-None-Match": etag} if etag else {}
    response = client.get(URL, headers=headers)
    if response.status_code == 304:
        return set(), etag, False
    response.raise_for_status()
    ids = {v["cveID"] for v in response.json().get("vulnerabilities") or [] if v.get("cveID")}
    return ids, response.headers.get("etag", ""), True
