from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from riskpatch.report import StackReport, level_rank, now_iso


def changed(previous: StackReport | None, current: StackReport) -> list[str]:
    if previous is None:
        previous = current.model_copy(update={"highest": "informational", "components": []})
    reasons: list[str] = []
    if level_rank(current.highest) > level_rank(previous.highest):
        reasons.append(f"rollup raised from {previous.highest} to {current.highest}")
    prev = {item.cve_id: item for item in _flat(previous)}
    for item in _flat(current):
        old = prev.get(item.cve_id)
        if old is None:
            reasons.append(f"New CVE {item.cve_id}")
        elif item.kev and not old.kev:
            reasons.append(f"KEV newly assigned {item.cve_id}")
        elif item.level != old.level and item.level in {"high", "critical", "medium"} and old.level in {"informational", "low", "unverified"}:
            reasons.append(f"{item.cve_id} leveled from {old.level} to {item.level}")
    return reasons


def _flat(report: StackReport):
    for component in report.components:
        for cve in component.cves:
            yield cve


def webhook_allowed(url: str) -> bool:
    parsed = urlsplit(url.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def emit(report: StackReport, reasons: list[str], reports_dir: Path, webhook: str, client: httpx.Client) -> None:
    if not reasons:
        return
    reports_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "at": now_iso(),
        "highest": report.highest,
        "reasons": reasons,
        "inventory": report.inventory_name,
    }
    with (reports_dir / "alerts.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    if not webhook_allowed(webhook):
        return
    for _ in range(3):
        try:
            response = client.post(webhook, json=entry, timeout=10)
            response.raise_for_status()
            return
        except Exception:
            continue
