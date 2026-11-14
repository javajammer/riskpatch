from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
from pydantic import ValidationError

from riskpatch.alerts import changed, emit
from riskpatch.inventory import Inventory, load_inventory
from riskpatch.llm import attach
from riskpatch.report import ComponentReport, StackReport, action_for, now_iso, rollup, write_reports
from riskpatch.rules import judge
from riskpatch.sources import fetch_component, offline_enabled
from riskpatch.sources.shodan import enrich


def analyze(inventory: Inventory, cache_dir: Path, client: httpx.Client, ttl_ok: bool) -> StackReport:
    errors: list[str] = []
    stale = False
    components: list[ComponentReport] = []
    offline = offline_enabled()
    for component in inventory.components:
        facts, component_stale, error = fetch_component(component, cache_dir, client, offline, ttl_ok)
        stale = stale or component_stale
        if error:
            errors.append(error)
        if not offline:
            facts = enrich(facts, client)
        verdicts = [judge(component, fact) for fact in facts]
        attach(verdicts, client)
        if verdicts:
            level = rollup([item.level for item in verdicts])
        else:
            level = "informational"
        components.append(
            ComponentReport(
                id=component.id,
                name=component.name,
                version=component.version,
                ecosystem=component.ecosystem.value,
                rollup=level,
                action=action_for(level),
                cves=verdicts,
            )
        )
    highest = rollup([item.rollup for item in components]) if components else "unverified"
    return StackReport(
        generated_at=now_iso(),
        stale=stale or offline,
        inventory_name=inventory.meta.name,
        environment=inventory.meta.environment.value,
        highest=highest,
        action=action_for(highest),
        components=components,
        errors=errors,
    )


def run_once(inventory_path: Path, reports_dir: Path, cache_dir: Path, webhook: str, ttl_ok: bool = False) -> StackReport:
    cache_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    previous = _read_previous(reports_dir)
    inventory = load_inventory(inventory_path)
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        report = analyze(inventory, cache_dir, client, ttl_ok)
        write_reports(report, reports_dir)
        reasons = changed(previous, report)
        with httpx.Client(timeout=10, follow_redirects=False) as hook:
            emit(report, reasons, reports_dir, webhook, hook)
    return report


def _read_previous(reports_dir: Path) -> StackReport | None:
    path = reports_dir / "latest.json"
    if not path.exists():
        return None
    try:
        return StackReport.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValidationError):
        return None


def webhook_url() -> str:
    return os.environ.get("ALERT_WEBHOOK_URL", "").strip()
