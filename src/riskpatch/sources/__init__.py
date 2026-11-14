from __future__ import annotations

import json
import os
from pathlib import Path

import httpx

from riskpatch.facts import VulnFact
from riskpatch.inventory import Component, Ecosystem
from riskpatch.sources.circl import query_circl
from riskpatch.sources.nvd import query_nvd
from riskpatch.sources.osv import query_osv

PACKAGE = {
    Ecosystem.packagist,
    Ecosystem.debian,
    Ecosystem.ubuntu,
    Ecosystem.pypi,
    Ecosystem.npm,
    Ecosystem.go,
    Ecosystem.crates,
}


def cache_path(cache_dir: Path, component: Component) -> Path:
    return cache_dir / f"{component.id}.json"


def load_cached(path: Path) -> list[VulnFact]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [VulnFact.model_validate(item) for item in payload.get("vulns") or []]


def save_cached(path: Path, facts: list[VulnFact], stale: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"stale": stale, "vulns": [item.model_dump() for item in facts]}, indent=2),
        encoding="utf-8",
    )


def bundled_fixture(component: Component) -> list[VulnFact]:
    root = Path(__file__).resolve().parents[1] / "fixtures" / f"{component.id}.json"
    if not root.exists():
        return []
    return load_cached(root)


def bundled_fixture_by_product(product: str) -> list[VulnFact]:
    path = Path(__file__).resolve().parents[1] / "fixtures" / f"{product.lower()}.json"
    return load_cached(path) if path.exists() else []


def fetch_component(component: Component, cache_dir: Path, client: httpx.Client, offline: bool, ttl_ok: bool) -> tuple[list[VulnFact], bool, str]:
    path = cache_path(cache_dir, component)
    if offline:
        if path.exists():
            return load_cached(path), True, ""
        bundled = bundled_fixture(component)
        if bundled:
            save_cached(path, bundled, True)
            return bundled, True, ""
        return [], True, f"{component.id}: offline and cache empty"
    if ttl_ok and path.exists():
        return load_cached(path), False, ""
    errors: list[str] = []
    facts: list[VulnFact] = []
    try:
        if component.ecosystem in PACKAGE:
            facts = query_osv(component, client)
        else:
            facts = query_nvd(component, client)
    except Exception as exc:
        errors.append(f"{component.id}: sumber utama gagal: {exc}")
        try:
            facts = query_circl(component, client)
            errors.clear()
        except Exception as fallback:
            errors.append(f"{component.id}: CIRCL gagal: {fallback}")
            if path.exists():
                return load_cached(path), True, "; ".join(errors)
            return [], True, "; ".join(errors)
    save_cached(path, facts, False)
    return facts, False, ""


def offline_enabled() -> bool:
    return os.environ.get("RISKPATCH_OFFLINE", "0") == "1"
