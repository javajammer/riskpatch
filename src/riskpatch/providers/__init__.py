"""HTTP provider adapters. Each keeps provenance (url, raw response) next to the normalized record."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from riskpatch.facts import VersionBound, VulnFact


@dataclass
class CveQuery:
    vendor: str = ""
    product: str = ""
    ecosystem: str = ""
    name: str = ""
    version: str = ""


@dataclass
class CveRecord:
    fact: VulnFact
    affected: dict[str, list[VersionBound]] = field(default_factory=dict)  # match_key -> ranges
    source: str = ""
    url: str = ""
    raw: Any = None


class CveProvider(Protocol):
    name: str

    def search(self, query: CveQuery) -> list[CveRecord]: ...

    def get(self, cve_id: str) -> CveRecord | None: ...
