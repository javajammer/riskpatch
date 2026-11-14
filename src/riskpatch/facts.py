from __future__ import annotations

from pydantic import BaseModel, Field


class VersionBound(BaseModel):
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None
    exact: str | None = None


class VulnFact(BaseModel):
    cve_id: str
    summary: str = ""
    cvss_score: float | None = None
    cvss_severity: str | None = None
    attack_vector: str | None = None
    cwe: list[str] = Field(default_factory=list)
    kev: bool = False
    references: list[str] = Field(default_factory=list)
    patched_versions: list[str] = Field(default_factory=list)
    ranges: list[VersionBound] = Field(default_factory=list)
    affected: bool | None = None
    source: str
    match_note: str = ""
    epss: float | None = None
    ransomware: str = ""
