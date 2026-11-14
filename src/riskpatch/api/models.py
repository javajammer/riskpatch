from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class AssetDeleteRequest(BaseModel):
    asset_ids: list[str] = Field(min_length=1, max_length=200)


class FreshnessRefreshRequest(BaseModel):
    layer: str | None = Field(None, max_length=32)
    asset_id: str | None = Field(None, max_length=255)


class Health(BaseModel):
    status: str
    version: str


class Ready(BaseModel):
    status: str
    schema_version: int
    database: str


class AssetOut(BaseModel):
    asset_id: str
    hostname: str | None = None
    environment: str
    exposure: str
    auth_boundary: str
    mitigations: list[str] = Field(default_factory=list)
    collector_version: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_id: str | None = None
    kernel: str | None = None
    latest_snapshot_id: int | None = None
    first_seen: str
    last_seen: str
    updated_at: str
    findings_open: int = 0
    highest_level: str | None = None
    owner: str = ""
    business_tier: str = ""
    service: str = ""
    maintenance_window: str = ""
    ownership_updated_at: str | None = None
    ownership_updated_by: str = ""


class OwnershipPatch(BaseModel):
    owner: str | None = Field(None, max_length=120)
    business_tier: str | None = Field(None, pattern="^(tier1|tier2|tier3|)$")
    service: str | None = Field(None, max_length=120)
    maintenance_window: str | None = Field(None, max_length=120)


class AssetPatch(BaseModel):
    environment: str | None = Field(None, max_length=32)
    exposure: str | None = Field(None, pattern="^(internet|internal|vpn|localhost|unknown)$")
    auth_boundary: str | None = Field(None, pattern="^(unauthenticated|authenticated|admin|unknown)$")
    mitigations: list[str] | None = Field(None, max_length=50)


class SnapshotOut(BaseModel):
    id: int
    asset_id: str
    collected_at: str
    received_at: str
    collector_version: str | None = None
    schema_version: str
    payload_hash: str
    analysis_status: str
    analyzed_at: str | None = None
    error_count: int
    updated_at: str


class SnapshotDetail(SnapshotOut):
    components: list[dict[str, Any]]
    diff_from_previous: dict[str, Any]
    facts: dict[str, Any] | None = None


class FindingOut(BaseModel):
    id: int
    asset_id: str
    snapshot_id: int | None = None
    component_name: str
    component_version: str
    ecosystem: str
    cve_id: str
    level: str
    previous_level: str | None = None
    action: str
    confidence: str
    status: str
    cvss_score: float | None = None
    kev: bool
    exposure: str
    exposure_assumed: bool
    reachability: str
    one_line: str
    ruleset_version: str
    first_seen: str
    last_seen: str
    level_changed_at: str
    updated_at: str


class Evidence(BaseModel):
    kind: str
    detail: str


class FindingDetail(FindingOut):
    evidence: list[Evidence]
    verdict: dict[str, Any]


class CveOut(BaseModel):
    cve_id: str
    summary: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    attack_vector: str | None = None
    cwe: list[str] = Field(default_factory=list)
    kev: bool
    references: list[str] = Field(default_factory=list)
    patched_versions: list[str] = Field(default_factory=list)
    primary_source: str
    revision: int
    first_seen: str
    updated_at: str


class CveDetail(CveOut):
    affected: list[dict[str, Any]]
    sources: list[dict[str, Any]]
    revisions: list[dict[str, Any]]
    affected_assets: list[dict[str, Any]]


class JobOut(BaseModel):
    id: int
    type: str
    status: str
    trigger_source: str
    scope: dict[str, Any]
    queued_at: str
    started_at: str | None = None
    finished_at: str | None = None
    counts: dict[str, Any]
    error: str | None = None
    provider_status: dict[str, Any]
    attempts: int
    app_version: str | None = None
    ruleset_version: str | None = None
    duration_seconds: float | None = None


class JobDetail(JobOut):
    events: list[dict[str, Any]]


class JobRequest(BaseModel):
    asset_id: str | None = Field(None, max_length=128)


class CorrelationRequest(BaseModel):
    asset_id: str | None = Field(None, max_length=128, description="null = all assets")
    max_findings: int = Field(5, ge=1, le=20, description="number of open findings (highest level first) to send to model")
    skills: str | None = Field(None, max_length=4000, description="optional skills / context snippets fed to the LLM as extra context")


class ReportOut(BaseModel):
    id: int
    asset_id: str | None = None
    snapshot_id: int | None = None
    analysis_run_id: int | None = None
    generated_at: str
    highest: str
    stale: bool


class ReportDetail(ReportOut):
    content: dict[str, Any]
    markdown: str


class AlertOut(BaseModel):
    id: int
    asset_id: str | None = None
    kind: str
    message: str
    created_at: str
    status: str = "open"
    acknowledged_at: str | None = None
    acknowledged_by: str | None = None
    closed_at: str | None = None
    closed_by: str | None = None
    resolution_note: str = ""


class AlertCloseRequest(BaseModel):
    resolution_note: str = Field(min_length=3, max_length=1000)


class ProviderOut(BaseModel):
    provider: str
    last_attempt_at: str | None = None
    last_success_at: str | None = None
    last_error: str | None = None
    stale: bool
    records_last_run: int


class SearchHit(BaseModel):
    kind: str
    ref: str
    title: str
    snippet: str
