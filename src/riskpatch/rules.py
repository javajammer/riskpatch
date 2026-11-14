from __future__ import annotations

from pydantic import BaseModel, Field

from riskpatch.facts import VulnFact
from riskpatch.inventory import AuthBoundary, Component, Exposure, Role
from riskpatch.match import affected_by_ranges

LEVELS = [
    "informational",
    "low",
    "medium",
    "high",
    "critical",
]


class CveVerdict(BaseModel):
    cve_id: str
    summary: str
    cvss_score: float | None
    cvss_severity: str | None
    attack_vector: str | None
    cwe: list[str]
    kev: bool
    references: list[str]
    patched_versions: list[str]
    source: str
    level: str
    action: str
    exposure: str
    exposure_assumed: bool
    reachability: str
    one_line: str
    raises: list[str] = Field(default_factory=list)
    lowers: list[str] = Field(default_factory=list)
    narrative: str = ""
    narrative_source: str = "none"
    verdict: str = "unknown"


def bump(level: str, steps: int) -> str:
    index = LEVELS.index(level)
    return LEVELS[max(0, min(len(LEVELS) - 1, index + steps))]


def action_for(level: str) -> str:
    if level in {"critical", "high"}:
        return "Fix this week"
    if level == "medium":
        return "Schedule within 30 days"
    if level == "unverified":
        return "Complete inventory data"
    return "Document and monitor"


def reachability_for(component: Component) -> str:
    if not component.used_at_runtime:
        return "installed only"
    if component.effective_exposure == Exposure.internet:
        return "reachable externally (from template, not from code)"
    if component.effective_exposure in {Exposure.internal, Exposure.vpn, Exposure.localhost}:
        return "reachable internally (from template, not from code)"
    return "unverifiable"


def base_from_cvss(score: float | None) -> str:
    if score is None:
        return "unverified"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    return "medium"


def rollup(levels: list[str]) -> str:
    if not levels:
        return "informational"
    if any(level == "unverified" for level in levels) and all(
        level in {"informational", "unverified"} for level in levels
    ):
        return "unverified"
    ranked = [level for level in levels if level in LEVELS]
    if not ranked:
        return "unverified"
    return max(ranked, key=LEVELS.index)


def judge(component: Component, fact: VulnFact) -> CveVerdict:
    raises: list[str] = []
    lowers: list[str] = []
    assumed = component.exposure == Exposure.unknown
    if assumed:
        raises.append("unknown exposure treated as internet")
    affected = fact.affected
    if affected is None and fact.ranges:
        affected = affected_by_ranges(component.version, fact.ranges)
    if affected is None:
        level = "unverified"
        line = "Version match unverified. Do not assume safe."
        verdict = "unknown"
    elif not affected:
        if component.distro_package:
            level = "unverified"
            line = (
                "Upstream version outside official range, but distro_package is set. "
                "Distro backport not proven, so not necessarily safe."
            )
            verdict = "unknown"
        else:
            level = "informational"
            line = "Not affected on this upstream version per official range."
            verdict = "not_affected"
    else:
        verdict = "affected"
        level = base_from_cvss(fact.cvss_score)
        vector = (fact.attack_vector or "").upper()
        high_network = vector == "NETWORK" and (fact.cvss_score or 0) >= 7.0
        exposed = component.effective_exposure == Exposure.internet
        open_auth = component.auth_boundary in {AuthBoundary.unauthenticated, AuthBoundary.unknown}
        if high_network and exposed and open_auth:
            level = "critical" if (fact.cvss_score or 0) >= 9.0 or fact.kev else "high"
            raises.append("network, open exposure, and weak or unknown auth")
        if fact.kev and level in LEVELS and level != "critical":
            level = bump(level, 1)
            raises.append("in KEV, bumped one level")
        elif fact.kev:
            raises.append("in KEV")
        if component.effective_exposure in {Exposure.localhost, Exposure.vpn} and level in LEVELS:
            if level != "informational":
                level = bump(level, -1)
            lowers.append("localhost or vpn exposure lowers one level, not safe")
        if component.role == Role.dev and not component.used_at_runtime:
            if level in {"medium", "high", "critical"}:
                level = "low"
            lowers.append("dev and not used at runtime, max low")
        if fact.epss is not None and fact.epss >= 0.5:
            raises.append(f"EPSS {fact.epss:.2f} per Shodan")
        if fact.ransomware and fact.ransomware.lower() not in {"", "none", "unknown"}:
            raises.append("related to ransomware campaign per Shodan")
        if component.mitigations:
            lowers.append("mitigations recorded in template, not verified on host: " + ", ".join(component.mitigations))
        if level == "unverified":
            line = "Version is in affected range, but CVSS score missing. Not medium."
        else:
            line = f"Version {component.version} is in affected range. Actual risk {level}."
    return CveVerdict(
        cve_id=fact.cve_id,
        summary=fact.summary,
        cvss_score=fact.cvss_score,
        cvss_severity=fact.cvss_severity,
        attack_vector=fact.attack_vector,
        cwe=fact.cwe,
        kev=fact.kev,
        references=fact.references[:8],
        patched_versions=fact.patched_versions,
        source=fact.source,
        level=level,
        action=action_for(level),
        exposure=component.effective_exposure.value,
        exposure_assumed=assumed,
        reachability=reachability_for(component),
        one_line=line,
        raises=raises,
        lowers=lowers,
        verdict=verdict,
    )
