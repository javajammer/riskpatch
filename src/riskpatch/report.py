from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field

from riskpatch.rules import LEVELS, CveVerdict, action_for, rollup


class ComponentReport(BaseModel):
    id: str
    name: str
    version: str
    ecosystem: str
    rollup: str
    action: str
    cves: list[CveVerdict] = Field(default_factory=list)
    distro_package: str = ""


class StackReport(BaseModel):
    generated_at: str
    stale: bool
    inventory_name: str
    environment: str
    highest: str
    action: str
    components: list[ComponentReport]
    errors: list[str] = Field(default_factory=list)
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    exposure: str = ""
    tech_stack: list[str] = Field(default_factory=list)

    def fingerprint(self) -> str:
        rows = []
        for component in self.components:
            cves = sorted((item.cve_id, item.level, item.kev) for item in component.cves)
            rows.append((component.id, component.rollup, tuple(cves)))
        return json.dumps(rows, sort_keys=True)


def stack_highest(components: list[ComponentReport]) -> str:
    return rollup([item.rollup for item in components])


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def write_reports(report: StackReport, reports_dir: Path) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump()
    _atomic_write(reports_dir / "latest.json", json.dumps(payload, indent=2))
    _atomic_write(reports_dir / "latest.md", render_markdown(report))


LEVEL_EN = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "unverified": "Unverifiable",
    # Indonesian legacy values in older DB rows
    "kritis": "Critical",
    "tinggi": "High",
    "sedang": "Medium",
    "rendah": "Low",
    "informasi": "Informational",
}
ACTION_EN = {
    "immediate": "Fix this week",
    "schedule": "Schedule within 30 days",
    "document": "Document and monitor",
    "complete": "Complete inventory data",
    # Indonesian legacy values
    "segera": "Fix this week",
    "jadwalkan": "Schedule within 30 days",
    "lengkap": "Complete inventory data",
    "dokumentasi": "Document and monitor",
}
HIGH_CAP = 5


def _en_level(level: str) -> str:
    return LEVEL_EN.get(level, level.replace("_", " ").title())


def _en_action(action: str) -> str:
    return ACTION_EN.get(action, action.replace("_", " ").title())


def _parse_ver(value: str) -> Version | None:
    raw = (value or "").strip().lstrip("vV")
    if not raw:
        return None
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def min_fixed_version(current: str, patched: list[str] | None) -> str | None:
    cur = _parse_ver(current)
    newer: list[Version] = []
    for item in patched or []:
        ver = _parse_ver(item)
        if ver is None:
            continue
        if cur is None or ver > cur:
            newer.append(ver)
    if not newer:
        return None
    return str(min(newer))


def cover_version(current: str, cves: list[CveVerdict]) -> tuple[str | None, int]:
    needed: list[Version] = []
    missing = 0
    for cve in cves:
        fixed = min_fixed_version(current, cve.patched_versions)
        if fixed and (parsed := _parse_ver(fixed)):
            needed.append(parsed)
        else:
            missing += 1
    if not needed:
        return None, missing
    return str(max(needed)), missing


def _os_label(report: StackReport) -> str:
    name = " ".join(p for p in (report.os_name, report.os_version) if p).strip()
    return name or "OS not reported by collector"


def _upgrade_how(component: ComponentReport, target: str | None, os_label: str) -> str:
    distro = (component.distro_package or "").strip()
    if distro:
        return (
            f"This component was collected as distro package `{distro}` on {os_label}. "
            "Use the OS package manager and confirm the security changelog/backport; do not invent an apt/yum version. "
            "If the distro will not ship a fix, install a vendor-supported upstream build side-by-side and point the service at it."
        )
    if target:
        return (
            f"Upgrade the {component.ecosystem} runtime/library from {component.version} to **{target}** "
            f"(minimum version in intel feeds that is newer than the collected build and covers the listed KEV/Critical items). "
            f"Confirm {target} is supported on {os_label} before replacing the binary."
        )
    return (
        f"Intel feeds list no parseable fixed version newer than {component.version}. "
        f"Stay on a vendor-supported release for {os_label}; do not guess a version."
    )


def _patch_to(cve: CveVerdict, current: str) -> str:
    fixed = min_fixed_version(current, cve.patched_versions)
    if fixed:
        return f"minimum safe {fixed}"
    if cve.patched_versions:
        return "fixed versions listed but not comparable to the collected build"
    return "no fixed version in intel feeds"


def _cvss(cve: CveVerdict) -> str:
    if cve.cvss_score is None:
        return "CVSS pending"
    sev = (cve.cvss_severity or _en_level(cve.level)).upper()
    return f"{cve.cvss_score} {sev}"


def _sort_cves(cves: list[CveVerdict]) -> list[CveVerdict]:
    def key(cve: CveVerdict) -> tuple:
        rank = LEVELS.index(cve.level) if cve.level in LEVELS else 0
        return (0 if cve.kev else 1, -(cve.cvss_score or 0), -rank, cve.cve_id)

    return sorted(cves, key=key)


def _cve_line(cve: CveVerdict, current: str) -> str:
    kev = " KEV" if cve.kev else ""
    return f"- `{cve.cve_id}`{kev} · {_en_level(cve.level)} · {_cvss(cve)} · {_patch_to(cve, current)}"


def render_markdown(report: StackReport) -> str:
    all_cves = [cve for component in report.components for cve in component.cves]
    kev = [cve for cve in all_cves if cve.kev]
    by_level = {level: sum(1 for cve in all_cves if cve.level == level) for level in LEVELS}
    n_crit = by_level.get("critical", 0)
    n_high = by_level.get("high", 0)
    n_med = by_level.get("medium", 0)
    n_rest = len(all_cves) - n_crit - n_high - n_med
    os_label = _os_label(report)
    stack = report.tech_stack or [f"{c.name} {c.version}" for c in report.components]
    lines = [
        f"# RiskPatch posture report - {report.inventory_name}",
        "",
        "## Observed host (from collector)",
        "",
        f"- Hostname: {report.hostname or report.inventory_name}",
        f"- Operating system: {os_label}",
        f"- Exposure label: {report.exposure or 'not reported'}",
        f"- Inventory environment tag: {report.environment or 'not reported'} (label only; upgrades use OS and stack below)",
        f"- Collected tech stack: {', '.join(stack) if stack else 'none'}",
        f"- Generated: {report.generated_at}",
        f"- Highest residual risk: {_en_level(report.highest)}",
        f"- Required action: {_en_action(report.action)}",
        f"- Intel freshness: {'STALE - refresh CVE feeds before acting' if report.stale else 'Current'}",
        f"- Open CVE matches: {len(all_cves)} across {len(report.components)} component(s)",
        "",
        "## Executive summary",
        "",
        f"- **Fix this week:** {len(kev)} Known Exploited (KEV) and {n_crit} Critical. These are the only items that should block other work.",
        f"- **Schedule (30 days):** {n_high} High.",
        f"- **Plan / monitor:** {n_med} Medium, {n_rest} Low / informational / unverified.",
        "- Upgrade targets are the minimum versions in intel feeds that are newer than the collected build. If none exist, do not guess a version.",
        "",
    ]
    if report.errors:
        lines.append("## Collection issues")
        lines.extend(f"- {item}" for item in report.errors)
        lines.append("")
    lines += ["## What to do this week", ""]
    if not kev and n_crit == 0:
        lines.append("No KEV or Critical matches. Continue with the 30-day queue.")
        lines.append("")
    else:
        for component in report.components:
            week = _sort_cves([cve for cve in component.cves if cve.kev or cve.level == "critical"])
            if not week:
                continue
            target, missing = cover_version(component.version, week)
            lines.append(f"### {component.name} {component.version} ({component.ecosystem})")
            if target:
                lines.append(f"- **Do this:** upgrade `{component.name}` from `{component.version}` to **`{target}`** on {os_label}. That is the lowest intel-listed version that is newer than the collected build and covers these KEV/Critical matches.")
            else:
                lines.append(f"- **Do this:** keep `{component.name} {component.version}` until a vendor-supported fixed release for {os_label} is identified. Intel feeds do not list a comparable fixed version.")
            if missing:
                lines.append(f"- {missing} listed CVE(s) have no comparable fixed version; they do not lower the upgrade target.")
            lines.append(f"- {_upgrade_how(component, target, os_label)}")
            lines.extend(_cve_line(cve, component.version) for cve in week)
            lines.append("")
    lines += ["## Schedule within 30 days (High)", ""]
    high_any = False
    for component in report.components:
        high = _sort_cves([cve for cve in component.cves if cve.level == "high" and not cve.kev])
        if not high:
            continue
        high_any = True
        shown, rest = high[:HIGH_CAP], high[HIGH_CAP:]
        target, _missing = cover_version(component.version, high)
        lines.append(f"### {component.name} {component.version} ({component.ecosystem})")
        if target:
            lines.append(f"- **Do this:** plan upgrade of `{component.name}` from `{component.version}` to **`{target}`** on {os_label} within 30 days.")
        else:
            lines.append(f"- **Do this:** schedule a vendor-supported upgrade of `{component.name}` on {os_label}; no minimum fixed version is listed in feeds.")
        lines.extend(_cve_line(cve, component.version) for cve in shown)
        if rest:
            lines.append(f"- … {len(rest)} additional High CVE(s) on this component; same upgrade target applies.")
        lines.append("")
    if not high_any:
        lines.append("No additional High matches outside the week-one list.")
        lines.append("")
    lines += ["## Backlog (not this week)", ""]
    backlog = False
    for component in report.components:
        later = [cve for cve in component.cves if cve.level in {"medium", "low", "informational", "unverified"} and not cve.kev]
        if not later:
            continue
        backlog = True
        counts = ", ".join(f"{n} {_en_level(level)}" for level in LEVELS if (n := sum(1 for cve in later if cve.level == level)))
        lines.append(f"- {component.name} {component.version}: {counts}. Action: document and monitor.")
    if not backlog:
        lines.append("- None.")
    lines += [
        "",
        "## Component roll-up",
        "",
    ]
    for component in report.components:
        n = len(component.cves)
        if n == 0:
            lines.append(f"- {component.name} {component.version}: no matching CVE in current feeds.")
        else:
            lines.append(f"- {component.name} {component.version}: {n} match(es), roll-up {_en_level(component.rollup)}, {_en_action(component.action)}.")
    lines += [
        "",
        "## How to use this report",
        "",
        "1. This week: upgrade each component in “What to do this week” to the stated minimum version (or follow the distro-package instruction). That version is derived from intel `patched_versions` and the collected build, not from a guessed distro package number.",
        "2. Confirm the target runs on the collected OS before replacing binaries. If feeds have no target, do not invent one.",
        "3. High items are a 30-day change window. Medium/Low are documentation only.",
        "4. Re-run analysis after each upgrade; resolved matches drop off the next report.",
        "",
        "Deterministic verdicts only. Optional LLM narrative is omitted here so it cannot change priority.",
        "",
    ]
    return "\n".join(lines)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def level_rank(level: str) -> int:
    if level == "unverified":
        return 1
    return LEVELS.index(level) if level in LEVELS else 0


def action_from_report(report: StackReport) -> str:
    return action_for(report.highest if report.highest != "unverified" else "unverified")
