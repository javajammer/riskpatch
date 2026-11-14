"""English text helpers for CVE summaries and operator briefings."""
from __future__ import annotations

import json
import re
from typing import Any

SUMMARY_LIMIT = 8000
LIST_LIMIT = 180


def clip_text(value: str, limit: int = SUMMARY_LIMIT) -> str:
    text = (value or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    for sep in (". ", ".\n", "\n\n"):
        i = cut.rfind(sep)
        if i >= 12:
            return cut[: i + 1].strip()
    return cut.rstrip() + "…"


def clip_list(value: str, limit: int = LIST_LIMIT) -> str:
    text = (value or "").strip()
    if len(text) <= limit:
        return text or "-"
    return text[: limit - 1].rstrip() + "…"


def summary_from_raw(raw_json: str | None) -> str:
    if not raw_json:
        return ""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return ""
    cve = data.get("cve") or data
    for desc in cve.get("descriptions") or []:
        if str(desc.get("lang", "")).startswith("en"):
            return (desc.get("value") or "").strip()
    details = data.get("details") or data.get("summary")
    return str(details or "").strip()


def best_summary(stored: str, *raws: str | None) -> str:
    candidates = [stored or ""]
    candidates.extend(summary_from_raw(raw) for raw in raws)
    return max((clip_text(c) for c in candidates), key=len)


def _range_label(item: dict[str, Any]) -> str:
    """Generate a human-readable version range label from a VersionBound dict.

    Returns a clear label describing the affected version range.
    When no range boundaries are set, returns a note that the range is unspecified.
    """
    if item.get("exact"):
        return f"version {item['exact']}"
    parts = []
    if item.get("start_including"):
        parts.append(f">= {item['start_including']}")
    if item.get("start_excluding"):
        parts.append(f"> {item['start_excluding']}")
    if item.get("end_including"):
        parts.append(f"<= {item['end_including']}")
    if item.get("end_excluding"):
        parts.append(f"< {item['end_excluding']}")
    if parts:
        return " ".join(parts)
    return "version range not specified"


def product_from_key(match_key: str) -> str:
    parts = match_key.split(":")
    if len(parts) >= 3:
        return f"{parts[1]} {parts[2]}".replace("_", " ")
    return match_key.replace(":", " ")


def first_sentence(text: str) -> str:
    text = re.sub(r"\s+", " ", (text or "").strip())
    if not text:
        return ""
    m = re.search(r"(.+?[.!?])(\s|$)", text)
    return (m.group(1) if m else text[:240]).strip()


def operator_brief(
    *,
    cve_id: str,
    summary: str,
    cvss_score: Any,
    cvss_severity: str | None,
    attack_vector: str | None,
    kev: bool,
    cwe: list[str],
    patched_versions: list[str],
    products: list[str],
    affected_assets: list[dict],
    observed_os: str | None = None,
    distro_package: str | None = None,
) -> dict[str, list[str]]:
    lead = first_sentence(summary) or f"{cve_id} is recorded in the vulnerability catalog."
    products = [p for p in products if p] or []
    affected: list[str] = [lead]
    if products:
        affected.append("Catalog matches: " + "; ".join(products[:12]) + ("…" if len(products) > 12 else ""))
    if affected_assets:
        bits = []
        for a in affected_assets[:12]:
            mst = a.get("min_safe_target") or "not listed"
            aname = a["asset"]
            comp = a["component"]
            ver = a["version"]
            lvl = a["level"]
            bits.append(f"{aname} / {comp} {ver} → level {lvl} → min safe {mst}")
        affected.append("Affected open findings on this workspace: " + "; ".join(bits) + ("…" if len(affected_assets) > 12 else ""))
    else:
        affected.append("No open findings on collected assets. This CVE may still apply to uncollected software (for example a kernel or package not in the snapshot).")
    if attack_vector:
        affected.append(f"Attack vector recorded: {attack_vector}.")
    if cwe:
        affected.append("Weakness IDs: " + ", ".join(cwe[:8]) + ".")
    if kev:
        affected.append("CISA KEV: yes. Treat as actively exploited until the collected build is proven patched.")

    score = f"{cvss_score} {cvss_severity}" if cvss_score is not None else (cvss_severity or "not scored")
    mitigation = [
        f"Severity in catalog: {score}. Do not wait for a complete rewrite of the service; reduce exposure of the affected component until a patched build is in place.",
        "If the component is network-facing, restrict who can reach it (management network, firewall, or disable the service) until corrective action is done.",
        "Do not apply unpublished workarounds from unofficial blogs. Use the vendor or distro advisory linked in provenance.",
    ]
    if patched_versions:
        mitigation.append("Fixed versions listed in intel feeds: " + ", ".join(patched_versions[:8]) + ".")

    corrective: list[str] = []
    fixed_assets = [a for a in affected_assets if a.get("min_safe_target")]
    if fixed_assets:
        for a in fixed_assets[:8]:
            asset_name = a["asset"]
            comp = a["component"]
            ver = a["version"]
            mst = a["min_safe_target"]
            os_hint = observed_os or "the observed OS"
            corrective.append(
                f"Upgrade {asset_name} ({comp}) from {ver} to {mst} or newer on {os_hint}."
            )
        corrective.append("Re-run RiskPatch analysis after the upgrade and confirm these CVEs no longer appear as open findings.")
    else:
        if observed_os:
            corrective.append(
                f"No fixed version listed in intel feeds - stay on vendor-supported release for {observed_os}; do not guess a package number"
            )
        else:
            corrective.append("No fixed version listed in intel feeds - stay on vendor-supported release; do not guess a package number")
        if distro_package:
            corrective.insert(
                1,
                f"If distro package '{distro_package}' is set, verify the corresponding apt/yum security package on this OS; do not invent a package number.",
            )
        corrective.append("Re-run RiskPatch analysis after any upgrade and confirm this CVE no longer appears as an open finding.")

    preventive = [
        "Keep the observed OS and runtimes on vendor-supported releases; delay of kernel and TLS library updates is the usual root cause of repeat Critical findings.",
        "Record environment and exposure in inventory so scoring does not assume internet for unclassified hosts.",
        "Subscribe to distro security notices for the collected packages and apply them on a fixed cadence, not only after a SOC ticket.",
    ]
    if kev:
        preventive.append("Add this CVE to the KEV watch list until every collected asset is patched or proven not running the component.")
    return {
        "affected": affected,
        "mitigation": mitigation,
        "corrective": corrective,
        "preventive": preventive,
    }
