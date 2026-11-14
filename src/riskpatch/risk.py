"""Transparent, versioned priority score for a work item.

The score is a sum of visible reasons, never a hidden number: every point comes with a label so an analyst can explain the order.
It is NOT CVSS alone. Change the weights only together with RISK_VERSION so past decisions can be interpreted.
"""
from __future__ import annotations

from dataclasses import dataclass

RISK_VERSION = "1"
LEVEL_POINTS = {"critical": 40, "high": 30, "medium": 15, "low": 5, "unverified": 3, "informational": 2}
LEVEL_LABELS = {"critical": "Critical severity", "high": "High severity", "medium": "Medium severity", "low": "Low severity",
                "unverified": "Unverified match", "informational": "Informational"}
TIER_POINTS = {"tier1": 10, "tier2": 5, "tier3": 0}
TIER_LABELS = {"tier1": "Tier 1 server", "tier2": "Tier 2 server", "tier3": "Tier 3 server"}
KEV_POINTS, INTERNET_POINTS, FIX_POINTS = 25, 10, 5
AGE_STEPS = ((90, 5, "open 90+ days"), (30, 3, "open 30+ days"))
ALL_UNVERIFIED_PENALTY = -10
# (band, minimum points, plain name)
BANDS = (("P1", 80, "Critical priority"), ("P2", 60, "High priority"), ("P3", 35, "Medium priority"), ("P4", 0, "Low priority"))
BAND_NAMES = {b: n for b, _m, n in BANDS}


@dataclass(frozen=True)
class Score:
    points: int
    band: str
    reasons: tuple[tuple[str, int], ...]
    version: str = RISK_VERSION

    def explain(self) -> str:
        return " · ".join(f"{label} {pts:+d}" for label, pts in self.reasons) + f" = {self.points}"


def score(level: str, kev: bool, internet: bool, best_tier: str, has_fix: bool, age_days: int, all_unverified: bool) -> Score:
    reasons: list[tuple[str, int]] = [(LEVEL_LABELS.get(level, "Severity"), LEVEL_POINTS.get(level, 0))]
    if kev:
        reasons.append(("Known exploited (KEV)", KEV_POINTS))
    if internet:
        reasons.append(("Internet-facing server", INTERNET_POINTS))
    if best_tier in TIER_POINTS and TIER_POINTS[best_tier]:
        reasons.append((TIER_LABELS[best_tier], TIER_POINTS[best_tier]))
    if has_fix:
        reasons.append(("Fix is known", FIX_POINTS))
    for days, pts, label in AGE_STEPS:
        if age_days >= days:
            reasons.append((label, pts))
            break
    if all_unverified:
        reasons.append(("Package match not confirmed", ALL_UNVERIFIED_PENALTY))
    total = max(0, min(100, sum(p for _l, p in reasons)))
    band = next(b for b, minimum, _n in BANDS if total >= minimum)
    return Score(total, band, tuple(reasons))
