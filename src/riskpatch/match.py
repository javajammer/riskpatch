from __future__ import annotations

from packaging.version import InvalidVersion, Version

from riskpatch.facts import VersionBound


def parse_version(value: str) -> Version | None:
    text = value.strip()
    if text.lower().startswith("v") and text[1:2].isdigit():
        text = text[1:]
    text = text.split("+", 1)[0]
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _cmp_bound(version: Version, bound: str | None, inclusive: bool, is_start: bool) -> bool | None:
    if not bound or bound in {"*", "-"}:
        return True
    parsed = parse_version(bound)
    if parsed is None:
        return None
    if is_start:
        return version >= parsed if inclusive else version > parsed
    return version <= parsed if inclusive else version < parsed


def in_bound(version: str, bound: VersionBound) -> bool | None:
    parsed = parse_version(version)
    if parsed is None:
        return None
    if bound.exact and bound.exact not in {"*", "-"}:
        exact = parse_version(bound.exact)
        if exact is None:
            return None
        return parsed == exact
    checks = [
        _cmp_bound(parsed, bound.start_including, True, True),
        _cmp_bound(parsed, bound.start_excluding, False, True),
        _cmp_bound(parsed, bound.end_including, True, False),
        _cmp_bound(parsed, bound.end_excluding, False, False),
    ]
    if any(item is None for item in checks):
        return None
    return all(checks)


def affected_by_ranges(version: str, ranges: list[VersionBound]) -> bool | None:
    if not ranges:
        return None
    seen: list[bool] = []
    for bound in ranges:
        result = in_bound(version, bound)
        if result is None:
            return None
        seen.append(result)
    return any(seen)


def cpe_version(cpe: str) -> str | None:
    parts = cpe.split(":")
    if len(parts) < 6 or not cpe.startswith("cpe:2.3:"):
        return None
    return parts[5]


def derive_fixed_versions(version: str, ranges: list[VersionBound]) -> list[str]:
    """Upstream fix versions for an installed version, from the ranges that contain it: NVD's end_excluding is the first fixed
    version. end_including bounds say nothing about the fix, and distro backports are not covered (they must be checked with the vendor)."""
    return [b.end_excluding for b in ranges if b.end_excluding and b.end_excluding not in {"*", "-"} and in_bound(version, b) is True]
