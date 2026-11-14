from riskpatch.facts import VersionBound
from riskpatch.match import affected_by_ranges, cpe_version, in_bound


def test_range_excludes_patched():
    bound = VersionBound(start_including="8.2.0", end_excluding="8.2.20")
    assert in_bound("8.2.12", bound) is True
    assert in_bound("8.2.20", bound) is False


def test_unparseable_is_none():
    assert affected_by_ranges("not a version", [VersionBound(exact="1.0.0")]) is None


def test_cpe_version():
    assert cpe_version("cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*") == "8.2.12"
