from riskpatch.facts import VersionBound, VulnFact
from riskpatch.inventory import load_inventory
from riskpatch.rules import judge
from pathlib import Path


def component(exposure="internet", role="runtime", runtime=True, distro=""):
    item = load_inventory(Path("inventory/stack.example.yaml")).components[0]
    data = item.model_dump()
    data.update(exposure=exposure, role=role, used_at_runtime=runtime, distro_package=distro)
    return item.__class__.model_validate(data)


def fact(**kwargs):
    base = dict(
        cve_id="CVE-2024-0001",
        summary="test",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        attack_vector="NETWORK",
        kev=False,
        affected=True,
        source="test",
        ranges=[VersionBound(start_including="8.2.0", end_excluding="8.2.20")],
    )
    base.update(kwargs)
    return VulnFact(**base)


def test_internet_unauth_critical():
    verdict = judge(component(), fact())
    assert verdict.level == "critical"
    assert verdict.action == "Fix this week"


def test_kev_raises_one():
    verdict = judge(component(exposure="internal", role="library"), fact(cvss_score=5.0, attack_vector="LOCAL", kev=True))
    assert verdict.level == "high"


def test_localhost_lowers_not_safe():
    verdict = judge(component(exposure="localhost"), fact())
    assert verdict.level == "high"
    assert verdict.level != "informational"


def test_dev_capped():
    verdict = judge(component(role="dev", runtime=False), fact())
    assert verdict.level == "low"


def test_outside_range_info():
    verdict = judge(component(), fact(affected=False, ranges=[VersionBound(end_excluding="8.2.0")]))
    assert verdict.level == "informational"


def test_distro_backport_unverified():
    verdict = judge(component(distro="8.2.12-1ubuntu"), fact(affected=False))
    assert verdict.level == "unverified"
    assert verdict.action == "Complete inventory data"


def test_missing_cvss_is_unverified():
    verdict = judge(component(), fact(cvss_score=None, attack_vector=None))
    assert verdict.level == "unverified"


def test_unknown_range():
    verdict = judge(component(), fact(affected=None, ranges=[]))
    assert verdict.level == "unverified"
