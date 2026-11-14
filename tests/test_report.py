from riskpatch.report import ComponentReport, StackReport, render_markdown
from riskpatch.rules import CveVerdict


def _cve(**kwargs) -> CveVerdict:
    base = dict(
        summary="s",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        attack_vector="NETWORK",
        cwe=[],
        kev=False,
        references=[],
        patched_versions=["1.25.7"],
        source="nvd",
        level="critical",
        action="Fix this week",
        exposure="internet",
        exposure_assumed=True,
        reachability="external",
        one_line="affected",
    )
    base.update(kwargs)
    return CveVerdict(**base)


def test_render_markdown_is_actionable_english():
    report = StackReport(
        generated_at="2026-10-30T00:00:00Z",
        stale=False,
        inventory_name="local-laptop",
        environment="unknown",
        highest="critical",
        action="Fix this week",
        hostname="example-host",
        os_name="Pop!_OS",
        os_version="22.04",
        exposure="unknown",
        tech_stack=["go 1.18.1"],
        components=[
            ComponentReport(
                id="go",
                name="go",
                version="1.18.1",
                ecosystem="Go",
                rollup="critical",
                action="Fix this week",
                cves=[
                    _cve(cve_id="CVE-KEV-1", kev=True, level="high", action="Fix this week", cvss_score=7.5, cvss_severity="HIGH"),
                    _cve(cve_id="CVE-CRIT-1", level="critical"),
                    *[_cve(cve_id=f"CVE-HIGH-{i}", level="high", action="Fix this week", cvss_score=7.5, cvss_severity="HIGH") for i in range(6)],
                    _cve(cve_id="CVE-LOW-1", level="low", action="Document and monitor", cvss_score=3.1, cvss_severity="LOW", patched_versions=[]),
                ],
            )
        ],
    )
    md = render_markdown(report)
    assert md.startswith("# RiskPatch posture report - local-laptop")
    assert "Laporan" not in md
    assert "Observed host (from collector)" in md
    assert "Pop!_OS 22.04" in md
    assert "example-host" in md
    assert "What to do this week" in md
    assert "upgrade `go` from `1.18.1` to **`1.25.7`**" in md
    assert "CVE-KEV-1" in md and "KEV" in md
    assert "CVE-CRIT-1" in md
    assert "minimum safe 1.25.7" in md
    assert "additional High CVE" in md
    assert "CVE-LOW-1" not in md
    assert "1 Low" in md
