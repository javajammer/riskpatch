from riskpatch.textclip import best_summary, clip_text, operator_brief


def test_clip_text_keeps_sentence():
    text = "First sentence. " + ("word " * 400) + "End."
    out = clip_text(text, 80)
    assert out.endswith(".")
    assert "First sentence." in out
    assert len(out) <= 80


def test_best_summary_prefers_full_raw():
    raw = '{"descriptions":[{"lang":"en","value":"In the Linux kernel, the following vulnerability has been resolved: ipv4 free after RCU."}]}'
    stored = "In the Linux kernel, the following vulnerability has been resolved:\nipv4: free inet_opt"
    got = best_summary(stored, raw)
    assert "RCU" in got
    assert not got.endswith("inet_opt")


def test_operator_brief_english_sections():
    brief = operator_brief(
        cve_id="CVE-2026-98432",
        summary="In the Linux kernel, ipv4 SYN handling was fixed.",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        attack_vector="NETWORK",
        kev=False,
        cwe=["CWE-416"],
        patched_versions=[],
        products=["linux linux kernel (>= 6.1)"],
        findings=[],
    )
    assert brief["affected"] and brief["mitigation"] and brief["corrective"] and brief["preventive"]
    blob = " ".join(sum(brief.values(), []))
    assert "CVE-2026-98432" in blob or "Linux" in blob
    assert "exploit" not in blob.lower() or "not an exploit" in blob.lower()
