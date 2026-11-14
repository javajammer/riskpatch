from pathlib import Path

from riskpatch.pipeline import _read_previous
from riskpatch.report import StackReport
from riskpatch.service import should_mark_fetched


def test_corrupt_previous_does_not_crash(tmp_path: Path):
    (tmp_path / "latest.json").write_text("{", encoding="utf-8")
    assert _read_previous(tmp_path) is None


def test_stale_or_errors_do_not_mark_fresh():
    report = StackReport(
        generated_at="t",
        stale=True,
        inventory_name="a",
        environment="dev",
        highest="informational",
        action="Document and monitor",
        components=[],
        errors=["offline"],
    )
    assert should_mark_fetched(report) is False
    assert should_mark_fetched(report.model_copy(update={"stale": False, "errors": []})) is True
