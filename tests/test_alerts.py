import json
from pathlib import Path

import httpx

from riskpatch.alerts import changed, emit
from riskpatch.pipeline import analyze
from riskpatch.inventory import load_inventory
from riskpatch.report import StackReport, write_reports


def test_webhook_failure_keeps_report(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RISKPATCH_OFFLINE", "1")
    inventory = load_inventory(Path("inventory/stack.example.yaml"))
    report = analyze(inventory, tmp_path / "cache", httpx.Client(), False)
    write_reports(report, tmp_path)
    def boom(*args, **kwargs):
        raise httpx.ConnectError("down")
    client = httpx.Client()
    client.post = boom
    emit(report, ["laporan pertama"], tmp_path, "http://127.0.0.1:9/hook", client)
    assert (tmp_path / "latest.md").exists()
    lines = (tmp_path / "alerts.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert json.loads(lines[-1])["reasons"] == ["laporan pertama"]


def test_first_empty_report_does_not_alert():
    report = StackReport(
        generated_at="t",
        stale=False,
        inventory_name="a",
        environment="dev",
        highest="informasional",
        action="dokumentasikan",
        components=[],
    )
    assert changed(None, report) == []


def test_bad_webhook_is_skipped(tmp_path: Path):
    report = StackReport(
        generated_at="t",
        stale=False,
        inventory_name="a",
        environment="dev",
        highest="tinggi",
        action="segera",
        components=[],
    )
    emit(report, ["CVE baru X"], tmp_path, "file:///tmp/x", httpx.Client())
    assert "CVE baru X" in (tmp_path / "alerts.jsonl").read_text(encoding="utf-8")


def test_changed_detects_new_cve():
    left = StackReport(
        generated_at="t",
        stale=False,
        inventory_name="a",
        environment="dev",
        highest="low",
        action="Document and monitor",
        components=[],
    )
    right = left.model_copy(update={"highest": "high"})
    assert changed(left, right)
