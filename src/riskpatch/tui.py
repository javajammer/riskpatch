from __future__ import annotations

import os
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Header, Static, TabbedContent, TabPane

from riskpatch.inventory import load_inventory
from riskpatch.report import StackReport
from riskpatch.service import paths


class RiskPatchApp(App):
    TITLE = "RiskPatch"
    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
        Binding("q", "quit", "Exit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Summary", id="summary"):
                yield Static(id="summary-body")
            with TabPane("Components", id="components"):
                yield DataTable(id="components-table")
            with TabPane("CVE", id="cves"):
                yield DataTable(id="cve-table")
                yield Static(id="cve-detail")
            with TabPane("Alert", id="alerts"):
                yield Static(id="alert-body")
        yield Footer()

    def on_mount(self) -> None:
        components = self.query_one("#components-table", DataTable)
        components.add_columns("id", "version", "rollup", "action")
        cves = self.query_one("#cve-table", DataTable)
        cves.add_columns("component", "cve", "level", "action", "kev")
        cves.cursor_type = "row"
        self.reload()

    def reload(self) -> None:
        inventory, reports, _cache = paths()
        summary = self.query_one("#summary-body", Static)
        errors = _validate(inventory)
        report = _load_report(reports)
        if report is None:
            summary.update("No report yet. Service has not written latest.md.\n" + "\n".join(errors))
        else:
            summary.update(
                "\n".join(
                    [
                        f"Inventory: {report.inventory_name} ({report.environment})",
                        f"Time: {report.generated_at}",
                        f"Highest risk: {report.highest}",
                        f"Action: {report.action}",
                        f"Stale: {'yes' if report.stale else 'no'}",
                        *errors,
                        *report.errors,
                    ]
                )
            )
        self._fill_tables(report)
        alerts = reports / "alerts.jsonl"
        text = alerts.read_text(encoding="utf-8") if alerts.exists() else "No alerts yet."
        self.query_one("#alert-body", Static).update(text[-4000:])

    def _fill_tables(self, report: StackReport | None) -> None:
        components = self.query_one("#components-table", DataTable)
        cves = self.query_one("#cve-table", DataTable)
        components.clear()
        cves.clear()
        self._rows = []
        if report is None:
            return
        for component in report.components:
            components.add_row(component.id, component.version, component.rollup, component.action)
            for cve in component.cves:
                self._rows.append(cve)
                cves.add_row(component.id, cve.cve_id, cve.level, cve.action, "yes" if cve.kev else "no")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "cve-table":
            return
        if event.cursor_row >= len(self._rows):
            return
        cve = self._rows[event.cursor_row]
        self.query_one("#cve-detail", Static).update(
            "\n".join(
                [
                    cve.one_line,
                    f"Reachability: {cve.reachability}",
                    f"Exposure: {cve.exposure}",
                    f"Raises: {', '.join(cve.raises) or '-'}",
                    f"Lowers: {', '.join(cve.lowers) or '-'}",
                    cve.narrative,
                ]
            )
        )

    def action_refresh(self) -> None:
        _inventory, reports, _cache = paths()
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "refresh.request").write_text("1", encoding="utf-8")
        self.query_one("#summary-body", Static).update("Refresh requested. Service will fetch.")


def _validate(path: Path) -> list[str]:
    if not path.exists():
        return [f"Template not found: {path}"]
    try:
        load_inventory(path)
    except Exception as exc:
        return [f"Template invalid: {exc}"]
    return []


def _load_report(reports: Path) -> StackReport | None:
    path = reports / "latest.json"
    if not path.exists():
        return None
    return StackReport.model_validate_json(path.read_text(encoding="utf-8"))


def run_tui() -> None:
    os.environ.setdefault("RISKPATCH_INVENTORY", "/data/inventory/stack.yaml")
    RiskPatchApp().run()
