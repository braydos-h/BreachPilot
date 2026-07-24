"""Reports screen — list, preview, and export generated reports."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Static, Label
from textual import on

from tui.services import ServiceRegistry
from tui.widgets import HelpFooter


class ReportsScreen(Screen):
    """View and export generated reports."""

    BINDINGS = [
        Binding("R", "generate_report", "Generate"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="rpt-error")
        yield Static("[bold]Reports[/] — findings ready for export", id="rpt-header")
        yield DataTable(id="rpt-table", cursor_type="row")
        yield Label("", id="rpt-count")
        yield HelpFooter(id="rpt-footer")

    def on_mount(self) -> None:
        table = self.query_one("#rpt-table", DataTable)
        table.add_columns("ID", "Severity", "Title", "Asset", "Status")
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#rpt-error", Static)
        footer = self.query_one("#rpt-footer", HelpFooter)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            footer.show_default()
            return
        err.update("")

        ready = svc.verifier.list_report_ready()
        validated = svc.verifier.list_validated()

        table = self.query_one("#rpt-table", DataTable)
        table.clear()

        all_items = ready + validated
        if not all_items:
            table.add_row("", "", "[dim]No report-ready findings[/]", "", "")
            self.query_one("#rpt-count", Label).update("  [dim]No reports available.[/]")
            footer.show_context("R Generate Report", "Esc Back")
            return

        for f in all_items:
            sev = _sev_short(f.get("impact_score", 0))
            fid = f.get("finding_id", "?")
            table.add_row(
                fid[:16],
                sev,
                f.get("title", "?")[:50],
                f.get("affected_asset", "?")[:24],
                f.get("status", "?"),
            )

        self.query_one("#rpt-count", Label).update(
            f"  [bold]{len(ready)}[/] report-ready | [bold]{len(validated)}[/] validated (pending)"
        )

        footer.show_context(
            "Enter Preview", "R Generate Report", "Esc Back"
        )

    @on(DataTable.RowSelected)
    def _on_row(self) -> None:
        pass  # Future: open preview

    def action_generate_report(self) -> None:
        svc = self._get_services()
        ready = svc.verifier.list_report_ready()
        if ready:
            fid = ready[0]["finding_id"]
            try:
                r = svc.reporter.generate_report(fid)
                self.notify(f"Report generated: {fid}.md", severity="information")
            except ValueError as exc:
                self.notify(str(exc), severity="error")
        else:
            self.notify("No report-ready findings. Validate first.", severity="warning")

    def refresh_data(self) -> None:
        self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc


def _sev_short(score: int) -> str:
    if score >= 80: return "CRIT"
    if score >= 50: return "HIGH"
    if score >= 30: return "MED"
    if score >= 10: return "LOW"
    return "INFO"
