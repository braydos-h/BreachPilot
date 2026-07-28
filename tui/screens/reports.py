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
        """Preview the most recent HTML report for the selected finding target.

        There is no dedicated viewer widget; instead we surface a string render
        of the HTML report path (and a short snippet) in the error/static pane.
        The HTML is produced by ``EnhancedReportGenerator`` under
        ``<workspace>/enhanced/*.html``; the legacy markdown report lives under
        ``<workspace>/reports/<finding_id>.md``. We prefer the newest HTML and
        fall back to the markdown path so the operator always gets a pointer.
        """
        target = self._selected_target()
        html_path = self._latest_html_report()
        md_path = self._legacy_md_path(target)
        pane = self.query_one("#rpt-error", Static)
        if html_path is not None:
            pane.update(
                f"[bold green]HTML report ready[/]\n[dim]{html_path}[/]\n"
                "[dim]Open the file in a browser to view the full report.[/]"
            )
            self.notify(f"HTML report: {html_path.name}", severity="information")
        elif md_path is not None:
            pane.update(
                f"[bold yellow]Markdown report only[/]\n[dim]{md_path}[/]\n"
                "[dim]Generate an HTML report from the enhanced generator for a richer view.[/]"
            )
            self.notify("Markdown report available (no HTML yet)", severity="information")
        else:
            pane.update("[bold red]No report file found.[/] Press R to generate one.")
            self.notify("No report file found yet", severity="warning")

    def _selected_target(self) -> str:
        """Best-effort: read the asset column of the currently highlighted row."""
        try:
            table = self.query_one("#rpt-table", DataTable)
            coord = table.cursor_coordinate
            if coord is None:
                return ""
            row_key = table.coordinate_to_row_key(coord)
            if row_key is None:
                return ""
            # Column 3 is "Asset" (see on_mount).
            try:
                cell = table.get_cell_at(coord)
            except Exception:
                return ""
            return str(cell or "")
        except Exception:
            return ""

    def _latest_html_report(self):
        """Return the newest ``*.html`` under the enhanced reports dir, or None."""
        try:
            svc = self._get_services()
            ws = getattr(svc, "workspace_root", None)
            if ws is None:
                return None
            from pathlib import Path
            enhanced = Path(ws) / "enhanced"
            if not enhanced.exists():
                return None
            candidates = sorted(enhanced.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
            return candidates[0] if candidates else None
        except Exception:
            return None

    def _legacy_md_path(self, target: str):
        """Return the legacy markdown report path for a target/finding, or None."""
        try:
            svc = self._get_services()
            ws = getattr(svc, "workspace_root", None)
            if ws is None:
                return None
            from pathlib import Path
            reports = Path(ws) / "reports"
            if not reports.exists():
                return None
            candidates = sorted(reports.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
            return candidates[0] if candidates else None
        except Exception:
            return None

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
