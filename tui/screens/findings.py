"""Findings screen — color-coded DataTable of all findings by status."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Select, Static, Label
from textual import on

from tui.screens.finding_detail import FindingDetailScreen
from tui.services import ServiceRegistry
from tui.themes import STATUS_ICONS
from tui.widgets import HelpFooter


class FindingsScreen(Screen):
    """Browse, validate, and reject candidate security findings."""

    BINDINGS = [
        Binding("v", "validate_selected", "Validate"),
        Binding("r", "reject_selected", "Reject"),
        Binding("R", "generate_report", "Report"),
        Binding("m", "missing_evidence", "Missing Ev"),
        Binding("escape", "pop_screen", "Back"),
        Binding("slash", "focus_search", "Search"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="findings-error")
        with Horizontal(id="findings-filter"):
            yield Select(
                [("All Statuses", ""), ("candidate", "candidate"),
                 ("needs_validation", "needs_validation"), ("validated", "validated"),
                 ("report_ready", "report_ready"), ("rejected", "rejected")],
                prompt="Status", id="findings-status-filter",
            )
        yield Label("", id="findings-count")
        yield DataTable(id="findings-table", cursor_type="row")
        yield HelpFooter(id="findings-footer")

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("St", "Sev", "Vuln Class", "Title", "Asset", "Confidence")
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#findings-error", Static)
        footer = self.query_one("#findings-footer", HelpFooter)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            footer.show_default()
            return
        err.update("")

        all_findings = self._current_findings()
        self.query_one("#findings-count", Label).update(
            f"  Total: [bold]{len(all_findings)}[/] findings"
        )

        table = self.query_one("#findings-table", DataTable)
        table.clear()

        if not all_findings:
            table.add_row("", "", "[dim]No findings yet[/]", "", "", "")
            footer.show_context("Enter Detail", "Esc Back")
            return

        for f in all_findings:
            status = f.get("status", "?")
            status_icon = STATUS_ICONS.get(status, "?")
            sev_label = _sev_label(f.get("impact_score", 0))
            conf = f"{f.get('confidence', 0):.0%}"

            table.add_row(
                status_icon,
                sev_label,
                f.get("vuln_class", "?")[:20],
                f.get("title", "Untitled")[:50],
                f.get("affected_asset", "?")[:24],
                conf,
            )

        footer.show_context(
            "Enter Open", "v Validate", "r Reject", "R Generate Report", "Esc Back"
        )

    @on(DataTable.RowSelected)
    def _on_row_select(self, event: DataTable.RowSelected) -> None:
        table = self.query_one("#findings-table", DataTable)
        svc = self._get_services()
        if not svc.has_active_mission:
            return
        all_f = self._current_findings()
        # Get the row index from the cursor_row, not row_key
        row_idx = event.cursor_row
        if 0 <= row_idx < len(all_f):
            fid = all_f[row_idx].get("finding_id", "")
            if fid:
                self.app.push_screen(FindingDetailScreen(fid))

    def action_validate_selected(self) -> None:
        svc = self._get_services()
        table = self.query_one("#findings-table", DataTable)
        all_f = self._current_findings()
        if table.cursor_row < len(all_f):
            fid = all_f[table.cursor_row].get("finding_id", "")
            r = svc.verifier.validate_finding(fid)
            if r.get("valid"):
                self.notify(f"Finding {fid} validated.", severity="information")
            else:
                self.notify(f"Validation issues: {', '.join(r.get('missing', []))}", severity="warning")
            self._load_data()

    def action_reject_selected(self) -> None:
        svc = self._get_services()
        all_f = self._current_findings()
        table = self.query_one("#findings-table", DataTable)
        if all_f and 0 <= table.cursor_row < len(all_f):
            fid = all_f[table.cursor_row].get("finding_id", "")
            if fid:
                svc.verifier.reject(fid, "Rejected by user.")
                self.notify(f"Finding {fid} rejected.")
                self._load_data()

    def action_generate_report(self) -> None:
        svc = self._get_services()
        all_f = self._current_findings()
        table = self.query_one("#findings-table", DataTable)
        if all_f and 0 <= table.cursor_row < len(all_f):
            fid = all_f[table.cursor_row].get("finding_id", "")
            if fid:
                try:
                    svc.reporter.generate_report(fid)
                    self.notify(f"Report generated: {fid}.md", severity="information")
                except (ValueError, OSError) as exc:
                    self.notify(str(exc), severity="error")

    def action_missing_evidence(self) -> None:
        svc = self._get_services()
        all_f = self._current_findings()
        table = self.query_one("#findings-table", DataTable)
        if all_f and 0 <= table.cursor_row < len(all_f):
            fid = all_f[table.cursor_row].get("finding_id", "")
            if fid:
                result = svc.verifier.mark_needs_validation(fid, ["More validation required."])
                self.notify(result)
                self._load_data()

    def refresh_data(self) -> None:
        self._load_data()

    @on(Select.Changed, "#findings-status-filter")
    def _on_filter(self) -> None:
        self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc

    def _current_findings(self) -> list[dict]:
        """Findings for the active mission, narrowed by the status filter.

        Used by BOTH the table render and the row-indexed actions (validate /
        reject / open-detail) so a filtered view and its row indices always refer
        to the same list. Without this, selecting row 3 in a filtered table would
        map to the wrong finding in an unfiltered ``list_all()``.
        """
        svc = self._get_services()
        if not svc.has_active_mission:
            return []
        status = ""
        try:
            status = self.query_one("#findings-status-filter", Select).value or ""
        except Exception:
            status = ""
        return svc.verifier.list_all(status=status)


def _sev_label(score: int) -> str:
    if score >= 80:
        return "CRIT"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MED"
    if score >= 10:
        return "LOW"
    return "INFO"
