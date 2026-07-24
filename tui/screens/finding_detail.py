"""Finding Detail screen — full view + 10-point validation checklist."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button, Footer, Header, Label, Static, Checkbox,
)
from textual import on

from tui.services import ServiceRegistry
from tui.themes import COLORS
from tui.widgets import HelpFooter


class FindingDetailScreen(Screen):
    """Detailed finding view with validation checklist.

    Shows: title, vuln_class, asset, endpoint, summary, impact, confidence,
    status, evidence, repro steps. Offers validate/reject/report actions.
    """

    BINDINGS = [
        Binding("v", "validate", "Validate"),
        Binding("r", "reject_finding", "Reject"),
        Binding("R", "generate_report", "Report"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def __init__(self, finding_id: str) -> None:
        super().__init__()
        self._finding_id = finding_id

    def compose(self) -> ComposeResult:
        yield Static("", id="fd-error")
        with VerticalScroll(id="fd-body"):
            yield Static("[bold]FINDING DETAIL[/]", id="fd-title")
            yield Static("Loading...", id="fd-content")
            yield Static("\n[bold]VALIDATION CHECKLIST[/]", id="fd-checklist-title")
            yield Static("", id="fd-checklist")
        with Horizontal(id="fd-actions"):
            yield Button("Validate (v)", id="btn-validate", variant="primary")
            yield Button("Reject (r)", id="btn-reject", variant="error")
            yield Button("Generate Report (R)", id="btn-report", variant="success")
            yield Button("Needs Validation (n)", id="btn-needs-val", variant="warning")
        yield HelpFooter(id="fd-footer")

    def on_mount(self) -> None:
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#fd-error", Static)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            return
        err.update("")

        finding = svc.verifier.get_finding(self._finding_id)
        if not finding:
            err.update(f"[bold red]Finding {self._finding_id} not found.[/]")
            return

        severity = _sev_label(finding.get("impact_score", 0))
        sev_color = {"CRITICAL": COLORS["danger"], "HIGH": COLORS["critical"],
                     "MEDIUM": COLORS["warning"], "LOW": COLORS["low"],
                     "INFO": COLORS["muted"]}.get(severity, COLORS["muted"])

        status = finding.get("status", "?")
        lines = [
            f"[bold]Title:[/]         {finding.get('title', 'Untitled')[0:80]}",
            f"[bold]Vuln Class:[/]    {finding.get('vuln_class', 'Unclassified')}",
            f"[bold]Affected:[/]      {finding.get('affected_asset', 'N/A')}",
            f"[bold]Endpoint:[/]      {finding.get('affected_endpoint', 'N/A')}",
            f"[bold]Severity:[/]      [{sev_color}]{severity}[/] (impact: {finding.get('impact_score', 0)}/100)",
            f"[bold]Confidence:[/]    {finding.get('confidence', 0):.0%}",
            f"[bold]Status:[/]        {status}",
            "",
            f"[bold]Summary:[/]",
            f"  {finding.get('summary', 'No summary.')}",
            "",
            f"[bold]Impact:[/]",
            f"  {finding.get('impact', 'Impact not assessed.')}",
            "",
            f"[bold]Evidence:[/] {', '.join(finding.get('evidence_refs', [])) or '[dim]none[/]'}",
        ]

        repro = finding.get("reproduction_steps", [])
        if repro:
            lines.append("")
            lines.append("[bold]Reproduction Steps:[/]")
            for i, s in enumerate(repro, 1):
                lines.append(f"  {i}. {s}")

        missing = finding.get("missing_validation", [])
        if missing:
            lines.append("")
            lines.append(f"[yellow bold]Missing Validation:[/] {', '.join(missing)}")

        content = self.query_one("#fd-content", Static)
        content.update("\n".join(lines))

        # Build validation checklist
        val_result = svc.verifier.validate_finding(
            self._finding_id, scope_gate=svc.scope, evidence_store=svc.evidence
        )
        checks = val_result.get("checks", {})

        check_items = [
            ("in_scope", "Asset is in scope"),
            ("has_evidence", "Evidence exists"),
            ("has_summary", "Adequate summary (>20 chars)"),
            ("has_impact", "Impact statement present"),
            ("has_vuln_class", "Vulnerability classified"),
            ("has_reproduction_steps", "Reproduction steps documented"),
        ]

        check_lines = []
        for key, label in check_items:
            passed = checks.get(key, False)
            mark = "[green]Y[/]" if passed else "[red]X[/]"
            check_lines.append(f"  [{mark}] [{'dim' if not passed else ''}]{label}[/]")

        if val_result.get("valid"):
            check_lines.append("")
            check_lines.append("  [green bold]All checks passed — ready to validate.[/]")

        self.query_one("#fd-checklist", Static).update("\n".join(check_lines))

        footer = self.query_one("#fd-footer", HelpFooter)
        footer.show_context("v Validate", "r Reject", "R Gen Report", "n Needs Val", "Esc Back")

    @on(Button.Pressed, "#btn-validate")
    def action_validate(self) -> None:
        svc = self._get_services()
        if svc.has_active_mission:
            result = svc.verifier.validate_finding(
                self._finding_id, scope_gate=svc.scope, evidence_store=svc.evidence
            )
            if result.get("valid"):
                svc.verifier.mark_report_ready(self._finding_id)
                self.notify(f"Finding {self._finding_id} marked report-ready!", severity="information")
            else:
                self.notify(f"Missing: {', '.join(result.get('missing', []))}", severity="warning")
            self._load_data()

    @on(Button.Pressed, "#btn-reject")
    def action_reject_finding(self) -> None:
        svc = self._get_services()
        if svc.has_active_mission:
            svc.verifier.reject(self._finding_id, "Rejected by user review.")
            self.notify(f"Finding {self._finding_id} rejected.")
            self._load_data()

    @on(Button.Pressed, "#btn-report")
    def action_generate_report(self) -> None:
        svc = self._get_services()
        try:
            report = svc.reporter.generate_report(self._finding_id)
            self.notify(f"Report generated for {self._finding_id}!", severity="information")
        except ValueError as exc:
            self.notify(str(exc), severity="error")

    @on(Button.Pressed, "#btn-needs-val")
    def action_needs_validation(self) -> None:
        svc = self._get_services()
        if svc.has_active_mission:
            svc.verifier.mark_needs_validation(self._finding_id, ["More validation required."])
            self.notify(f"Finding {self._finding_id} marked needs_validation.")
            self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc


def _sev_label(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "INFO"
