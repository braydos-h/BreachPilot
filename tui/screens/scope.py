"""Scope screen — manage allow/deny rules, inline scope tester, forbidden actions."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label, Static,
)
from textual import on

from tui.services import ServiceRegistry
from tui.widgets import HelpFooter, ScopeCheckPreview


class ScopeScreen(Screen):
    """Scope management — view rules, test assets, manage forbidden actions."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="scope-error")
        yield Label("[bold]Scope Tester[/] — enter an asset to check scope:", id="scope-tester-label")
        with Horizontal(id="scope-tester-row"):
            yield Input(placeholder="api.example.com", id="scope-tester-input")
            yield Button("Check", id="scope-tester-btn", variant="primary")
        yield ScopeCheckPreview(id="scope-check-result")
        yield Label("[bold]Scope Rules[/]", id="scope-rules-label")
        with Horizontal(id="scope-tables"):
            yield DataTable(id="scope-allow-table", cursor_type="row")
            yield DataTable(id="scope-deny-table", cursor_type="row")
        yield Label("[bold]Forbidden Actions[/]", id="scope-forbidden-label")
        yield Static("", id="scope-forbidden-list")
        yield HelpFooter(id="scope-footer")

    def on_mount(self) -> None:
        self._build_tables()
        self._load_data()

    def _build_tables(self) -> None:
        allow = self.query_one("#scope-allow-table", DataTable)
        allow.add_columns("Rule", "Type")
        deny = self.query_one("#scope-deny-table", DataTable)
        deny.add_columns("Rule", "Type")

    def _load_data(self) -> None:
        svc = self._get_services()
        if not svc.has_active_mission:
            self.query_one("#scope-error", Static).update(
                "[bold red]No active mission.[/] Create one first."
            )
            return

        self.query_one("#scope-error", Static).update("")
        scope = svc.scope.list_scope()

        allow = self.query_one("#scope-allow-table", DataTable)
        allow.clear()
        for r in scope.get("allow", []):
            allow.add_row(r, _guess_type(r))

        deny = self.query_one("#scope-deny-table", DataTable)
        deny.clear()
        for r in scope.get("deny", []):
            deny.add_row(r, _guess_type(r))

        forbidden = svc.scope.list_forbidden_actions()
        self.query_one("#scope-forbidden-list", Static).update(
            "  " + "  ".join(f"[red bold]X[/] [dim]{f}[/dim]" for f in forbidden[:6])
            + ("  ..." if len(forbidden) > 6 else "")
        )

        footer = self.query_one("#scope-footer", HelpFooter)
        footer.show_context("Enter Check Scope", "r Refresh", "Esc Back")

    @on(Button.Pressed, "#scope-tester-btn")
    @on(Input.Submitted, "#scope-tester-input")
    def _on_check(self) -> None:
        svc = self._get_services()
        if not svc.has_active_mission:
            return
        asset = self.query_one("#scope-tester-input", Input).value.strip()
        if not asset:
            return
        result = svc.check_scope(asset, "recon", "manual_scope_check", "low")
        preview = self.query_one("#scope-check-result", ScopeCheckPreview)
        preview.show_result(result)

    def refresh_data(self) -> None:
        self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc


def _guess_type(asset: str) -> str:
    if asset.startswith("*."):
        return "wildcard"
    if "/" in asset and any(c.isdigit() for c in asset[:3]):
        return "cidr"
    parts = asset.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    return "domain"
