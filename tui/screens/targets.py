"""Targets screen — discovered assets from graph + memory."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Static
from textual import on

from tui.services import ServiceRegistry
from tui.widgets import HelpFooter


class TargetsScreen(Screen):
    """Show discovered assets (domains, IPs, services) from target graph."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="tg-error")
        yield DataTable(id="tg-table", cursor_type="row")
        yield HelpFooter(id="tg-footer")

    def on_mount(self) -> None:
        table = self.query_one("#tg-table", DataTable)
        table.add_columns("Asset", "Type", "In Scope", "Services/Tech", "Score")
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#tg-error", Static)
        footer = self.query_one("#tg-footer", HelpFooter)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            footer.show_default()
            return
        err.update("")

        data = svc.graph.query_graph(limit=100)
        nodes = data.get("nodes", [])

        table = self.query_one("#tg-table", DataTable)
        table.clear()

        if not nodes:
            table.add_row(
                "[dim]No assets discovered[/]",
                "", "", "", ""
            )
            footer.show_context("r Refresh", "Esc Back")
            return

        for n in nodes[:60]:
            ntype = n.get("type", "?")
            value = str(n.get("value", ""))[:40]
            scope_check = "N/A"
            if value and svc.scope:
                try:
                    sr = svc.scope.check_scope(value, "recon", "view", "low")
                    scope_check = "YES" if sr.allowed else "NO"
                except Exception:
                    scope_check = "?"
            sc = scope_check

            # Interest score based on node type
            score_map = {"permission_boundary": "HIGH", "finding": "HIGH",
                         "endpoint": "MED", "parameter": "MED",
                         "service": "MED", "host": "LOW", "domain": "LOW"}
            score = score_map.get(ntype, "—")

            table.add_row(value, ntype, sc, "", score)

        footer.show_context("r Refresh", "Esc Back")

    def refresh_data(self) -> None:
        self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc
