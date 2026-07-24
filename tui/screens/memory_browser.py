"""Memory browser screen — browse all memory types with filtering."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Select, Input, Static, Label
from textual import on

from tui.services import ServiceRegistry
from tui.themes import COLORS
from tui.widgets import HelpFooter


MEM_TYPES = [
    ("All Types", ""),
    ("target", "target"),
    ("hypothesis", "hypothesis"),
    ("dead_end", "dead_end"),
    ("episodic", "episodic"),
    ("semantic", "semantic"),
    ("working", "working"),
]


class MemoryBrowserScreen(Screen):
    """Browse all memory entries with filtering by type/target."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="mem-error")
        with Horizontal(id="mem-filter"):
            yield Select(MEM_TYPES, prompt="Type", id="mem-type-filter")
            yield Input(placeholder="Target filter...", id="mem-target-filter")
        yield Label("", id="mem-count")
        yield DataTable(id="mem-table", cursor_type="row")
        yield HelpFooter(id="mem-footer")

    def on_mount(self) -> None:
        table = self.query_one("#mem-table", DataTable)
        table.add_columns("Type", "Target", "Fact", "Confidence")
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#mem-error", Static)
        footer = self.query_one("#mem-footer", HelpFooter)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            footer.show_default()
            return
        err.update("")

        target = self.query_one("#mem-target-filter", Input).value.strip()
        mem_type = self.query_one("#mem-type-filter", Select).value or None

        items = svc.memory.retrieve(target=target or "", memory_type=mem_type, limit=100)
        self.query_one("#mem-count", Label).update(
            f"  [bold]{len(items)}[/] memory entries"
        )

        table = self.query_one("#mem-table", DataTable)
        table.clear()

        for m in items:
            mt = m.get("memory_type", "?")
            mt_color = {
                "target": COLORS["info"], "hypothesis": COLORS["warning"],
                "dead_end": COLORS["danger"], "working": COLORS["safe"],
                "semantic": COLORS["accent"],
            }.get(mt, COLORS["muted"])

            table.add_row(
                f"[{mt_color}]{mt}[/]",
                (m.get("target", "") or "")[:24],
                (m.get("fact", "") or "")[:60],
                f"{m.get('confidence', 0):.0%}",
            )

        footer.show_context("r Refresh", "Esc Back")

    def refresh_data(self) -> None:
        self._load_data()

    @on(Select.Changed, "#mem-type-filter")
    @on(Input.Submitted, "#mem-target-filter")
    def _on_filter(self) -> None:
        self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc
