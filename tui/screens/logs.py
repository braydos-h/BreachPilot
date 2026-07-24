"""Logs screen — color-coded audit trail with event type filtering."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Select, Static, Label
from textual import on

from tui.services import ServiceRegistry
from tui.themes import COLORS
from tui.widgets import HelpFooter


EVENT_TYPES = [
    ("All Events", ""),
    ("mission_created", "mission_created"),
    ("task_created", "task_created"),
    ("tool_executed", "tool_executed"),
    ("tool_blocked", "tool_blocked"),
    ("finding", "finding"),
    ("scope_check", "scope_check"),
    ("status_changed", "status_changed"),
    ("loop_complete", "loop_complete"),
    ("agent_started", "agent_started"),
    ("agent_complete", "agent_complete"),
    ("agent_failed", "agent_failed"),
    ("agent_blocked", "agent_blocked"),
    ("critic_decision", "critic_decision"),
    ("reflection_output", "reflection_output"),
    ("blackboard_updated", "blackboard_updated"),
]


class LogsScreen(Screen):
    """Audit log browser with filtering."""

    BINDINGS = [
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="logs-error")
        with Horizontal(id="logs-filter"):
            yield Select(EVENT_TYPES, prompt="Event", id="logs-event-filter")
        yield Label("", id="logs-count")
        yield DataTable(id="logs-table", cursor_type="row")
        yield HelpFooter(id="logs-footer")

    def on_mount(self) -> None:
        table = self.query_one("#logs-table", DataTable)
        table.add_columns("Time", "Event", "Message")
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#logs-error", Static)
        footer = self.query_one("#logs-footer", HelpFooter)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            footer.show_default()
            return
        err.update("")

        # Event-type filter: the #logs-event-filter Select fires _on_filter ->
        # _load_data on change, so read its value here and narrow the query.
        # "All Events" maps to value "" (and an unselected Select yields
        # Select.BLANK); both mean no filter.
        event_filter = self.query_one("#logs-event-filter", Select).value
        event_type = event_filter if isinstance(event_filter, str) and event_filter else None

        with svc.db.connection() as conn:
            if event_type:
                cur = conn.execute(
                    "SELECT * FROM audit_logs WHERE mission_id=? AND event_type=? "
                    "ORDER BY created_at DESC LIMIT 200",
                    (svc.mission_id, event_type),
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM audit_logs WHERE mission_id=? ORDER BY created_at DESC LIMIT 200",
                    (svc.mission_id,),
                )
            rows = [dict(r) for r in cur.fetchall()]

        self.query_one("#logs-count", Label).update(
            f"  [bold]{len(rows)}[/] recent log entries"
        )

        table = self.query_one("#logs-table", DataTable)
        table.clear()

        for r in rows[:150]:
            ts = (r.get("created_at", "") or "")[11:19]
            evt = r.get("event_type", "?")
            msg = (r.get("message", "") or "")[:80]

            evt_color = COLORS["muted"]
            if "blocked" in evt or "error" in evt.lower():
                evt_color = COLORS["danger"]
            elif "created" in evt or "started" in evt:
                evt_color = COLORS["info"]
            elif "complete" in evt or "completed" in evt:
                evt_color = COLORS["safe"]

            table.add_row(f"[dim]{ts}[/]", f"[{evt_color}]{evt}[/]", msg)

        footer.show_context("r Refresh", "Esc Back")

    def refresh_data(self) -> None:
        self._load_data()

    @on(Select.Changed, "#logs-event-filter")
    def _on_filter(self) -> None:
        self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc
