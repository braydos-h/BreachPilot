"""Tasks screen — sortable/filterable task DataTable with keyboard actions."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Label, Select, Static,
)
from textual import on

from tui.screens.execution import ExecutionScreen
from tui.screens.task_detail import TaskDetailScreen
from tui.services import ServiceRegistry
from tui.widgets import HelpFooter


PHASE_OPTIONS = [
    ("All Phases", ""),
    ("recon", "recon"),
    ("analysis", "analysis"),
    ("test", "test"),
    ("validate", "validate"),
    ("report", "report"),
]

STATUS_OPTIONS = [
    ("All Statuses", ""),
    ("pending", "pending"),
    ("running", "running"),
    ("blocked", "blocked"),
    ("complete", "complete"),
    ("failed", "failed"),
]


class TasksScreen(Screen):
    """Task queue — view, filter, execute, block, complete tasks."""

    BINDINGS = [
        Binding("x", "execute_task", "Execute"),
        Binding("b", "block_task", "Block"),
        Binding("c", "complete_task", "Complete"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="tasks-error")
        with Horizontal(id="tasks-filter"):
            yield Select(PHASE_OPTIONS, prompt="Phase", id="tasks-phase-filter")
            yield Select(STATUS_OPTIONS, prompt="Status", id="tasks-status-filter")
            yield Input(placeholder="Search...", id="tasks-search")
        yield Label("", id="tasks-counts")
        yield DataTable(id="tasks-table", cursor_type="row")
        yield HelpFooter(id="tasks-footer")

    def on_mount(self) -> None:
        table = self.query_one("#tasks-table", DataTable)
        table.add_columns("ID", "Pri", "Phase", "Objective", "Target", "Status", "Risk")
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#tasks-error", Static)
        footer = self.query_one("#tasks-footer", HelpFooter)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            footer.show_default()
            return
        err.update("")

        counts = svc.tasks.count_by_status()
        parts = []
        if counts.get("pending"):
            parts.append(f"[bold]{counts['pending']} pending[/]")
        if counts.get("running"):
            parts.append(f"[yellow]{counts['running']} running[/]")
        if counts.get("blocked"):
            parts.append(f"[red]{counts['blocked']} blocked[/]")
        if counts.get("complete"):
            parts.append(f"[green]{counts['complete']} complete[/]")
        if counts.get("failed"):
            parts.append(f"[dim]{counts['failed']} failed[/]")
        self.query_one("#tasks-counts", Label).update("  " + "  ".join(parts))

        table = self.query_one("#tasks-table", DataTable)
        table.clear()
        status = phase = search = ""
        try:
            status = self.query_one("#tasks-status-filter", Select).value or ""
            phase = self.query_one("#tasks-phase-filter", Select).value or ""
            search = self.query_one("#tasks-search", Input).value or ""
        except Exception:
            status = phase = search = ""
        open_tasks = svc.tasks.list_open_tasks(status=status, phase=phase, search=search)
        for t in open_tasks[:80]:
            risk = t.get("risk_level", "low")[:1].upper()
            table.add_row(
                t.get("task_id", "?")[:16],
                str(t.get("priority", 0)),
                t.get("phase", "?")[:8],
                t.get("objective", "?")[:60],
                t.get("target", "?")[:24],
                t.get("status", "?"),
                risk,
            )

        footer.show_context(
            "Enter Open", "x Execute", "b Block", "c Complete", "r Refresh", "Esc Back"
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        table = self.query_one("#tasks-table", DataTable)
        if event.cursor_row < table.row_count:
            row = table.get_row_at(event.cursor_row)
            if row:
                task_id = str(row[0])
                self.app.push_screen(TaskDetailScreen(task_id))

    def action_execute_task(self) -> None:
        table = self.query_one("#tasks-table", DataTable)
        if table.row_count and table.cursor_row < table.row_count:
            row = table.get_row_at(table.cursor_row)
            task_id = str(row[0])
            self.app.push_screen(ExecutionScreen(task_id))

    def action_block_task(self) -> None:
        svc = self._get_services()
        if not svc.has_active_mission:
            return
        table = self.query_one("#tasks-table", DataTable)
        if table.row_count and table.cursor_row < table.row_count:
            row = table.get_row_at(table.cursor_row)
            task_id = str(row[0])
            svc.tasks.block_task(task_id, "Blocked manually by user.")
            self.notify(f"Task {task_id} blocked.")
            self._load_data()

    def action_complete_task(self) -> None:
        svc = self._get_services()
        if not svc.has_active_mission:
            return
        table = self.query_one("#tasks-table", DataTable)
        if table.row_count and table.cursor_row < table.row_count:
            row = table.get_row_at(table.cursor_row)
            task_id = str(row[0])
            svc.tasks.complete_task(task_id, "Manually completed from task queue.")
            self.notify(f"Task {task_id} completed.")
            self._load_data()

    def refresh_data(self) -> None:
        self._load_data()

    @on(Select.Changed)
    def _on_filter_change(self) -> None:
        self._load_data()

    @on(Input.Submitted, "#tasks-search")
    def _on_search(self) -> None:
        self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc
