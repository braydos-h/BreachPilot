"""Task Detail screen — full task view with execute/block/complete actions."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button, Footer, Header, Label, Static,
)
from textual import on

from tui.screens.execution import ExecutionScreen
from tui.services import ServiceRegistry
from tui.themes import COLORS
from tui.widgets import HelpFooter


class TaskDetailScreen(Screen):
    """Detailed view of a single task, with action buttons."""

    BINDINGS = [
        Binding("x", "execute", "Execute"),
        Binding("b", "block_task", "Block"),
        Binding("c", "complete_task", "Complete"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def __init__(self, task_id: str) -> None:
        super().__init__()
        self._task_id = task_id

    def compose(self) -> ComposeResult:
        yield Static("", id="task-detail-error")
        with VerticalScroll(id="task-detail-body"):
            yield Label("[bold]TASK DETAILS[/]", id="task-detail-title")
            yield Static("Loading...", id="task-detail-content")
            yield Static("", id="task-detail-evidence-label")
            yield Static("", id="task-detail-evidence")
        with Horizontal(id="task-detail-actions"):
            yield Button("Execute (x)", id="btn-execute", variant="primary")
            yield Button("Block (b)", id="btn-block", variant="error")
            yield Button("Complete (c)", id="btn-complete", variant="success")
        yield HelpFooter(id="task-detail-footer")

    def on_mount(self) -> None:
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#task-detail-error", Static)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            return
        err.update("")

        task = svc.tasks.get_task(self._task_id)
        if not task:
            err.update(f"[bold red]Task {self._task_id} not found.[/]")
            return

        risk = task.get("risk_level", "low").upper()
        risk_color = {"HIGH": COLORS["danger"], "MEDIUM": COLORS["warning"], "LOW": COLORS["safe"]}.get(risk, COLORS["safe"])

        lines = [
            f"Task ID:    {task.get('task_id', '?')}",
            f"Status:     {task.get('status', '?')}",
            f"Phase:      {task.get('phase', '?')}  |  Target: {task.get('target', '?')}",
            f"Priority:   {task.get('priority', 0)}  |  Risk: [{risk_color}]{risk}[/]",
            f"Asset Type: {task.get('asset_type', '?')}",
        ]

        # Show swarm agent mapping if available
        try:
            swarm = svc.swarm
            matching = [
                a for a in swarm.agent_rows
                if a.get("task_id") == task.get("task_id")
            ]
            if matching:
                agent = matching[-1]
                lines.append(
                    f"Swarm Agent: [bold]{agent.get('agent_type', '?')}[/] "
                    f"({agent.get('agent_id', '')}) — {agent.get('status', '?')}"
                )
        except Exception:
            pass

        lines.extend([
            "",
            f"[bold]Objective:[/]",
            f"  {task.get('objective', 'No objective.')}",
            "",
            f"[bold]Hypothesis:[/]",
            f"  {task.get('hypothesis', 'No hypothesis.')}",
            "",
            f"[bold]Allowed Tools:[/] {', '.join(task.get('allowed_tools', [])) or 'none'}",
            "",
            f"[bold]Success Criteria:[/]",
        ])
        for c in task.get("success_criteria", []):
            lines.append(f"  {c}")
        lines.append("")
        lines.append(f"[bold]Stop Conditions:[/]")
        for s in task.get("stop_conditions", []):
            lines.append(f"  {s}")
        lines.append("")

        evidence_refs = task.get("evidence_refs", [])
        if evidence_refs:
            lines.append(f"[bold]Evidence:[/] {', '.join(evidence_refs)}")
        else:
            lines.append("[bold]Evidence:[/] [dim]none[/]")

        if task.get("result_summary"):
            lines.append("")
            lines.append(f"[bold]Result:[/] {task.get('result_summary')}")

        content = self.query_one("#task-detail-content", Static)
        content.update("\n".join(lines))

        footer = self.query_one("#task-detail-footer", HelpFooter)
        footer.show_context("x Execute", "b Block", "c Complete", "Esc Back")

    @on(Button.Pressed, "#btn-execute")
    def action_execute(self) -> None:
        self.app.push_screen(ExecutionScreen(self._task_id))

    @on(Button.Pressed, "#btn-block")
    def action_block_task(self) -> None:
        svc = self._get_services()
        if svc.has_active_mission:
            svc.tasks.block_task(self._task_id, "Blocked from task detail view.")
            self.notify(f"Task {self._task_id} blocked.")
            self._load_data()

    @on(Button.Pressed, "#btn-complete")
    def action_complete_task(self) -> None:
        svc = self._get_services()
        if svc.has_active_mission:
            svc.tasks.complete_task(self._task_id, "Manually completed.")
            self.notify(f"Task {self._task_id} completed.")
            self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc
