"""Execution screen — scope preview, live execution, post-execution results.

Three phases: Preview → Running → Results. Live tool execution is not wired here
(the TUI has no live ExecutorAgent session); pressing Execute surfaces an honest
notice instead of fabricating evidence or marking the task complete. Use the
CLI/TUI mission flow (agent loop) for real execution.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button, Footer, Header, Label, ProgressBar, Static,
)
from textual import on

from tui.screens.findings import FindingsScreen
from tui.services import ServiceRegistry
from tui.themes import COLORS
from tui.widgets import (
    HelpFooter, ScopeCheckPreview, ConfirmModal,
)


class ExecutionScreen(Screen):
    """Execute a task: scope preview → confirm → honest-notice (no fabrication)."""

    BINDINGS = [
        Binding("x", "confirm_execute", "Confirm Execute"),
        Binding("v", "goto_findings", "Open Findings"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def __init__(self, task_id: str) -> None:
        super().__init__()
        self._task_id = task_id
        self._task: dict = {}
        self._scope_result = None
        self._output = ""
        self.Phase = 0  # 0=preview, 1=running, 2=results, 3=done (instance state, not a shared class attr)

    def compose(self) -> ComposeResult:
        yield Static("", id="exec-error")
        with VerticalScroll(id="exec-body"):
            yield Static("[bold]EXECUTION PREVIEW[/]", id="exec-title")
            yield Static("", id="exec-task-summary")
            yield ScopeCheckPreview(id="exec-scope-preview")
            yield Static("", id="exec-risk")
            yield Static("", id="exec-progress-area")
            yield ProgressBar(id="exec-progress", total=100, show_eta=False)
            yield Static("", id="exec-output")
            yield Static("", id="exec-result")
        with Horizontal(id="exec-actions"):
            yield Button("Execute (x)", id="btn-exec-confirm", variant="primary")
            yield Button("Cancel (Esc)", id="btn-exec-cancel", variant="default")
        yield HelpFooter(id="exec-footer")

    def on_mount(self) -> None:
        self._load_preview()
        self.query_one("#exec-progress", ProgressBar).display = False
        self.query_one("#exec-output", Static).display = False
        self.query_one("#exec-result", Static).display = False

    # ── Phase 0: Preview ──────────────────────────────────────────────

    def _load_preview(self) -> None:
        svc = self._get_services()
        err = self.query_one("#exec-error", Static)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            return
        err.update("")

        task = svc.tasks.get_task(self._task_id)
        if not task:
            err.update(f"[bold red]Task {self._task_id} not found.[/]")
            return
        self._task = task

        target = task.get("target", "")
        phase = task.get("phase", "recon")
        tools = task.get("allowed_tools", ["unknown"])[:1]
        tool = tools[0] if tools else "unknown"
        risk = task.get("risk_level", "low")

        self.query_one("#exec-task-summary", Static).update(
            f"\n  Task:       {self._task_id}\n"
            f"  Objective:  {task.get('objective', '')}\n"
            f"  Hypothesis: {task.get('hypothesis', '')}\n"
            f"  Planned:    Execute {tool} against {target}\n"
            f"  Tool:       {tool}"
        )

        result = svc.check_scope(target, phase, tool, risk)
        self._scope_result = result
        self.query_one("#exec-scope-preview", ScopeCheckPreview).show_result(result)

        risk_color = {"high": COLORS["danger"], "medium": COLORS["warning"], "low": COLORS["safe"]}.get(risk, COLORS["safe"])
        approval = "yes" if result and result.requires_human_approval else "no"
        self.query_one("#exec-risk", Static).update(
            f"\n  Risk Level:  [{risk_color}]{risk.upper()}[/]\n"
            f"  Approval:    {approval}\n"
            f"  Stop Cond:   {', '.join(task.get('stop_conditions',['none']))[:80]}"
        )

        footer = self.query_one("#exec-footer", HelpFooter)
        footer.show_context("x Confirm Execute", "v Open Findings", "Esc Back")

        if not result or not result.allowed:
            self.query_one("#btn-exec-confirm", Button).disabled = True
            self.query_one("#exec-error", Static).update(
                "[bold red]Cannot execute: out of scope.[/]"
            )

    @on(Button.Pressed, "#btn-exec-confirm")
    def action_confirm_execute(self) -> None:
        # M35 phase guard — once actioned, re-pressing 'x' must not re-run.
        if self.Phase != 0:
            self.notify("Already executed.", severity="warning")
            return
        if not self._scope_result or not self._scope_result.allowed:
            self.notify("Cannot execute — out of scope.", severity="error")
            return
        # H20: live execution is not available in this context. Surface an honest
        # notice rather than fabricating evidence or marking the task complete.
        # Use the CLI/TUI mission flow (agent loop) for real execution.
        self.Phase = 3  # mark actioned so the guard above fires on re-press
        self.notify(
            "Live execution is not available in this context — "
            "use the CLI/TUI mission flow.",
            severity="warning",
        )

    @on(Button.Pressed, "#btn-exec-cancel")
    def action_cancel(self) -> None:
        self.dismiss()

    @on(Button.Pressed, "#btn-done")
    def _on_done(self) -> None:
        self.dismiss()

    @on(Button.Pressed, "#btn-goto-findings")
    def _on_goto_findings_btn(self) -> None:
        self.app.push_screen(FindingsScreen())

    def action_goto_findings(self) -> None:
        self.app.push_screen(FindingsScreen())

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc