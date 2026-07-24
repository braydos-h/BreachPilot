"""Dashboard screen — mission overview, task counts, finding stats, next action."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical
from textual.widgets import Button, Static
from textual.screen import Screen
from textual.timer import Timer

from tui.services import ServiceRegistry
from tui.themes import (
    COLORS, RISK_PROFILE_COLORS, RISK_PROFILE_LABELS,
)

# Import screens used by action handlers
from tui.screens.tasks import TasksScreen
from tui.screens.findings import FindingsScreen
from tui.screens.swarm import SwarmScreen


class DashboardScreen(Screen):
    """Main dashboard showing mission status, task/finding counts, and next action."""

    BINDINGS = [
        Binding("n", "new_mission", "New Mission"),
        Binding("t", "goto_tasks", "Tasks"),
        Binding("a", "goto_swarm", "Swarm"),
        Binding("f", "goto_findings", "Findings"),
        Binding("r", "refresh", "Refresh"),
        Binding("x", "run_next_task", "Run Next"),
        Binding("l", "goto_logs", "Logs"),
    ]

    _refresh_timer: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Static("", id="dash-error")
        # Quick Actions row
        with Horizontal(id="dash-actions"):
            yield Button("New Mission", id="btn-new-mission", variant="primary")
            yield Button("Run Next Task", id="btn-run-next", variant="success")
            yield Button("Swarm", id="btn-swarm")
            yield Button("Refresh", id="btn-refresh")
            yield Button("Open Logs", id="btn-open-logs")
        with Grid(id="dash-grid"):
            with Vertical(id="dash-mission"):
                yield Static("[bold]MISSION[/]", classes="card-title")
                yield Static("Loading...", id="dash-mission-body")
            with Vertical(id="dash-scope"):
                yield Static("[bold]SCOPE[/]", classes="card-title")
                yield Static("Loading...", id="dash-scope-body")
            with Vertical(id="dash-tasks"):
                yield Static("[bold]TASKS[/]", classes="card-title")
                yield Static("Loading...", id="dash-tasks-body")
            with Vertical(id="dash-findings"):
                yield Static("[bold]FINDINGS[/]", classes="card-title")
                yield Static("Loading...", id="dash-findings-body")
            with Vertical(id="dash-next"):
                yield Static("[bold]NEXT ACTION[/]", classes="card-title")
                yield Static("Loading...", id="dash-next-body")
            with Vertical(id="dash-recent"):
                yield Static("[bold]RECENT[/]", classes="card-title")
                yield Static("Loading...", id="dash-recent-body")
            with Vertical(id="dash-swarm"):
                yield Static("[bold]SWARM[/]", classes="card-title")
                yield Static("Loading...", id="dash-swarm-body")
        # System status indicator
        yield Static("", id="dash-system-status")

    def on_mount(self) -> None:
        self.refresh_data()
        self._refresh_timer = self.set_interval(5, self.refresh_data)

    def on_screen_resume(self) -> None:
        # Re-arm the refresh timer; stop any existing first to avoid double-arming.
        if self._refresh_timer is not None:
            self._refresh_timer.stop()
        self.refresh_data()
        self._refresh_timer = self.set_interval(5, self.refresh_data)

    def on_screen_suspend(self) -> None:
        """Stop the refresh timer while the screen is suspended (e.g. another screen pushed on top)."""
        if self._refresh_timer is not None:
            self._refresh_timer.stop()
            self._refresh_timer = None

    def refresh_data(self) -> None:
        try:
            svc = self._get_services()
        except Exception:
            self._safe_update("#dash-error", "[bold red]Error:[/] Service registry unavailable.")
            return

        try:
            stats = svc.get_dashboard_stats()
        except Exception as exc:
            self._safe_update("#dash-error", f"[bold red]Error:[/] Failed to load stats: {exc}")
            return

        if stats is None:
            self._safe_update("#dash-error", "[bold red]Error:[/] Dashboard stats returned None.")
            return

        if stats.error:
            self._safe_update("#dash-error", f"[bold red]Error:[/] {stats.error}")
            if not stats.mission_active and "No active mission" in stats.error:
                self._show_no_mission()
            self._update_system_status(svc)
            return

        self._safe_update("#dash-error", "")

        # Mission card
        risk_color = RISK_PROFILE_COLORS.get(stats.mission_risk, COLORS["muted"])
        risk_label = RISK_PROFILE_LABELS.get(stats.mission_risk, stats.mission_risk)
        self._safe_update("#dash-mission-body",
            f"  Program:  [bold]{stats.mission_name}[/]\n"
            f"  Status:   [green]{stats.mission_status}[/]\n"
            f"  Risk:     [{risk_color}]{risk_label}[/]\n"
        )

        # Scope card
        self._safe_update("#dash-scope-body",
            f"  Allows:   {stats.scope_allows} rules\n"
            f"  Denies:   {stats.scope_denies} rules\n"
            f"  Profile:  {stats.mission_risk.replace('_', '-')}\n"
        )

        # Tasks card
        task_color = COLORS["warning"] if stats.tasks_pending > 0 else COLORS["muted"]
        self._safe_update("#dash-tasks-body",
            f"  Pending:    [{task_color}]{stats.tasks_pending}[/]\n"
            f"  Running:    [yellow]{stats.tasks_running}[/]\n"
            f"  Blocked:    [red]{stats.tasks_blocked}[/]\n"
            f"  Completed:  [green]{stats.tasks_completed}[/] | Failed: [dim]{stats.tasks_failed}[/]"
        )

        # Findings card
        finding_text = []
        if stats.findings_report_ready:
            finding_text.append(
                f"  Report-Ready:  [{COLORS['safe']}]{stats.findings_report_ready}[/]"
            )
        if stats.findings_candidates:
            finding_text.append(
                f"  Candidates:    {stats.findings_candidates}"
            )
        if stats.findings_needs_validation:
            finding_text.append(
                f"  [yellow]Needs Val:    {stats.findings_needs_validation}[/]"
            )
        if stats.findings_validated:
            finding_text.append(
                f"  [green]Validated:     {stats.findings_validated}[/]"
            )
        if not finding_text:
            finding_text.append("  [dim]No findings yet[/]")

        self._safe_update("#dash-findings-body", "\n".join(finding_text))

        # Next action card
        next_task = stats.next_task
        if next_task:
            risk_str = next_task.get("risk_level", "low")
            risk_color_map = {"high": COLORS["danger"], "medium": COLORS["warning"], "low": COLORS["safe"]}
            rc = risk_color_map.get(risk_str, COLORS["safe"])
            self._safe_update("#dash-next-body",
                f"  ID:        {next_task.get('task_id', '?')}\n"
                f"  Objective: {next_task.get('objective', '')[:60]}\n"
                f"  Phase:     {next_task.get('phase', '?')}  Risk: [{rc}]{risk_str.upper()}[/]\n"
                f"  Priority:  {next_task.get('priority', 0)}"
            )
        else:
            self._safe_update("#dash-next-body",
                "  [dim]No pending tasks. Run planner or agent loop.[/]"
            )

        # Recent card
        self._safe_update("#dash-recent-body",
            f"  {stats.last_action[:100] or '[dim]No recent activity[/]'}"
        )

        # Swarm card
        if stats.swarm_active:
            access = "[green]ACCESS[/]" if stats.swarm_access_achieved else "[dim]no access[/]"
            swarm_text = [
                f"  Agents:  [bold]{stats.swarm_agent_count}[/]  "
                f"running [yellow]{stats.swarm_running_count}[/]  "
                f"blocked [red]{stats.swarm_blocked_count}[/]",
                f"  Status:  {access}",
            ]
            if stats.swarm_last_reflection:
                swarm_text.append(
                    f"  Reflection: {stats.swarm_last_reflection[:80]}"
                )
        else:
            swarm_text = ["  [dim]Swarm not active. Run with --swarm.[/]"]
        self._safe_update("#dash-swarm-body", "\n".join(swarm_text))

        # System status
        self._update_system_status(svc)

    def _safe_update(self, widget_id: str, content: str) -> None:
        """Safely update a widget, ignoring NoMatches errors."""
        try:
            self.query_one(widget_id, Static).update(content)
        except Exception:
            pass

    def _update_system_status(self, svc: ServiceRegistry) -> None:
        """Update the system status indicator."""
        try:
            db_ok = svc.db is not None
            has_mission = svc.has_active_mission
            status_parts = [
                f"DB: [{'green' if db_ok else 'red'}]{'Connected' if db_ok else 'Disconnected'}[/]",
                f"Mission: [{'green' if has_mission else 'dim'}]{'Active' if has_mission else 'None'}[/]",
            ]
            self._safe_update("#dash-system-status",
                "[dim]System Status:[/] " + " | ".join(status_parts)
            )
        except Exception:
            self._safe_update("#dash-system-status", "[dim]System Status: Unavailable[/]")

    def _show_no_mission(self) -> None:
        for wid_id in ("dash-mission-body", "dash-scope-body", "dash-tasks-body",
                        "dash-findings-body", "dash-next-body", "dash-recent-body",
                        "dash-swarm-body", "dash-error"):
            try:
                self.query_one(f"#{wid_id}", Static).update(
                    "[dim]No active mission[/]"
                )
            except Exception:
                pass

    # ── Button handlers ────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle Quick Action button presses."""
        btn_id = event.button.id
        if btn_id == "btn-new-mission":
            self.action_new_mission()
        elif btn_id == "btn-run-next":
            self.action_run_next_task()
        elif btn_id == "btn-swarm":
            self.action_goto_swarm()
        elif btn_id == "btn-refresh":
            self.refresh_data()
        elif btn_id == "btn-open-logs":
            self.action_goto_logs()

    # ── Actions ────────────────────────────────────────────────────────

    def action_new_mission(self) -> None:
        from tui.screens.mission_setup import MissionSetupScreen
        self.app.push_screen(MissionSetupScreen())

    def action_goto_tasks(self) -> None:
        self.app.push_screen(TasksScreen())

    def action_goto_swarm(self) -> None:
        self.app.push_screen(SwarmScreen())

    def action_goto_findings(self) -> None:
        self.app.push_screen(FindingsScreen())

    def action_run_next_task(self) -> None:
        """Run the next pending task."""
        svc = self._get_services()
        if not svc.has_active_mission:
            self.notify("No active mission. Create one first.", severity="warning")
            return
        try:
            next_task = svc.tasks.get_next_task()
            if next_task is None:
                self.notify("No pending tasks available.", severity="information")
                return
            task_id = next_task.get("task_id", "unknown")
            self.notify(f"Running task: {task_id}", severity="information")
            # Navigate to execution screen
            from tui.screens.execution import ExecutionScreen
            self.app.push_screen(ExecutionScreen(task_id=task_id))
        except Exception as exc:
            self.notify(f"Failed to run task: {exc}", severity="error")

    def action_goto_logs(self) -> None:
        from tui.screens.logs import LogsScreen
        self.app.push_screen(LogsScreen())

    def _get_services(self) -> ServiceRegistry:
        from tui.services import ServiceRegistry
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc
