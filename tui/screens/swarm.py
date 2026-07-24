"""Swarm screen — live view of specialist agents, blackboard, and battle log."""

from __future__ import annotations

import time

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import DataTable, Label, Static

from tui.services import ServiceRegistry, SwarmStateSnapshot
from tui.themes import COLORS, STATUS_ICONS
from tui.widgets import HelpFooter


class SwarmScreen(Screen):
    """Live view of the multi-agent swarm state."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "pop_screen", "Back"),
    ]

    _refresh_timer: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Static("", id="swarm-error")
        with Horizontal(id="swarm-summary-bar"):
            yield Label("  Swarm: [dim]loading...[/]", id="swarm-summary")
        with Grid(id="swarm-grid"):
            with Vertical(id="swarm-agents-panel"):
                yield Static("[bold]AGENTS[/]", classes="card-title")
                yield DataTable(id="swarm-agents-table", cursor_type="row")
            with Vertical(id="swarm-blackboard-panel"):
                yield Static("[bold]BLACKBOARD[/]", classes="card-title")
                yield Static("[dim]No blackboard data.[/]", id="swarm-blackboard-content")
            with Vertical(id="swarm-battle-log-panel"):
                yield Static("[bold]BATTLE LOG[/]", classes="card-title")
                yield Static("[dim]No battle log entries.[/]", id="swarm-battle-log-content")
        yield HelpFooter(id="swarm-footer")

    def on_mount(self) -> None:
        table = self.query_one("#swarm-agents-table", DataTable)
        table.add_columns("Agent", "Type", "Task", "Status", "Time")
        self._load_data()
        self._refresh_timer = self.set_interval(3, self._load_data)

    def on_screen_resume(self) -> None:
        # Re-arm the refresh timer; stop any existing first to avoid double-arming.
        if self._refresh_timer is not None:
            self._refresh_timer.stop()
        self._load_data()
        self._refresh_timer = self.set_interval(3, self._load_data)

    def on_screen_suspend(self) -> None:
        """Stop the refresh timer while the screen is suspended."""
        if self._refresh_timer is not None:
            self._refresh_timer.stop()
            self._refresh_timer = None

    def refresh_data(self) -> None:
        self._load_data()

    def action_refresh(self) -> None:
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#swarm-error", Static)
        footer = self.query_one("#swarm-footer", HelpFooter)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            footer.show_default()
            return
        err.update("")

        try:
            state = svc.swarm
        except Exception as exc:
            err.update(f"[bold red]Error:[/] {exc}")
            footer.show_default()
            return

        self._update_summary(state)
        self._update_agents(state)
        self._update_blackboard(state)
        self._update_battle_log(state)
        footer.show_context("r Refresh", "Esc Back")

    def _update_summary(self, state: SwarmStateSnapshot) -> None:
        label = self.query_one("#swarm-summary", Label)
        if not state.active:
            label.update("  Swarm: [dim]no state file found[/]")
            return

        age = time.time() - state.updated_at if state.updated_at else 0
        age_str = f"{age:.0f}s ago" if age < 120 else f"{age / 60:.0f}m ago"
        running = sum(1 for a in state.agent_rows if a.get("status") == "running")
        blocked = sum(1 for a in state.agent_rows if a.get("status") == "blocked")
        access = "[green]ACCESS[/]" if state.blackboard.get("access_achieved") else "[dim]no access[/]"

        parts = [
            f"[bold]{len(state.agent_rows)}[/] agents",
            f"[yellow]{running}[/] running",
            f"[red]{blocked}[/] blocked",
            access,
            f"[dim]updated {age_str}[/]",
        ]
        label.update("  Swarm: " + "  |  ".join(parts))

    def _update_agents(self, state: SwarmStateSnapshot) -> None:
        table = self.query_one("#swarm-agents-table", DataTable)
        table.clear()
        if not state.active:
            return

        status_color = {
            "running": COLORS["warning"],
            "complete": COLORS["safe"],
            "failed": COLORS["danger"],
            "blocked": COLORS["danger"],
            "idle": COLORS["muted"],
        }

        for agent in state.agent_rows:
            status = agent.get("status", "idle")
            color = status_color.get(status, COLORS["muted"])
            icon = STATUS_ICONS.get(status, "")
            table.add_row(
                agent.get("agent_id", "")[:20],
                agent.get("agent_type", "?")[:12],
                agent.get("task_id", "")[:20],
                f"[{color}]{icon} {status}[/]",
                "—",
            )

    def _update_blackboard(self, state: SwarmStateSnapshot) -> None:
        content = self.query_one("#swarm-blackboard-content", Static)
        if not state.active:
            content.update("[dim]No blackboard data.[/]")
            return

        bb = state.blackboard
        lines: list[str] = []

        if state.strategy_shift:
            lines.append(f"[bold accent]Strategy:[/] {state.strategy_shift[:200]}")
            lines.append("")

        access = bb.get("access_achieved", False)
        lines.append(
            f"[bold]Access achieved:[/] {'[green]YES[/]' if access else '[dim]no[/]'}"
        )

        services = bb.get("discovered_services", [])
        if services:
            lines.append(f"[bold]Services:[/] {len(services)}")
            for svc in services[:5]:
                lines.append(f"  • {str(svc)[:60]}")

        creds = bb.get("credentials_found", [])
        if creds:
            lines.append(f"[bold]Credentials:[/] {len(creds)}")

        loot = bb.get("loot", [])
        if loot:
            lines.append(f"[bold]Loot:[/] {len(loot)}")

        hosts = bb.get("compromised_hosts", [])
        if hosts:
            lines.append(f"[bold]Compromised hosts:[/] {len(hosts)}")

        failed = bb.get("failed_modules", [])
        if failed:
            lines.append(f"[bold]Failed modules:[/] {len(failed)}")

        if not lines:
            lines.append("[dim]Blackboard is empty.[/]")

        content.update("\n".join(lines))

    def _update_battle_log(self, state: SwarmStateSnapshot) -> None:
        content = self.query_one("#swarm-battle-log-content", Static)
        if not state.active or not state.battle_log_tail:
            content.update("[dim]No battle log entries.[/]")
            return

        lines: list[str] = []
        for entry in reversed(state.battle_log_tail[-20:]):
            task_id = entry.get("task_id", "?")
            tool = entry.get("tool", "?")
            target = entry.get("target", "")
            success = entry.get("success", False)
            summary = str(entry.get("summary", ""))[:80]
            error = entry.get("error", "")
            icon = "[green]✓[/]" if success else "[red]✗[/]"
            lines.append(f"{icon} [bold]{task_id}[/] [{tool}] {target}")
            if summary:
                lines.append(f"    {summary}")
            if error:
                lines.append(f"    [red]{str(error)[:80]}[/]")
        content.update("\n".join(lines))

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc
