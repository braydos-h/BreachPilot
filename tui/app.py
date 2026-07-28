"""Main Textual application — ResearchTUI with screen routing and sidebar."""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Container
from textual.screen import Screen
from textual.widgets import (
    Footer, Header, Label, Static, ListView, ListItem, DataTable,
)
from textual import on

from textual.message import Message

from tui.services import ServiceRegistry
from tui.themes import (
    COLORS, RISK_PROFILE_COLORS, RISK_PROFILE_LABELS,
)

# Import all screens so they are available in on_mount and actions
from tui.screens.dashboard import DashboardScreen
from tui.screens.mission_setup import MissionSetupScreen
from tui.screens.scope import ScopeScreen
from tui.screens.targets import TargetsScreen
from tui.screens.tasks import TasksScreen
from tui.screens.task_detail import TaskDetailScreen
from tui.screens.execution import ExecutionScreen
from tui.screens.findings import FindingsScreen
from tui.screens.finding_detail import FindingDetailScreen
from tui.screens.evidence import EvidenceScreen
from tui.screens.reports import ReportsScreen
from tui.screens.logs import LogsScreen
from tui.screens.help_screen import HelpScreen
from tui.screens.settings import SettingsScreen
from tui.screens.memory_browser import MemoryBrowserScreen
from tui.screens.graph import GraphScreen
from tui.screens.swarm import SwarmScreen
from tui.screens.skills_screen import SkillsScreen
from tui.screens.eval import EvalScreen


# ── Reusable widgets ───────────────────────────────────────────────────────


class _AppSidebar(ListView):
    """Application sidebar linked to navigation items."""

    # IDs that are separators (not clickable navigation items)
    _SEPARATOR_IDS: set[str] = {
        "nav-header", "nav-sep-scope", "nav-sep-research",
        "nav-sep-results", "nav-sep-system",
    }

    class ItemClicked(Message):
        """Message sent when a sidebar item is clicked."""
        def __init__(self, item_id: str) -> None:
            super().__init__()
            self.item_id = item_id

    def compose(self) -> ComposeResult:
        yield ListItem(Static("  [bold]NAVIGATION[/]"), id="nav-header")
        yield ListItem(Static("  D  Dashboard"), id="nav-dashboard")
        yield ListItem(Static("  M  Missions"), id="nav-missions")
        yield ListItem(Static("  --- Scope ---"), id="nav-sep-scope")
        yield ListItem(Static("  S  Scope Rules"), id="nav-scope")
        yield ListItem(Static("  T  Targets"), id="nav-targets")
        yield ListItem(Static("  --- Research ---"), id="nav-sep-research")
        yield ListItem(Static("  Q  Task Queue"), id="nav-tasks")
        yield ListItem(Static("  A  Swarm Agents"), id="nav-swarm")
        yield ListItem(Static("  M  Memory"), id="nav-memory")
        yield ListItem(Static("  G  Target Graph"), id="nav-graph")
        yield ListItem(Static("  --- Results ---"), id="nav-sep-results")
        yield ListItem(Static("  E  Evidence"), id="nav-evidence")
        yield ListItem(Static("  F  Findings"), id="nav-findings")
        yield ListItem(Static("  R  Reports"), id="nav-reports")
        yield ListItem(Static("  --- System ---"), id="nav-sep-system")
        yield ListItem(Static("  L  Logs"), id="nav-logs")
        yield ListItem(Static("  ?  Settings"), id="nav-settings")
        yield ListItem(Static("  V  Eval"), id="nav-eval")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.item is None:
            return
        item_id = event.item.id or ""
        # Skip separator items — they are not navigable
        if item_id in self._SEPARATOR_IDS:
            return
        self.post_message(self.ItemClicked(item_id))


class _AppFooter(Static):
    """Bottom bar showing keyboard shortcuts."""

    def on_mount(self) -> None:
        self.update(
            "[dim]D Dashboard  T Tasks  A Swarm  F Findings  E Evidence  S Scope  G Graph  L Logs  ? Help  q Quit[/]"
        )


# ── Screen router ──────────────────────────────────────────────────────────

_SCREEN_MAP: dict[str, type] = {}


def _screen_map():
    if not _SCREEN_MAP:
        from tui.screens import (
            DashboardScreen, MissionSetupScreen, ScopeScreen,
            TasksScreen, TaskDetailScreen, ExecutionScreen,
            FindingsScreen, FindingDetailScreen,
            EvidenceScreen, ReportsScreen, LogsScreen,
            HelpScreen, SettingsScreen, MemoryBrowserScreen,
            GraphScreen, TargetsScreen, SkillsScreen,
        )
        _SCREEN_MAP.update({
            "dashboard": DashboardScreen,
            "missions": MissionSetupScreen,
            "scope": ScopeScreen,
            "targets": TargetsScreen,
            "tasks": TasksScreen,
            "swarm": SwarmScreen,
            "memory": MemoryBrowserScreen,
            "graph": GraphScreen,
            "evidence": EvidenceScreen,
            "findings": FindingsScreen,
            "reports": ReportsScreen,
            "logs": LogsScreen,
            "help": HelpScreen,
            "settings": SettingsScreen,
            "skills": SkillsScreen,
            "eval": EvalScreen,
        })
    return _SCREEN_MAP


# ── Main App ───────────────────────────────────────────────────────────────


class ResearchTUI(App):
    """AI Bug Bounty Agent — Interactive Terminal UI."""

    CSS_PATH = "app.tcss"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("question_mark", "toggle_help", "Help", priority=True),
        Binding("slash", "focus_search", "Search"),
        Binding("r", "refresh", "Refresh"),
        Binding("d", "goto_dashboard", "Dashboard"),
        Binding("t", "goto_tasks", "Tasks"),
        Binding("a", "goto_swarm", "Swarm"),
        Binding("f", "goto_findings", "Findings"),
        Binding("e", "goto_evidence", "Evidence"),
        Binding("s", "goto_scope", "Scope"),
        Binding("g", "goto_graph", "Graph"),
        Binding("l", "goto_logs", "Logs"),
        Binding("k", "goto_skills", "Skills"),
        Binding("v", "goto_eval", "Eval"),
    ]

    TITLE = "AI Bug Bounty Research Agent"

    def __init__(
        self,
        services: ServiceRegistry | None = None,
        workspace: Path | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        if services is not None:
            self._services = services
        else:
            self._services = ServiceRegistry(workspace)

    # ── Properties ─────────────────────────────────────────────────────

    @property
    def services(self) -> ServiceRegistry:
        return self._services

    # ── Composition ────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            # Sidebar
            with Container(id="sidebar-container"):
                yield Static("", id="sidebar-mission")
                yield _AppSidebar(id="sidebar")
            # Main content
            with Container(id="content-container"):
                yield Static("", id="content-area")
        # Footer
        yield _AppFooter(id="status-footer")

    def on_mount(self) -> None:
        self._update_status()
        self.push_screen(DashboardScreen())

    # ── Screen navigation ──────────────────────────────────────────────

    def action_goto_dashboard(self) -> None:
        self.switch_screen(DashboardScreen())

    def action_goto_tasks(self) -> None:
        self.push_screen(TasksScreen())

    def action_goto_swarm(self) -> None:
        self.push_screen(SwarmScreen())

    def action_goto_findings(self) -> None:
        self.push_screen(FindingsScreen())

    def action_goto_evidence(self) -> None:
        self.push_screen(EvidenceScreen())

    def action_goto_scope(self) -> None:
        self.push_screen(ScopeScreen())

    def action_goto_graph(self) -> None:
        self.push_screen(GraphScreen())

    def action_goto_logs(self) -> None:
        self.push_screen(LogsScreen())

    def action_goto_skills(self) -> None:
        self.push_screen(SkillsScreen())

    def action_goto_eval(self) -> None:
        self.push_screen(EvalScreen())

    def action_toggle_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_focus_search(self) -> None:
        # Try to focus the search input on the current screen
        screen = self.screen
        if screen:
            try:
                inp = screen.query_one("Input", expect_type=None)
                if inp:
                    inp.focus()
            except Exception:
                pass

    def action_refresh(self) -> None:
        screen = self.screen
        if screen and hasattr(screen, "refresh_data"):
            screen.refresh_data()

    # ── Sidebar events ─────────────────────────────────────────────────

    @on(_AppSidebar.ItemClicked)
    def _on_sidebar_click(self, event: _AppSidebar.ItemClicked) -> None:
        item = event.item_id
        if item == "nav-dashboard":
            self.action_goto_dashboard()
        elif item == "nav-tasks":
            self.action_goto_tasks()
        elif item == "nav-swarm":
            self.action_goto_swarm()
        elif item == "nav-findings":
            self.action_goto_findings()
        elif item == "nav-evidence":
            self.action_goto_evidence()
        elif item == "nav-scope":
            self.action_goto_scope()
        elif item == "nav-graph":
            self.action_goto_graph()
        elif item == "nav-logs":
            self.action_goto_logs()
        elif item == "nav-missions":
            self.push_screen(MissionSetupScreen())
        elif item == "nav-reports":
            self.push_screen(ReportsScreen())
        elif item == "nav-memory":
            self.push_screen(MemoryBrowserScreen())
        elif item == "nav-targets":
            self.push_screen(TargetsScreen())
        elif item == "nav-settings":
            self.push_screen(SettingsScreen())
        elif item == "nav-eval":
            self.push_screen(EvalScreen())

    def _update_status(self) -> None:
        svc = self._services
        if svc.has_active_mission:
            name = svc.mission_name
            risk = svc.mission_risk_profile
        else:
            name = "No active mission"
            risk = "low_noise_non_destructive"

        bar = self.query_one("#sidebar-mission", Static)
        color = RISK_PROFILE_COLORS.get(risk, COLORS["muted"])
        label = RISK_PROFILE_LABELS.get(risk, risk.upper())
        bar.update(
            f"[bold]Mission[/]\n  {name[:24]}\n[{color}]  {label}[/]"
        )


def run(workspace: Path | None = None) -> None:
    """Launch the TUI."""
    app = ResearchTUI(workspace=workspace)
    app.run()
