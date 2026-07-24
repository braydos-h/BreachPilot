"""Screens package for the TUI."""

from tui.screens.dashboard import DashboardScreen
from tui.screens.mission_setup import MissionSetupScreen
from tui.screens.scope import ScopeScreen
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
from tui.screens.targets import TargetsScreen
from tui.screens.swarm import SwarmScreen
from tui.screens.skills_screen import SkillsScreen

__all__ = [
    "DashboardScreen",
    "MissionSetupScreen",
    "ScopeScreen",
    "TasksScreen",
    "TaskDetailScreen",
    "ExecutionScreen",
    "FindingsScreen",
    "FindingDetailScreen",
    "EvidenceScreen",
    "ReportsScreen",
    "LogsScreen",
    "HelpScreen",
    "SettingsScreen",
    "MemoryBrowserScreen",
    "GraphScreen",
    "TargetsScreen",
    "SwarmScreen",
    "SkillsScreen",
]
