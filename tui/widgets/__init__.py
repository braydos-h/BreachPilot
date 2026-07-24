"""Reusable widgets for the TUI — sidebar, status bar, modals, empty states."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static, ListView, ListItem
from textual import on

from tui.themes import COLORS, RISK_PROFILE_COLORS, RISK_PROFILE_LABELS


# ── Sidebar ────────────────────────────────────────────────────────────────


class Sidebar(ListView):
    """Navigation sidebar with section headers."""

    BINDINGS = [
        Binding("d", "select_dashboard", "Dashboard"),
        Binding("t", "select_tasks", "Tasks"),
        Binding("f", "select_findings", "Findings"),
        Binding("e", "select_evidence", "Evidence"),
        Binding("s", "select_scope", "Scope"),
        Binding("g", "select_graph", "Graph"),
        Binding("l", "select_logs", "Logs"),
    ]

    def compose(self) -> ComposeResult:
        yield ListItem(Static("  [bold]NAVIGATION[/bold]"), id="nav-header")
        yield ListItem(Static("  D  Dashboard"), id="nav-dashboard")
        yield ListItem(Static("  M  Missions"), id="nav-missions")
        yield ListItem(Static("  --- Scope ---"), id="nav-sep-scope")
        yield ListItem(Static("  S  Scope Rules"), id="nav-scope")
        yield ListItem(Static("  T  Targets"), id="nav-targets")
        yield ListItem(Static("  --- Research ---"), id="nav-sep-research")
        yield ListItem(Static("  Q  Task Queue"), id="nav-tasks")
        yield ListItem(Static("  M  Memory"), id="nav-memory")
        yield ListItem(Static("  G  Target Graph"), id="nav-graph")
        yield ListItem(Static("  --- Results ---"), id="nav-sep-results")
        yield ListItem(Static("  E  Evidence"), id="nav-evidence")
        yield ListItem(Static("  F  Findings"), id="nav-findings")
        yield ListItem(Static("  R  Reports"), id="nav-reports")
        yield ListItem(Static("  --- System ---"), id="nav-sep-system")
        yield ListItem(Static("  L  Logs"), id="nav-logs")
        yield ListItem(Static("  S  Settings"), id="nav-settings")


# ── Status Bar ─────────────────────────────────────────────────────────────


class StatusBar(Static):
    """Top status bar showing mission name + risk badge + clock."""

    def update_mission(self, name: str, risk: str) -> None:
        color = RISK_PROFILE_COLORS.get(risk, COLORS["muted"])
        label = RISK_PROFILE_LABELS.get(risk, risk.upper())
        self.update(
            f"  [bold]AI Bug Bounty Agent[/]    "
            f"Mission: [bold]{name}[/]    "
            f"[on {color}][white bold]  {label}  [/]"
        )


# ── Help Footer ────────────────────────────────────────────────────────────


class HelpFooter(Static):
    """Bottom help bar with context-sensitive keyboard shortcuts."""

    def show_default(self) -> None:
        self.update(
            "[dim]↑↓ Nav  Enter Select  / Search  r Refresh  q Quit  ? Help[/dim]"
        )

    def show_context(self, *binds: str) -> None:
        self.update(f"[dim]{'  '.join(binds)}[/dim]")


# ── Confirmation Modal ─────────────────────────────────────────────────────


class ConfirmModal(ModalScreen[bool]):
    """Modal dialog for confirming dangerous or important actions.

    Usage::

        def action_delete(self):
            self.app.push_screen(ConfirmModal("Delete finding?", "This cannot be undone."), callback=self._on_confirm)

        def _on_confirm(self, result: bool):
            if result:
                ...
    """

    def __init__(
        self,
        title: str,
        body: str = "",
        danger: bool = False,
    ) -> None:
        super().__init__()
        self._title = title
        self._body = body
        self._danger = danger

    def compose(self) -> ComposeResult:
        border_color = COLORS["danger"] if self._danger else COLORS["warning"]
        yield Static(
            f"[bold {border_color}]{'⚠ DANGER: ' if self._danger else ''}{self._title}[/]",
            id="modal-title",
        )
        if self._body:
            yield Static(self._body, id="modal-body")
        yield Static("", id="modal-spacer")
        with Horizontal(id="modal-buttons"):
            yield Button("Confirm", variant="error" if self._danger else "primary", id="btn-confirm")
            yield Button("Cancel", variant="default", id="btn-cancel")

    @on(Button.Pressed, "#btn-confirm")
    def _on_confirm(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#btn-cancel")
    def _on_cancel(self) -> None:
        self.dismiss(False)

    def key_escape(self) -> None:
        self.dismiss(False)


# ── Scope Check Preview ────────────────────────────────────────────────────


class ScopeCheckPreview(Static):
    """Shows scope gate result before execution with color-coded pass/fail."""

    def show_result(self, result) -> None:
        if result is None:
            self.update(
                "\n[bold yellow]?  No scope check available — no active mission.[/]"
            )
            return

        if result.allowed:
            color = COLORS["safe"]
            icon = "V"
            self.update(
                f"\n[{color} bold]{icon}  IN SCOPE: {result.risk_level}[/]\n"
                f"  Matched Rule: {result.matched_scope_rule}\n"
                f"  Third-party:  {result.is_third_party}\n"
                f"  Rate Limit:   {result.rate_limit_remaining or 'N/A'}"
            )
        else:
            color = COLORS["danger"]
            icon = "X"
            self.update(
                f"\n[{color} bold]{icon}  BLOCKED[/]\n"
                f"  Reason: {result.reason}"
            )

    def show_empty(self) -> None:
        self.update("\n[dim]No scope check performed yet.[/]")


# ── Empty State ────────────────────────────────────────────────────────────


class EmptyState(Static):
    """Friendly empty-state message with optional action hint."""

    def __init__(
        self,
        message: str,
        hint: str = "",
        action_text: str = "",
        action_id: str = "",
    ) -> None:
        super().__init__()
        self._message = message
        self._hint = hint
        self._action_text = action_text
        self._action_id = action_id

    def compose(self) -> ComposeResult:
        yield Static("", id="empty-spacer")
        yield Static(f"\n\n  [dim italic]{self._message}[/]\n", id="empty-message")
        if self._hint:
            yield Static(f"  [dim]{self._hint}[/]", id="empty-hint")
        if self._action_text:
            yield Button(self._action_text, id=f"empty-action-{self._action_id}", variant="primary")


# ── Section Card (used on dashboard) ───────────────────────────────────────


class Card(Static):
    """Bordered card widget for dashboard sections."""

    def __init__(self, title: str, content: str = "", *, id: str = "") -> None:
        super().__init__(id=id)
        self._title = title
        self._content = content

    def compose(self) -> ComposeResult:
        yield Static(f"[bold]{self._title}[/]", classes="card-title")
        yield Static(self._content, classes="card-content")

    def update_content(self, content: str) -> None:
        self._content = content
        content_widget = self.query_one(".card-content", Static)
        content_widget.update(content)
