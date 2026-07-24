"""Skills screen — read-only view of the runtime-skill catalog and the
current-run active selection (Tier 3.2).

Deliberately read-only: there is **no enable/disable toggle**. Skill selection
stays deterministic so an operator cannot be coerced into pulling attack-only
methodology in recon mode by toggling a skill on mid-run. Advisory only --
skills never change permission, scope, approval, command-safety, or audit.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Header, Label, Static

from tui.services import ServiceRegistry
from tui.widgets import HelpFooter


class SkillsScreen(Screen):
    """Runtime Skills — read-only catalog + active selection."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static("", id="skills-error")
        yield Label("[bold]Runtime Skills[/] — advisory prompt-context layer (read-only)", id="skills-title")
        yield Static(
            "[dim]Skills are advisory only. They never change scope, permission, "
            "approval, command-safety, or audit rules.[/]",
            id="skills-note",
        )
        yield Label("[bold]Active Selection (current run)[/]", id="skills-active-label")
        yield DataTable(id="skills-active-table", cursor_type="row")
        yield Label("[bold]Catalog[/]", id="skills-catalog-label")
        with VerticalScroll(id="skills-catalog-scroll"):
            yield DataTable(id="skills-catalog-table", cursor_type="row")
        yield HelpFooter(id="skills-footer")

    def on_mount(self) -> None:
        self._build_tables()
        self._load_data()

    def _build_tables(self) -> None:
        active = self.query_one("#skills-active-table", DataTable)
        active.add_columns("Skill", "Risk", "Tags", "Reason")
        catalog = self.query_one("#skills-catalog-table", DataTable)
        catalog.add_columns("Skill", "Domain", "Tags", "Description")

    def _load_data(self) -> None:
        svc = self._get_services()
        try:
            skills_svc = svc.skills
        except Exception as exc:
            self.query_one("#skills-error", Static).update(f"[bold red]Skills unavailable: {exc}[/]")
            return

        # Active selection (best-effort, no live mission context required since
        # skill selection is config-driven, not mission-driven).
        active = self.query_one("#skills-active-table", DataTable)
        active.clear()
        try:
            payloads = skills_svc.active_selection(mode="recon")
        except Exception:
            payloads = []
        if not payloads:
            active.add_row("(none selected)", "", "", "Run an assessment to populate the active set.")
        for p in payloads:
            tags = ", ".join(p.get("matched_tags", [])[:5]) or "(none)"
            active.add_row(p.get("name", ""), p.get("risk_level", ""), tags, (p.get("reason", "") or "")[:120])

        # Catalog
        catalog = self.query_one("#skills-catalog-table", DataTable)
        catalog.clear()
        for entry in skills_svc.list_catalog():
            tags = ", ".join(entry.get("tags", [])[:6]) or "(none)"
            desc = (entry.get("description", "") or "").replace("\n", " ").strip()[:160]
            name = entry["name"] + (" maybe" if entry.get("maybe") else "")
            catalog.add_row(name, entry.get("domain", "") or "-", tags, desc)

        self.query_one("#skills-error", Static).update("")
        footer = self.query_one("#skills-footer", HelpFooter)
        footer.show_context("Read-only", "r Refresh", "Esc Back")

    def refresh_data(self) -> None:
        self._load_data()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc