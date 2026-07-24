"""Evidence screen — browse, compare, view raw evidence."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Select, Static, Label
from textual import on

from tui.services import ServiceRegistry
from tui.widgets import HelpFooter


TYPE_OPTIONS = [
    ("All Types", ""),
    ("raw_output", "raw_output"),
    ("http_response", "http_response"),
    ("note", "note"),
    ("structured_json", "structured_json"),
]


class EvidenceScreen(Screen):
    """Browse evidence items with selection for comparison."""

    BINDINGS = [
        Binding("o", "open_raw", "Open Raw"),
        Binding("d", "diff_evidence", "Diff"),
        Binding("c", "copy_ref", "Copy Ref"),
        Binding("space", "toggle_select", "Select"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def __init__(self) -> None:
        # Instance state, NOT a class attribute: previously `_selection` was a
        # class-level set shared across every EvidenceScreen instance, so row
        # selections bled between sessions.
        super().__init__()
        self._selection: set[int] = set()

    def compose(self) -> ComposeResult:
        yield Static("", id="ev-error")
        with Horizontal(id="ev-filter"):
            yield Select(TYPE_OPTIONS, prompt="Type", id="ev-type-filter")
        yield Label("", id="ev-count")
        yield DataTable(id="ev-table", cursor_type="row")
        yield Static("", id="ev-compare")
        yield HelpFooter(id="ev-footer")

    def on_mount(self) -> None:
        table = self.query_one("#ev-table", DataTable)
        table.add_columns("ID", "Type", "Target", "Summary", "Created")
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#ev-error", Static)
        footer = self.query_one("#ev-footer", HelpFooter)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            footer.show_default()
            return
        err.update("")

        items = self._current_evidence(limit=200)
        self.query_one("#ev-count", Label).update(
            f"  Total: [bold]{len(items)}[/] evidence items"
        )

        table = self.query_one("#ev-table", DataTable)
        table.clear()

        if not items:
            table.add_row("", "", "[dim]No evidence captured yet[/]", "", "")
            footer.show_context("Enter View", "Esc Back")
            return

        for e in items:
            eid = e.get("evidence_id", "?")
            ev_type = e.get("type", "?")
            summary = (e.get("summary", "") or "")[:50]
            target = (e.get("metadata", {}).get("target", "") or "")[:20]
            created = (e.get("created_at", "") or "")[:16]

            table.add_row(eid[:16], ev_type[:12], target, summary, created)

        footer.show_context(
            "Enter View", "Space Select", "d Diff", "o Open Raw", "c Copy", "r Refresh", "Esc Back"
        )

    def action_toggle_select(self) -> None:
        table = self.query_one("#ev-table", DataTable)
        if table.cursor_row in self._selection:
            self._selection.discard(table.cursor_row)
        else:
            self._selection.add(table.cursor_row)
        self._show_compare()

    def action_open_raw(self) -> None:
        svc = self._get_services()
        table = self.query_one("#ev-table", DataTable)
        if table.row_count:
            all_ev = self._current_evidence()
            idx = table.cursor_row
            if 0 <= idx < len(all_ev):
                ev = svc.evidence.get(all_ev[idx]["evidence_id"])
                if ev:
                    text = ev.get("content", "") or ev.get("summary", "")
                    self.app.push_screen(_EvidenceDetailScreen(
                        all_ev[idx]["evidence_id"], text[:4000]
                    ))

    def action_copy_ref(self) -> None:
        """Copy the selected evidence reference id to the clipboard."""
        table = self.query_one("#ev-table", DataTable)
        if table.row_count:
            all_ev = self._current_evidence()
            if 0 <= table.cursor_row < len(all_ev):
                eid = all_ev[table.cursor_row].get("evidence_id", "")
                if eid:
                    self.app.copy_to_clipboard(eid)
                    self.notify(f"Copied evidence ref: {eid}")

    def action_diff_evidence(self) -> None:
        if len(self._selection) >= 2:
            svc = self._get_services()
            items = self._current_evidence()
            sel = sorted(self._selection)
            if sel[0] >= len(items) or sel[1] >= len(items):
                # Filter changed since selection -> indices are stale. Clear and abort.
                self.notify("Selection is stale (filter changed). Re-select.", severity="warning")
                self._selection.clear()
                self._show_compare()
                return
            id_a = items[sel[0]]["evidence_id"]
            id_b = items[sel[1]]["evidence_id"]
            result = svc.evidence.compare(id_a, id_b)
            same = result.get("same_hash", False)
            self.notify(
                f"Diff: {'Same' if same else 'Different'} hash | "
                f"A: {result.get('a_summary','')[:40]} | B: {result.get('b_summary','')[:40]}"
            )

    def _show_compare(self) -> None:
        if len(self._selection) == 2:
            self.query_one("#ev-compare", Static).update(
                f"[yellow]Comparing {len(self._selection)} selected items. Press 'd' to diff.[/]"
            )
        elif len(self._selection) == 1:
            self.query_one("#ev-compare", Static).update(
                "[dim]1 item selected. Select another with Space to compare.[/]"
            )
        else:
            self.query_one("#ev-compare", Static).update("")

    def refresh_data(self) -> None:
        self._load_data()

    @on(Select.Changed, "#ev-type-filter")
    def _on_type_filter(self) -> None:
        # Filter changed -> cached row-selection indices no longer map to the same
        # evidence rows, so clear them before reloading.
        self._selection.clear()
        self._show_compare()
        self._load_data()

    def _current_evidence(self, limit: int = 200) -> list[dict]:
        """Evidence for the active mission, narrowed by the type filter.

        Used by BOTH the table render and the row-indexed actions (open-raw / diff)
        so a filtered view and its row indices always refer to the same list.
        """
        svc = self._get_services()
        if not svc.has_active_mission:
            return []
        ev_type = ""
        try:
            ev_type = self.query_one("#ev-type-filter", Select).value or ""
        except Exception:
            ev_type = ""
        return svc.evidence.list_for_mission(limit=limit, evidence_type=ev_type)

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc


class _EvidenceDetailScreen(Screen):
    def __init__(self, ev_id: str, content: str) -> None:
        super().__init__()
        self._ev_id = ev_id
        self._content = content

    BINDINGS = [Binding("escape", "pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Static(f"[bold]Evidence: {self._ev_id}[/]\n\n{self._content}", id="ev-detail-content")
        yield HelpFooter(id="ev-detail-footer")

    def on_mount(self) -> None:
        self.query_one("#ev-detail-footer", HelpFooter).show_context("Esc Back")
