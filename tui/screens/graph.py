"""Target Graph screen — tree navigator for the attack surface model."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Static, Label
from textual import on

from tui.services import ServiceRegistry
from tui.widgets import HelpFooter


class GraphScreen(Screen):
    """Tree-based navigator for the target graph."""

    BINDINGS = [
        Binding("t", "new_task_from_graph", "New Task"),
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="graph-error")
        yield Label("[bold]Target Graph — Attack Surface Model[/]", id="graph-header")
        with VerticalScroll(id="graph-tree"):
            yield Static("[dim]Loading graph data...[/]", id="graph-content")
        yield Label("", id="graph-stats")
        yield HelpFooter(id="graph-footer")

    def on_mount(self) -> None:
        self._load_data()

    def _load_data(self) -> None:
        svc = self._get_services()
        err = self.query_one("#graph-error", Static)
        footer = self.query_one("#graph-footer", HelpFooter)

        if not svc.has_active_mission:
            err.update("[bold red]No active mission.[/]")
            footer.show_default()
            return
        err.update("")

        graph = svc.graph
        data = graph.query_graph(limit=200)
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])

        # Build tree lines
        lines: list[str] = []

        # Group nodes by type
        by_type: dict[str, list[dict]] = {}
        for n in nodes:
            t = n.get("type", "other")
            by_type.setdefault(t, []).append(n)

        def _icon(n_type: str) -> str:
            return {"host": "[H]", "domain": "[D]", "ip": "[I]", "service": "[S]",
                    "endpoint": "[E]", "parameter": "[P]", "permission_boundary": "[B]",
                    "technology": "[T]", "finding": "[F]"}.get(n_type, "[?]")

        type_order = ["host", "domain", "ip", "service", "web_app", "api", "endpoint",
                       "parameter", "permission_boundary", "technology", "finding"]

        for t in type_order:
            items = by_type.pop(t, [])
            if items:
                lines.append(f"")
                lines.append(f"[bold]── {t.upper()}S ({len(items)}) ──[/]")
                for it in items[:15]:
                    val = str(it.get("value", ""))[:60]
                    lines.append(f"    {_icon(t)} {val}")

        # Remaining types
        for t, items in sorted(by_type.items()):
            lines.append(f"")
            lines.append(f"[bold]── {t.upper()} ({len(items)}) ──[/]")
            for it in items[:5]:
                val = str(it.get("value", ""))[:60]
                lines.append(f"    {_icon(t)} {val}")

        # Edge summary
        if edges:
            lines.append(f"")
            lines.append(f"[bold]── RELATIONSHIPS ({len(edges)}) ──[/]")
            edge_counts: dict[str, int] = {}
            for e in edges:
                rel = e.get("relation", "?")
                edge_counts[rel] = edge_counts.get(rel, 0) + 1
            for rel, cnt in sorted(edge_counts.items(), key=lambda x: -x[1])[:10]:
                lines.append(f"    → {rel}: {cnt} edge(s)")

        # Query-based sections
        untested = graph.find_untested_assets()
        if untested:
            lines.append(f"")
            lines.append(f"[yellow bold]── UNTESTED ASSETS ({len(untested)}) ──[/]")
            for u in untested[:8]:
                lines.append(f"    [yellow]○[/] {u}")

        boundaries = graph.find_permission_boundaries()
        if boundaries:
            lines.append(f"")
            lines.append(f"[bold]── PERMISSION BOUNDARIES ({len(boundaries)}) ──[/]")
            for b in boundaries[:8]:
                lines.append(f"    {b.get('boundary', '?')[:60]}")

        id_candidates = graph.find_object_id_candidates()
        if id_candidates:
            lines.append(f"")
            lines.append(f"[bold accent]── OBJECT ID CANDIDATES ({len(id_candidates)}) ──[/]")
            for c in id_candidates[:8]:
                lines.append(f"    {c.get('value', '?')[:60]}")

        if not lines:
            lines.append("[dim]No graph data yet. Nodes are created as the agent discovers assets.[/]")

        self.query_one("#graph-content", Static).update("\n".join(lines))

        self.query_one("#graph-stats", Label).update(
            f"  Stats: {len(nodes)} nodes, {len(edges)} edges"
        )

        footer.show_context("t New Task", "r Refresh", "Esc Back")

    def refresh_data(self) -> None:
        self._load_data()

    def action_new_task_from_graph(self) -> None:
        # Delegate to the app-level task navigation rather than fabricating a
        # task-creation flow here (no inline create infra exists on this screen).
        self.app.action_goto_tasks()

    def _get_services(self) -> ServiceRegistry:
        app = self.app
        svc = getattr(app, "_services", None)
        if svc is None:
            svc = ServiceRegistry()
            app._services = svc
        return svc
