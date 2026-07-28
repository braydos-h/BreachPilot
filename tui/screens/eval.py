"""Eval screen — list recent eval runs from reports/eval/*/eval_report.json."""

from __future__ import annotations

import json
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import (
    DataTable, Footer, Header, Label, Static,
)

from tui.widgets import HelpFooter

EVAL_DIR = Path("reports/eval")
EVAL_REPORT_NAME = "eval_report.json"


class EvalScreen(Screen):
    """Eval runs — list recent eval reports on disk (read-only)."""

    BINDINGS = [
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "pop_screen", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="eval-error")
        yield Label("[bold]Eval Runs[/] — recent evaluation reports:", id="eval-label")
        yield DataTable(id="eval-table", cursor_type="row")
        yield HelpFooter(id="eval-footer")

    def on_mount(self) -> None:
        self._build_table()
        self._load_data()

    def _build_table(self) -> None:
        table = self.query_one("#eval-table", DataTable)
        table.add_columns("Run ID", "Target", "Verdict", "Success Rate")

    def _load_data(self) -> None:
        table = self.query_one("#eval-table", DataTable)
        table.clear()
        runs = self._scan_runs()
        if not runs:
            self.query_one("#eval-error", Static).update(
                "[dim]No eval runs found.[/]"
            )
            return
        self.query_one("#eval-error", Static).update("")
        for run in runs:
            table.add_row(
                run.get("run_id", "?"),
                run.get("target", "?"),
                run.get("verdict", "?"),
                run.get("success_rate", "?"),
            )
        footer = self.query_one("#eval-footer", HelpFooter)
        footer.show_context("Eval Runs", "r Refresh", "Esc Back")

    def _scan_runs(self) -> list[dict]:
        """Best-effort scan of reports/eval/*/eval_report.json.

        Degrades to an empty list when the dir is missing/empty or json is bad.
        """
        runs: list[dict] = []
        try:
            if not EVAL_DIR.exists() or not EVAL_DIR.is_dir():
                return runs
            entries = list(EVAL_DIR.iterdir())
        except OSError:
            return runs

        for entry in entries:
            try:
                if not entry.is_dir():
                    continue
                report_path = entry / EVAL_REPORT_NAME
                if not report_path.exists():
                    continue
                with report_path.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            run_id = data.get("run_id") or entry.name
            target = str(data.get("target", "?"))
            verdict = str(data.get("verdict", "?"))
            success_rate = self._format_success_rate(data.get("success_rate"))
            runs.append({
                "run_id": str(run_id),
                "target": target,
                "verdict": verdict,
                "success_rate": success_rate,
            })
        runs.sort(key=lambda r: r["run_id"], reverse=True)
        return runs

    @staticmethod
    def _format_success_rate(value) -> str:
        if value is None:
            return "?"
        try:
            return f"{float(value):.1f}%"
        except (TypeError, ValueError):
            return str(value)

    def refresh_data(self) -> None:
        self._load_data()