"""Help screen — keyboard shortcuts reference."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Static

from tui.widgets import HelpFooter


class HelpScreen(Screen):
    """Two-column keybinding reference."""

    BINDINGS = [Binding("escape", "pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(HELP_TEXT, id="help-content")
        yield HelpFooter(id="help-footer")

    def on_mount(self) -> None:
        self.query_one("#help-footer", HelpFooter).show_context("Esc Back")


HELP_TEXT = """\
# KEYBOARD SHORTCUTS

## Global (all screens)

| Key      | Action              |
|----------|---------------------|
| Esc      | Back / pop screen   |
| q        | Quit application    |
| ?        | This help screen    |
| /        | Focus search/filter |
| r        | Refresh current data|

## Navigation

| Key      | Action              |
|----------|---------------------|
| d        | Dashboard           |
| t        | Task Queue          |
| f        | Findings            |
| e        | Evidence            |
| s        | Scope Rules         |
| g        | Target Graph        |
| l        | Audit Logs          |

## Tasks

| Key      | Action              |
|----------|---------------------|
| Enter    | Open task details   |
| x        | Execute task        |
| b        | Block task          |
| c        | Complete task       |
| n        | New task            |

## Findings

| Key      | Action              |
|----------|---------------------|
| Enter    | Open finding detail |
| v        | Validate finding    |
| r        | Reject finding      |
| R        | Generate report     |
| m        | Show missing evidence|

## Evidence

| Key      | Action              |
|----------|---------------------|
| Enter    | View evidence       |
| Space    | Select for compare  |
| d        | Diff selected       |
| o        | Open raw file       |

## Dashboard

| Key      | Action              |
|----------|---------------------|
| n        | New mission wizard  |
"""
