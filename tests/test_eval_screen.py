"""Tests for the read-only TUI Eval screen (eval run browser)."""

from __future__ import annotations


def test_eval_screen_imports():
    from tui.screens.eval import EvalScreen

    assert EvalScreen is not None
    assert isinstance(EvalScreen, type)


def test_eval_binding_registered():
    from tui.app import ResearchTUI

    assert any(getattr(b, "key", None) == "v" for b in ResearchTUI.BINDINGS)


def test_eval_screen_in_screen_map():
    from tui.app import _screen_map
    from tui.screens.eval import EvalScreen

    screen_map = _screen_map()
    assert "eval" in screen_map
    assert screen_map["eval"] is EvalScreen