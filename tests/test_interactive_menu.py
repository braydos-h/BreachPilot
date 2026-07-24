"""Tests for the interactive menu system."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock


def test_menu_module_imports():
    """Verify the interactive_menu module can be imported."""
    from tools.interactive_menu import (
        BANNER, run_interactive_menu, _show_banner,
        _main_menu, _show_help, _view_reports, _edit_settings,
    )
    assert BANNER is not None
    assert callable(run_interactive_menu)
    assert callable(_show_banner)
    assert callable(_main_menu)
    assert callable(_show_help)
    assert callable(_view_reports)
    assert callable(_edit_settings)


def test_banner_contains_app_name():
    """Banner should contain the app name."""
    from tools.interactive_menu import BANNER
    assert "AI Bug Bounty" in BANNER
    assert "Research Agent" in BANNER


def test_help_text():
    """Help text should contain key sections."""
    from tools.interactive_menu import _show_help
    import io
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        _show_help()
        output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    assert "QUICK REFERENCE" in output
    assert "INTERACTIVE MODE" in output
    assert "TUI DASHBOARD" in output
    assert "DIRECT ATTACK" in output


def test_menu_session_args_match_main_defaults():
    """Menu-launched sessions should keep pace with main.py parser fields."""
    from main import parse_args
    from tools.interactive_menu import _build_session_args

    parser_args = parse_args([])
    menu_args = _build_session_args(recon_first=None)

    assert vars(menu_args).keys() == vars(parser_args).keys()
    assert menu_args.recon_first is None
    assert hasattr(menu_args, "quiet")
    assert hasattr(menu_args, "json")
    assert hasattr(menu_args, "debug")
    assert hasattr(menu_args, "yes")
    assert hasattr(menu_args, "self_test")
    assert hasattr(menu_args, "ultrathink")


def test_menu_recon_first_args_override_only_recon_first():
    """Recon-first menu path should use parser defaults except recon_first."""
    from main import parse_args
    from tools.interactive_menu import _build_session_args

    parser_args = parse_args([])
    menu_args = _build_session_args(recon_first=True)

    expected = vars(parser_args)
    actual = vars(menu_args)
    assert actual["recon_first"] is True
    assert {k: v for k, v in actual.items() if k != "recon_first"} == {
        k: v for k, v in expected.items() if k != "recon_first"
    }


def test_fallback_main_menu_exit():
    """Fallback menu should handle 'exit' choice."""
    with patch("builtins.input", return_value="8"):
        from tools.interactive_menu import _fallback_main_menu
        result = _fallback_main_menu()
        assert result == "exit"


def test_fallback_main_menu_new_session():
    """Fallback menu should handle 'new session' choice."""
    with patch("builtins.input", return_value="2"):
        from tools.interactive_menu import _fallback_main_menu
        result = _fallback_main_menu()
        assert result == "new_session"


def test_fallback_main_menu_eof():
    """Fallback menu should handle EOF gracefully."""
    with patch("builtins.input", side_effect=EOFError):
        from tools.interactive_menu import _fallback_main_menu
        result = _fallback_main_menu()
        assert result == "exit"


def test_run_interactive_menu_exits_on_exit():
    """run_interactive_menu should return 0 on exit."""
    with patch("tools.interactive_menu._show_banner"):
        with patch("tools.interactive_menu._main_menu", return_value="exit"):
            from tools.interactive_menu import run_interactive_menu
            result = run_interactive_menu()
            assert result == 0


def test_run_interactive_menu_exits_on_none():
    """run_interactive_menu should return 0 on None (Ctrl+C)."""
    with patch("tools.interactive_menu._show_banner"):
        with patch("tools.interactive_menu._main_menu", return_value=None):
            from tools.interactive_menu import run_interactive_menu
            result = run_interactive_menu()
            assert result == 0
