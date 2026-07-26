"""Regression tests for the boot-spinner heartbeat spam fix.

``open_exploit_mcp_session`` opens ``with ui.spinner(...)`` *around*
``yield session``, so the spinner's redraw thread would keep printing
``[STATUS] Booting MCP server (stdio)... X.Xs`` for the entire exploit
session. The fix calls ``AttackUi.release_active_spinner()`` once the
session has finished initializing, stopping the redraw thread before the
caller's tool-call loop runs.

These tests prove the fix mechanism directly — driving the real
``open_exploit_mcp_session`` is intentionally avoided (the in-test
harness in ``test_recon_first_session.py`` notes that patching the MCP
SDK's function-local ``stdio_client`` import is brittle). Instead we
force the spinner's animated branch (gated on ``sys.stderr.isatty()``)
and assert that ``release_active_spinner`` stops the recurring redraw.
"""

from __future__ import annotations

import time

import pytest


def _force_tty(monkeypatch) -> None:
    """Make the spinner take the animated (threaded) branch in a non-TTY test."""
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True)


def test_release_active_spinner_stops_redraw_thread(monkeypatch) -> None:
    _force_tty(monkeypatch)
    from tools.attack_ui import AttackUi

    ui = AttackUi(plain=False)
    assert not ui.plain  # animated branch is eligible

    with ui.spinner(
        "TESTSPIN",
        heartbeat_seconds=0.05,
        format_message=lambda t: f"TESTSPIN {t:.2f}s",
    ):
        state = ui._active_spinner
        assert state is not None and state.thread is not None
        # Let a few redraw ticks fire so the thread is genuinely live.
        time.sleep(0.15)
        assert state.thread.is_alive()
        ui.release_active_spinner()
        # The thread must be dead and the active slot cleared.
        assert not state.thread.is_alive()
        assert ui._active_spinner is None
        # Idempotent: a second call is a no-op.
        ui.release_active_spinner()


def test_release_active_spinner_idempotent_when_no_spinner() -> None:
    from tools.attack_ui import AttackUi

    ui = AttackUi(plain=False)
    assert ui._active_spinner is None
    # Must not raise when no spinner has ever been started.
    ui.release_active_spinner()
    assert ui._active_spinner is None


def test_release_stops_recurring_elapsed_redraw(monkeypatch, capsys) -> None:
    """The direct regression for the reported spam: after release, the
    elapsed-seconds redraw line must NOT keep ticking."""
    _force_tty(monkeypatch)
    from tools.attack_ui import AttackUi

    ui = AttackUi(plain=False)
    with ui.spinner(
        "TESTSPIN",
        heartbeat_seconds=0.05,
        format_message=lambda t: f"TESTSPIN {t:.2f}s",
    ):
        # Let ~4 redraw ticks fire.
        time.sleep(0.2)
        _before = capsys.readouterr().err.count("TESTSPIN")
        assert _before >= 1  # the spinner did draw

        ui.release_active_spinner()

        # If release failed to stop the thread, ~7 more redraws would fire
        # over this window. With release working, at most one racy in-flight
        # redraw can slip through before the thread checks stop_event.
        time.sleep(0.35)
        _delta = capsys.readouterr().err.count("TESTSPIN")

    assert _delta <= 1, (
        f"redraw thread kept ticking after release_active_spinner: "
        f"{_delta} new 'TESTSPIN' lines"
    )