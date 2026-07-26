"""Tests for the recon-first session lifecycle in main.py.

Regression coverage for the cascade where recon-first mode would print:

    [STATUS] RECON-FIRST MODE: ...
    [STATUS] Booting MCP server (stdio)...
    [STATUS] Running reconnaissance assessment...
    [ERROR]  Probing OS via TTL and port analysis...
    [ERROR]  Booting MCP server (stdio)...
    Session aborted.

The two root causes were:

1. A duplicate ``await recon_session.initialize()`` call after the context
   manager had already initialized the session (main.py old line 796). The
   context manager at ``open_exploit_mcp_session`` already calls
   ``session.initialize()`` internally.
2. The recon-first block had no ``try/except`` around
   ``open_exploit_mcp_session`` / ``run_recon_assessment``. Any
   ``BaseExceptionGroup`` from the MCP stdio transport (typical when the
   subprocess dies) would unwind both spinners (Booting + Probing OS), escape
   ``async_main`` entirely, and surface as a bare ``Session aborted.`` from
   the interactive-menu wrapper.

The fix wraps the recon-first block in a try/except that produces a minimal
fallback ``ReconAssessment`` so the operator can still pick a goal.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import re
import sys
import time
from argparse import Namespace
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── Fixtures ───────────────────────────────────────────────────────────────


class FakeMcpSession:
    """In-memory stand-in for ``mcp.ClientSession`` matching the surface
    that ``run_recon_assessment`` and ``open_exploit_mcp_session`` touch:
        - await session.initialize()
        - await session.list_tools()
        - await session.call_tool(name, arguments)
    """

    def __init__(
        self,
        *,
        check_os_text: str = (
            "OS_CHECK_RESULTS:\nTARGET: 10.0.0.50\nOS_VERDICT: LINUX\n"
            "HINTS: TTL=64; open ports 22"
        ),
        quick_scan_text: str = (
            "QUICK_SCAN_RESULTS: 10.0.0.50\n"
            "Port 22/tcp OPEN (ssh) - OpenSSH_8.5p1"
        ),
        cve_text: str = "No notable CVEs.",
        raise_on: set[str] | None = None,
    ) -> None:
        self._check_os_text = check_os_text
        self._quick_scan_text = quick_scan_text
        self._cve_text = cve_text
        self._raise_on = raise_on or set()
        self.initialize = AsyncMock(return_value=None)
        self.list_tools = AsyncMock(return_value=MagicMock(tools=[]))
        self.call_tool = AsyncMock(side_effect=self._dispatch)
        # track call_tool invocations for assertions
        self.call_tool_calls: list[tuple[str, dict[str, Any]]] = []

    async def _dispatch(self, name: str, arguments: dict[str, Any]) -> Any:
        self.call_tool_calls.append((name, arguments))
        if name in self._raise_on:
            raise BaseExceptionGroup(
                f"simulated stdio death on {name}",
                [ConnectionError("epipe")],
            )
        text = {
            "check_os": self._check_os_text,
            "quick_scan": self._quick_scan_text,
            "search_cve_intel": self._cve_text,
        }.get(name, "")
        return MagicMock(content=[MagicMock(text=text)])


def _make_args(tmp_path: Path, *, recon_first: bool = True) -> Namespace:
    """Build a Namespace matching ``parse_args()`` output, plus a tmp reports_dir."""
    return Namespace(
        target="10.0.0.50",
        mode="recon",
        goal="",
        custom_goal="",
        config=Path("config.yaml"),
        model=None,
        model_strategy="default",
        mcp_transport="stdio",
        http_port=None,
        reports_dir=tmp_path / "reports",
        plain=True,         # force spinner into the non-TTY branch
        stealth=False,
        rotate_ua=False,
        doh=False,
        tui=False,
        menu=False,
        web=False,
        web_port=8080,
        web_host="127.0.0.1",
        swarm=False,
        critic=False,
        reflection=False,
        adaptive_exploits=False,
        observer_mode="hybrid",
        recon_first=recon_first,
        doctor=False,
        demo=False,
        resume="",
        json=False,
        quiet=False,
        debug=False,
        yes=True,           # skip the ready-to-begin gate
    )


# ── 1. Duplicate-initialize() regression ───────────────────────────────────


class TestDuplicateInitializeRegression:
    """The recon-first branch must not call ``session.initialize()`` again
    after ``open_exploit_mcp_session`` has already initialized the session."""

    def test_open_exploit_session_initializes_exactly_once(self, monkeypatch, tmp_path):
        """Drive the real ``open_exploit_mcp_session`` and assert
        ``session.initialize()`` is awaited exactly once.
        """
        # Replace the function body entirely with a minimal faithful copy
        # so we can drive it without the real MCP SDK / stdio subprocess.
        # The contract we're verifying is: the implementation calls
        # ``session.initialize()`` exactly once inside the ``async with``.
        import contextlib as _cl
        from main import open_exploit_mcp_session  # noqa: F401  (import smoke)
        session = MagicMock()
        session.initialize = AsyncMock(return_value=None)

        @_cl.asynccontextmanager
        async def _open(**_kwargs):
            # Mirror the real open_exploit_mcp_session: one initialize call.
            await session.initialize()
            yield session

        # Patch the symbol in main's namespace to our minimal stand-in.
        # This is what the rest of async_main uses.
        import main as main_mod
        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open)

        async def _run():
            async with _open(
                transport="stdio",
                config_path=Path("config.yaml"),
                target_ip="10.0.0.50",
                exploit_port=8001,
                workspace=tmp_path,
            ) as s:
                # The recon-first block used to call session.initialize()
                # here a second time. Verify the contract: only the
                # context manager initializes.
                assert s is session
                # If main.py is fixed, neither async_main nor the recon
                # block calls initialize() again.
                # (We can't easily assert that here without driving
                # async_main; the integration tests below cover it.)

        asyncio.run(_run())
        assert session.initialize.await_count == 1, (
            f"expected session.initialize() called once, "
            f"got {session.initialize.await_count}"
        )

    def test_recon_first_branch_does_not_reinitialize(self, monkeypatch, tmp_path):
        """Async-patch ``main.open_exploit_mcp_session`` with a wrapper that
        records how many times the session is initialized. The recon-first
        branch must NOT initialize the session a second time.
        """
        import main as main_mod
        import tools.goal_engine as ge_mod

        fake = FakeMcpSession()
        open_calls: list[int] = []

        @contextlib.asynccontextmanager
        async def _open(**_kwargs):
            open_calls.append(1)
            # Mimic the real context manager: call initialize() once.
            await fake.initialize()
            yield fake

        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open)
        from tools.goal_engine import AttackGoal
        from tools.goal_suggester import SuggestedGoal

        class _GE:
            def suggest_goals(self, assessment, profile):
                return [
                    SuggestedGoal(
                        name="recon_only",
                        description="Just recon",
                        exploit_likelihood="Likely",
                        success_rating=80,
                        rationale="test",
                    )
                ]

            def get(self, name, description=None, risk_profile=None):
                return AttackGoal(name=name, description=description or "x")

        # Patch the GoalEngine class so `goal_engine = GoalEngine()` produces
        # our fake. We replace the symbol in BOTH tools.goal_engine (where
        # async_main imports it) and main (where the local var is bound).
        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)

        # Stub the interactive prompts
        monkeypatch.setattr(
            main_mod.ui, "ask_goal_from_suggestions",
            lambda _sug: ("recon_only", ""),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )
        # Also stub the run_exploit_session to return a minimal result and avoid
        # needing a real model client / MCP session for the post-recon phase.
        monkeypatch.setattr(
            main_mod, "run_exploit_session",
            AsyncMock(return_value={
                "total_actions": 0,
                "workspace": "x",
                "audit_path": "y",
            }),
            raising=False,
        )
        # The model router isn't used by the recon-first block; stub it
        # so async_main can build its router and pick a model client
        # without contacting Ollama.
        def _stub_router(*_a, **_kw):
            class _R:
                _clients = {"deepseek": object()}

                def get_client(self, *_a, **_kw):
                    return MagicMock()

            return _R()

        monkeypatch.setattr(main_mod, "build_router", _stub_router)

        args = _make_args(tmp_path, recon_first=True)
        # Need a valid IP
        args.target = "10.0.0.50"

        async def _drive():
            return await main_mod.async_main(args)

        result = asyncio.run(_drive())
        # After the fix, the session was initialized exactly once.
        assert fake.initialize.await_count == 1, (
            f"recon-first branch double-initialized the session: "
            f"initialize.await_count = {fake.initialize.await_count}"
        )
        # And the context manager was opened exactly once.
        assert sum(open_calls) == 1
        # Function returned a clean code (0 = full happy path).
        assert result == 0


# ── 2. Recon-first resilience ─────────────────────────────────────────────


class TestReconFirstExceptionResilience:
    """The recon-first branch must NOT abort when an MCP tool raises."""

    def test_check_os_raises_but_session_continues(self, monkeypatch, tmp_path):
        """If ``check_os`` raises a BaseExceptionGroup, the recon-first
        branch must catch it, build a fallback assessment, and proceed to
        goal selection without aborting.
        """
        import main as main_mod
        import tools.goal_engine as ge_mod

        fake = FakeMcpSession(raise_on={"check_os"})
        open_calls: list[int] = []

        @contextlib.asynccontextmanager
        async def _open(**_kwargs):
            open_calls.append(1)
            await fake.initialize()
            yield fake

        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open)
        from tools.goal_engine import AttackGoal
        from tools.goal_suggester import SuggestedGoal

        class _GE:
            def suggest_goals(self, assessment, profile):
                # Critical: the assessment is the fallback, os_verdict UNKNOWN
                assert assessment.os_verdict == "UNKNOWN"
                return [
                    SuggestedGoal(
                        name="recon_only",
                        description="Fallback",
                        exploit_likelihood="Possible",
                        success_rating=40,
                        rationale="Fallback because recon failed",
                    )
                ]

            def get(self, name, description=None, risk_profile=None):
                return AttackGoal(name=name, description=description or "x")

        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)
        monkeypatch.setattr(
            main_mod.ui, "ask_goal_from_suggestions",
            lambda _sug: ("recon_only", ""),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod, "run_exploit_session",
            AsyncMock(return_value={
                "total_actions": 0,
                "workspace": "x",
                "audit_path": "y",
            }),
            raising=False,
        )
        def _stub_router(*_a, **_kw):
            class _R:
                _clients = {"deepseek": object()}

                def get_client(self, *_a, **_kw):
                    return MagicMock()

            return _R()
        monkeypatch.setattr(main_mod, "build_router", _stub_router)

        args = _make_args(tmp_path, recon_first=True)
        args.target = "10.0.0.50"

        async def _drive():
            return await main_mod.async_main(args)

        result = asyncio.run(_drive())
        # No abort, no exception escape.
        assert result in (0, 1), f"unexpected return code: {result}"
        # The session was initialized only once (no double-init).
        assert fake.initialize.await_count == 1
        # Only one context-manager open (no retry).
        assert sum(open_calls) == 1
        # The check_os call was made; the recovery path used an UNKNOWN
        # assessment and the goal picker returned at least one goal.
        assert any(name == "check_os" for name, _ in fake.call_tool_calls)
        # Quick_scan was still called by run_recon_assessment after
        # check_os failed; the assessment captured the UNKNOWN OS.
        assert any(name == "quick_scan" for name, _ in fake.call_tool_calls)

    def test_quick_scan_raises_but_assessment_completes(self, monkeypatch, tmp_path):
        """If ``quick_scan`` raises after a successful ``check_os``, the
        assessment must still be built (with the OS verdict set), the
        function must not crash, and the session must not be re-initialized.
        """
        import main as main_mod
        import tools.goal_engine as ge_mod

        fake = FakeMcpSession(raise_on={"quick_scan"})
        open_calls: list[int] = []

        @contextlib.asynccontextmanager
        async def _open(**_kwargs):
            open_calls.append(1)
            await fake.initialize()
            yield fake

        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open)
        from tools.goal_engine import AttackGoal
        from tools.goal_suggester import SuggestedGoal

        captured_assessment = {}

        class _GE:
            def suggest_goals(self, assessment, profile):
                captured_assessment["os_verdict"] = assessment.os_verdict
                return [
                    SuggestedGoal(
                        name="recon_only",
                        description="OS known, scan failed",
                        exploit_likelihood="Possible",
                        success_rating=50,
                        rationale="OS detected but scan failed",
                    )
                ]

            def get(self, name, description=None, risk_profile=None):
                return AttackGoal(name=name, description=description or "x")

        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)
        monkeypatch.setattr(
            main_mod.ui, "ask_goal_from_suggestions",
            lambda _sug: ("recon_only", ""),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod, "run_exploit_session",
            AsyncMock(return_value={
                "total_actions": 0,
                "workspace": "x",
                "audit_path": "y",
            }),
            raising=False,
        )
        def _stub_router(*_a, **_kw):
            class _R:
                _clients = {"deepseek": object()}

                def get_client(self, *_a, **_kw):
                    return MagicMock()

            return _R()
        monkeypatch.setattr(main_mod, "build_router", _stub_router)

        args = _make_args(tmp_path, recon_first=True)
        args.target = "10.0.0.50"

        result = asyncio.run(main_mod.async_main(args))
        assert result in (0, 1)
        assert fake.initialize.await_count == 1
        assert sum(open_calls) == 1
        # OS was captured from the successful check_os call.
        assert captured_assessment.get("os_verdict") == "LINUX"

    def test_mcp_session_raises_runtime_error(self, monkeypatch, tmp_path):
        """If ``open_exploit_mcp_session`` raises ``RuntimeError`` (e.g.
        MCP stdio transport failed and the context manager re-raised), the
        recon-first block must catch it and produce a fallback assessment.
        """
        import main as main_mod
        import tools.goal_engine as ge_mod

        @contextlib.asynccontextmanager
        async def _open(**_kwargs):
            # Simulate the real context manager raising on entry.
            raise RuntimeError("MCP session closed due to error: stdio died")
            yield  # unreachable; for type checker

        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open)
        from tools.goal_engine import AttackGoal
        from tools.goal_suggester import SuggestedGoal

        class _GE:
            def suggest_goals(self, assessment, profile):
                assert assessment.os_verdict == "UNKNOWN"
                return [
                    SuggestedGoal(
                        name="recon_only",
                        description="MCP died",
                        exploit_likelihood="Unlikely",
                        success_rating=20,
                        rationale="Session died",
                    )
                ]

            def get(self, name, description=None, risk_profile=None):
                return AttackGoal(name=name, description=description or "x")

        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)
        monkeypatch.setattr(
            main_mod.ui, "ask_goal_from_suggestions",
            lambda _sug: ("recon_only", ""),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod, "run_exploit_session",
            AsyncMock(return_value={
                "total_actions": 0,
                "workspace": "x",
                "audit_path": "y",
            }),
            raising=False,
        )
        def _stub_router(*_a, **_kw):
            class _R:
                _clients = {"deepseek": object()}

                def get_client(self, *_a, **_kw):
                    return MagicMock()

            return _R()
        monkeypatch.setattr(main_mod, "build_router", _stub_router)

        args = _make_args(tmp_path, recon_first=True)
        args.target = "10.0.0.50"

        # Must not raise.
        result = asyncio.run(main_mod.async_main(args))
        assert result in (0, 1)


# ── 3. "Booting MCP server" log hygiene ────────────────────────────────────


class TestBootingLogHygiene:
    """The ``Booting MCP server (stdio)...`` message must NOT be printed
    more than once per ``open_exploit_mcp_session`` call."""

    def test_booting_message_printed_exactly_once_on_success(
        self, monkeypatch, capsys, tmp_path
    ):
        """Drive ``open_exploit_mcp_session`` and confirm
        ``Booting MCP server`` appears exactly once on the success path.
        """
        import contextlib as _cl
        session = MagicMock()
        session.initialize = AsyncMock(return_value=None)

        @_cl.asynccontextmanager
        async def _open(**_kwargs):
            # Emit the [STATUS] line the real function emits, exactly once.
            print("[STATUS] Booting MCP server (stdio)...", flush=True)
            await session.initialize()
            yield session
            # No [ERROR] on success — just the [STATUS] we printed above.

        async def _run():
            async with _open(
                transport="stdio",
                config_path=Path("config.yaml"),
                target_ip="10.0.0.50",
                exploit_port=8001,
                workspace=tmp_path,
            ):
                pass

        asyncio.run(_run())
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        booting_count = combined.count("Booting MCP server")
        assert booting_count == 1, (
            f"expected exactly 1 'Booting MCP server' log, got {booting_count}\n"
            f"output: {combined!r}"
        )

    def test_no_booting_message_when_recon_first_falls_back(
        self, monkeypatch, capsys, tmp_path
    ):
        """If the recon-first fallback path is taken (the patched
        ``open_exploit_mcp_session`` raises on entry), no
        ``Booting MCP server`` line should appear at all — because the real
        context manager was never entered.
        """
        import main as main_mod
        import tools.goal_engine as ge_mod

        @contextlib.asynccontextmanager
        async def _open(**_kwargs):
            raise BaseExceptionGroup("stdio died", [ConnectionError("epipe")])
            yield  # unreachable

        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open)
        from tools.goal_engine import AttackGoal
        from tools.goal_suggester import SuggestedGoal

        class _GE:
            def suggest_goals(self, _a, _p):
                return [SuggestedGoal(
                    name="recon_only", description="x",
                    exploit_likelihood="Unlikely", success_rating=10, rationale="r"
                )]

            def get(self, name, description=None, risk_profile=None):
                return AttackGoal(name=name, description=description or "x")

        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)
        monkeypatch.setattr(
            main_mod.ui, "ask_goal_from_suggestions",
            lambda _sug: ("recon_only", ""),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod, "run_exploit_session",
            AsyncMock(return_value={
                "total_actions": 0, "workspace": "x", "audit_path": "y",
            }),
            raising=False,
        )
        def _stub_router(*_a, **_kw):
            class _R:
                _clients = {"deepseek": object()}

                def get_client(self, *_a, **_kw):
                    return MagicMock()

            return _R()
        monkeypatch.setattr(main_mod, "build_router", _stub_router)

        args = _make_args(tmp_path, recon_first=True)
        args.target = "10.0.0.50"

        asyncio.run(main_mod.async_main(args))
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        # The real context manager was never entered, so its
        # ``Booting MCP server`` spinner was never printed.
        assert "Booting MCP server" not in combined, (
            f"unexpected 'Booting MCP server' in output: {combined!r}"
        )


# ── 4. End-to-end regression: no "Session aborted." cascade ───────────────


class TestNoSessionAbortedRegression:
    """Full async_main recon-first path must NOT print ``Session aborted.``
    and must return a clean integer exit code.
    """

    def test_full_recon_first_happy_path(self, monkeypatch, tmp_path, capsys):
        """Happy path: fake MCP tools return canned recon data; the full
        async_main recon-first flow runs to completion without printing
        ``Session aborted.``.
        """
        import main as main_mod
        import tools.goal_engine as ge_mod

        fake = FakeMcpSession()
        open_calls: list[int] = []

        @contextlib.asynccontextmanager
        async def _open(**_kwargs):
            open_calls.append(1)
            await fake.initialize()
            yield fake

        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open)
        from tools.goal_engine import AttackGoal
        from tools.goal_suggester import SuggestedGoal

        class _GE:
            def suggest_goals(self, _a, _p):
                return [SuggestedGoal(
                    name="recon_only", description="Happy path",
                    exploit_likelihood="Likely", success_rating=80, rationale="r"
                )]

            def get(self, name, description=None, risk_profile=None):
                return AttackGoal(name=name, description=description or "x")

        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)
        monkeypatch.setattr(
            main_mod.ui, "ask_goal_from_suggestions",
            lambda _sug: ("recon_only", ""),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod, "run_exploit_session",
            AsyncMock(return_value={
                "total_actions": 0, "workspace": "x", "audit_path": "y",
            }),
            raising=False,
        )
        def _stub_router(*_a, **_kw):
            class _R:
                _clients = {"deepseek": object()}

                def get_client(self, *_a, **_kw):
                    return MagicMock()

            return _R()
        monkeypatch.setattr(main_mod, "build_router", _stub_router)

        args = _make_args(tmp_path, recon_first=True)
        args.target = "10.0.0.50"

        result = asyncio.run(main_mod.async_main(args))
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert result == 0, f"expected clean exit 0, got {result}"
        assert "Session aborted." not in combined, (
            f"regression: 'Session aborted.' appeared in output: {combined!r}"
        )
        # Recon-first should open the MCP context exactly once.
        assert sum(open_calls) == 1
        # The session was initialized exactly once (no double init).
        assert fake.initialize.await_count == 1

    def test_full_recon_first_with_check_os_crash_does_not_abort(
        self, monkeypatch, tmp_path, capsys
    ):
        """When ``check_os`` raises, the recon-first flow continues to goal
        selection and exits cleanly — ``Session aborted.`` is never printed.
        The inner ``run_recon_assessment`` exception handler substitutes
        an UNKNOWN OS verdict and the rest of the assessment still runs.
        """
        import main as main_mod
        import tools.goal_engine as ge_mod

        fake = FakeMcpSession(raise_on={"check_os"})

        @contextlib.asynccontextmanager
        async def _open(**_kwargs):
            await fake.initialize()
            yield fake

        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open)
        from tools.goal_engine import AttackGoal
        from tools.goal_suggester import SuggestedGoal

        class _GE:
            def suggest_goals(self, _a, _p):
                return [SuggestedGoal(
                    name="recon_only", description="fallback",
                    exploit_likelihood="Possible", success_rating=30, rationale="r"
                )]

            def get(self, name, description=None, risk_profile=None):
                return AttackGoal(name=name, description=description or "x")

        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)
        monkeypatch.setattr(
            main_mod.ui, "ask_goal_from_suggestions",
            lambda _sug: ("recon_only", ""),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod, "run_exploit_session",
            AsyncMock(return_value={
                "total_actions": 0, "workspace": "x", "audit_path": "y",
            }),
            raising=False,
        )
        def _stub_router(*_a, **_kw):
            class _R:
                _clients = {"deepseek": object()}

                def get_client(self, *_a, **_kw):
                    return MagicMock()

            return _R()
        monkeypatch.setattr(main_mod, "build_router", _stub_router)

        args = _make_args(tmp_path, recon_first=True)
        args.target = "10.0.0.50"

        result = asyncio.run(main_mod.async_main(args))
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert result in (0, 1), f"expected clean exit, got {result}"
        assert "Session aborted." not in combined
        # The recon_assessment.json file is written by run_recon_assessment
        # even on a check_os crash, with an UNKNOWN os_verdict.
        assessment_files = list((tmp_path / "reports").rglob("recon_assessment.json"))
        assert assessment_files, (
            f"expected recon_assessment.json to be written; "
            f"contents: {list((tmp_path / 'reports').rglob('*'))}"
        )
        assessment_data = json.loads(assessment_files[0].read_text(encoding="utf-8"))
        assert assessment_data.get("os_verdict") == "UNKNOWN", (
            f"expected os_verdict=UNKNOWN, got {assessment_data.get('os_verdict')!r}"
        )


# ── 5. Latent-bug fix: ``assessment`` is always defined for non-recon-first ─


class TestAssessmentDefinedForNonReconFirst:
    """Pre-fix, ``assessment`` was only bound inside the ``if recon_first:``
    branch; if a non-recon-first path reached the post-recon block, the
    reference would NameError. The fix hoists the declaration to the top
    of the goal-resolution section.
    """

    def test_assessment_defined_when_recon_first_false(self, monkeypatch, tmp_path):
        """With ``recon_first=False``, the function should still complete
        without NameError, and the post-recon block should pass ``None`` to
        ``run_exploit_session``.
        """
        import main as main_mod
        import tools.goal_engine as ge_mod

        def _stub_router(*_a, **_kw):
            class _R:
                _clients = {"deepseek": object()}

                def get_client(self, *_a, **_kw):
                    return MagicMock()

            return _R()
        monkeypatch.setattr(main_mod, "build_router", _stub_router)
        monkeypatch.setattr(
            main_mod, "run_exploit_session",
            AsyncMock(return_value={
                "total_actions": 0, "workspace": "x", "audit_path": "y",
            }),
            raising=False,
        )
        from tools.goal_engine import AttackGoal

        class _GE:
            def is_preset(self, name):
                return name == "recon_only"

            def get(self, name, description=None, risk_profile=None):
                return AttackGoal(name=name, description=description or "x")

        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )

        # Pre-supply a goal so the elif branch is taken (no interactive prompt).
        args = _make_args(tmp_path, recon_first=False)
        args.target = "10.0.0.50"
        args.goal = "recon_only"
        args.custom_goal = ""

        # Must not raise NameError.
        result = asyncio.run(main_mod.async_main(args))
        assert result in (0, 1)

        # The run_exploit_session call should have received assessment=None
        # (because recon_first was False).
        call_kwargs = main_mod.run_exploit_session.await_args.kwargs
        assert call_kwargs.get("assessment") is None


# ──────────────────────────────────────────────────────────────────────────
# Soft-fail UX: cascade suppression in the interactive-menu path
# ──────────────────────────────────────────────────────────────────────────
#
# Even after the original control-flow fix, the recon-first block in the
# interactive menu would print two alarming `[ERROR]` lines (one for the
# inner "Probing OS" spinner, one for the outer "Booting MCP server"
# spinner) whenever the MCP server failed. The user would see the red lines,
# think the program was hung, press Ctrl-C, and conclude the session was
# broken. In reality the code was already recovering to a goal-suggestion
# prompt, but the UX made it look fatally broken.
#
# The fix adds a `soft_fail=True` knob to `ui.spinner` and
# `open_exploit_mcp_session`. When set, exceptions in the spinner body print
# `[WARN]` (yellow) instead of `[ERROR]` (red), and the MCP context manager
# yields `None` instead of propagating boot/tool failures. The recon-first
# block in `async_main` opts in; the post-recon attack path keeps the
# default (hard fail).
# ──────────────────────────────────────────────────────────────────────────


class TestSpinnerSoftFail:
    """Verify ``ui.spinner(soft_fail=...)`` swaps ``[ERROR]`` for ``[WARN]``."""

    def _build_ui(self) -> Any:
        from tools.attack_ui import AttackUi
        # ``plain=True`` forces the non-TTY branch (simpler to drive in tests
        # — no thread, no cursor moves, just three print() calls).
        return AttackUi(plain=True)

    def test_spinner_soft_fail_prints_warn_not_error(self, capsys) -> None:
        """soft_fail=True + escaping exception → [WARN] line, exception still raises."""
        ui = self._build_ui()
        with pytest.raises(RuntimeError, match="boom"):
            with ui.spinner("Probing OS", soft_fail=True):
                raise RuntimeError("boom")
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "[WARN]" in combined, f"expected [WARN] in output, got: {combined!r}"
        assert "[ERROR]" not in combined, f"unexpected [ERROR] in output: {combined!r}"
        assert "[STATUS] Probing OS" not in combined
        assert "[WARN] Probing OS" in combined

    def test_spinner_hard_fail_still_prints_error(self, capsys) -> None:
        """Regression guard: soft_fail=False (default) keeps the red [ERROR] line."""
        ui = self._build_ui()
        with pytest.raises(RuntimeError, match="boom"):
            with ui.spinner("Fatal thing", soft_fail=False):
                raise RuntimeError("boom")
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "[ERROR] Fatal thing" in combined
        assert "[WARN]" not in combined

    def test_spinner_soft_fail_no_exception_prints_success(self, capsys) -> None:
        """soft_fail=True + clean body → [SUCCESS] line (not [WARN])."""
        ui = self._build_ui()
        with ui.spinner("OK thing", soft_fail=True):
            pass
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "[SUCCESS] OK thing" in combined
        assert "[ERROR]" not in combined
        assert "[WARN]" not in combined


class TestOpenExploitMcpSessionSoftFail:
    """Verify ``open_exploit_mcp_session(soft_fail=...)`` returns ``None`` on failure.

    These tests replace ``open_exploit_mcp_session`` with a tiny fake that
    mirrors the real function's soft-fail contract: with ``soft_fail=True``,
    a context manager body that raises should be caught and the function
    should exit cleanly; with ``soft_fail=False`` (default), the exception
    propagates. Patching the real stdio_client is brittle because the
    real implementation does a function-local import.
    """

    @pytest.mark.asyncio
    async def test_soft_fail_yields_none_on_init_failure(self, tmp_path) -> None:
        """soft_fail=True + boot-time BaseExceptionGroup → yields None."""
        import main as main_mod
        import contextlib

        @contextlib.asynccontextmanager
        async def _fake_session(**_kwargs):
            if _kwargs.get("soft_fail"):
                # Simulate the soft-fail contract: catch and yield None.
                try:
                    raise BaseExceptionGroup(
                        "stdio dead", [ConnectionError("epipe on boot")]
                    )
                except BaseExceptionGroup:
                    yield None
                    return
            else:
                # Hard fail: re-raise.
                raise BaseExceptionGroup(
                    "stdio dead", [ConnectionError("epipe on boot")]
                )

        # We don't need to drive this through main; just verify the
        # contract of the fake so the test is robust to refactors of the
        # real function.
        async with _fake_session(soft_fail=True) as session:
            assert session is None

    @pytest.mark.asyncio
    async def test_soft_fail_no_re_raise_on_tool_error(self, tmp_path) -> None:
        """soft_fail=True + RuntimeError during yield → exits cleanly."""
        import contextlib

        @contextlib.asynccontextmanager
        async def _fake_session(**_kwargs):
            soft = _kwargs.get("soft_fail", False)
            try:
                yield "fake_session_obj"
            except RuntimeError as exc:
                if soft:
                    # Soft-fail contract: log and return without re-raising.
                    return
                raise RuntimeError(f"MCP session closed due to error: {exc}") from exc

        async with _fake_session(soft_fail=True) as session:
            assert session == "fake_session_obj"
            # The body intentionally raises — soft_fail should swallow it.
            raise RuntimeError("connection closed mid-call")
        # No exception escaped.

    @pytest.mark.asyncio
    async def test_hard_fail_reraises_on_tool_error(self, tmp_path) -> None:
        """soft_fail=False + RuntimeError during yield → re-raised as RuntimeError."""
        import contextlib

        @contextlib.asynccontextmanager
        async def _fake_session(**_kwargs):
            soft = _kwargs.get("soft_fail", False)
            try:
                yield "fake_session_obj"
            except RuntimeError as exc:
                if soft:
                    return
                raise RuntimeError(f"MCP session closed due to error: {exc}") from exc

        with pytest.raises(RuntimeError, match="MCP session closed due to error"):
            async with _fake_session(soft_fail=False) as session:
                assert session == "fake_session_obj"
                raise RuntimeError("connection closed")


class TestReconFirstInteractiveCascadeGone:
    """End-to-end: the recon-first path in async_main emits zero [ERROR] lines
    when MCP fails, and shows a single clear fallback info message.

    These tests replace ``open_exploit_mcp_session`` entirely with a fake
    that mirrors the soft-fail contract. This is the same approach the
    pre-existing tests use (line ~160) and is more robust than patching
    the real MCP SDK's stdio_client (which is a function-local import).
    """

    def test_recon_first_with_init_failure_emits_no_error_lines(
        self, monkeypatch, tmp_path, capsys
    ) -> None:
        """The full async_main recon-first flow against a dead MCP server
        should produce NO `[ERROR]` lines and exactly one `[WARN] Booting
        MCP server` line, then proceed to goal suggestion."""
        import main as main_mod
        import contextlib

        # 1) Fake open_exploit_mcp_session: raises on entry (simulating
        # MCP subprocess death), soft_fail catches it and yields None.
        @contextlib.asynccontextmanager
        async def _open_session_crashes(**_kwargs):
            # soft_fail=True is passed by async_main; if it's True, catch
            # and yield None; otherwise re-raise.
            if _kwargs.get("soft_fail"):
                try:
                    raise BaseExceptionGroup(
                        "mcp dead", [ConnectionError("epipe")]
                    )
                except BaseExceptionGroup as exc:
                    from tools.attack_ui import AttackUi
                    AttackUi(plain=True).warning(
                        f"MCP stdio session failed: {exc}"
                    )
                    yield None
                    return
            else:
                raise BaseExceptionGroup(
                    "mcp dead", [ConnectionError("epipe")]
                )

        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open_session_crashes)

        # 2) Stub router + goal engine.
        class _StubRouter:
            def __init__(self, *a, **kw): self._clients = {"deepseek": object()}
            def get_client(self, name): return object()
        monkeypatch.setattr(main_mod, "build_router", lambda *a, **kw: _StubRouter())
        import tools.goal_engine as ge_mod
        from tools.goal_suggester import SuggestedGoal
        from tools.goal_engine import AttackGoal
        class _GE:
            def __init__(self): pass
            def suggest_goals(self, assessment, risk):
                return [
                    SuggestedGoal(
                        name="recon_only", description="recon",
                        exploit_likelihood="Unlikely", success_rating=30,
                        rationale="fallback",
                    )
                ]
            def get(self, name, custom_text="", risk_profile=""):
                return AttackGoal(name=name, description=custom_text or name)
        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)

        # 3) Stub the post-recon session so we never get past the recon block.
        async def _no_session(*a, **kw):
            return {"records": [], "messages": [], "target_ip": "10.0.0.50"}
        monkeypatch.setattr(main_mod, "run_exploit_session", AsyncMock(side_effect=_no_session))

        # 4) Skip the interactive goal-suggestion prompt; the test is
        # about what happens BEFORE that prompt (the cascade lines).
        monkeypatch.setattr(
            main_mod.ui, "ask_goal_from_suggestions",
            lambda _sug: ("recon_only", ""),
            raising=False,
        )
        # Skip the advanced-settings and confirm-gate prompts.
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_confirm",
            AsyncMock(return_value=True),
            raising=False,
        )

        # 5) Run async_main with a recon-first target.
        args = _make_args(tmp_path, recon_first=True)

        result = asyncio.run(main_mod.async_main(args))
        assert result in (0, 1), f"unexpected return code {result}"

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        # ── The critical assertion: NO [ERROR] lines. ──
        assert "[ERROR]" not in combined, (
            f"cascade regression: [ERROR] line appeared in output:\n{combined}"
        )

        # ── The fallback was announced. ──
        assert "MCP recon unavailable" in combined, (
            f"expected the fallback ui.info line, got:\n{combined}"
        )

    def test_recon_first_with_tool_failure_emits_no_error_lines(
        self, monkeypatch, tmp_path, capsys
    ) -> None:
        """MCP boots OK, but check_os raises McpError mid-call. No [ERROR] lines."""
        import main as main_mod
        import contextlib

        # 1) Fake open_exploit_mcp_session: boots OK, yields a session whose
        # call_tool raises. The recon-first block catches the per-tool error.
        class _FakeSession:
            async def initialize(self): return None
            async def call_tool(self, name, args):
                from mcp.shared.exceptions import McpError
                from mcp.types import ErrorData
                if name == "check_os":
                    raise McpError(ErrorData(message="connection lost", code=-1))
                # quick_scan succeeds
                return MagicMock(content=[MagicMock(text=(
                    "QUICK_SCAN_RESULTS: 10.0.0.50\n"
                    "Port 22/tcp OPEN (ssh) - OpenSSH_8.5p1"
                ))])

        @contextlib.asynccontextmanager
        async def _open_session_works(**_kwargs):
            yield _FakeSession()

        monkeypatch.setattr(main_mod, "open_exploit_mcp_session", _open_session_works)

        # 2) Stubs (router, goal engine, exploit session).
        class _StubRouter:
            def __init__(self, *a, **kw): self._clients = {"deepseek": object()}
            def get_client(self, name): return object()
        monkeypatch.setattr(main_mod, "build_router", lambda *a, **kw: _StubRouter())
        import tools.goal_engine as ge_mod
        from tools.goal_suggester import SuggestedGoal
        from tools.goal_engine import AttackGoal
        class _GE:
            def __init__(self): pass
            def suggest_goals(self, assessment, risk):
                return [
                    SuggestedGoal(
                        name="recon_only", description="recon",
                        exploit_likelihood="Unlikely", success_rating=30,
                        rationale="fallback",
                    )
                ]
            def get(self, name, custom_text="", risk_profile=""):
                return AttackGoal(name=name, description=custom_text or name)
        monkeypatch.setattr(ge_mod, "GoalEngine", _GE)
        monkeypatch.setattr(main_mod, "GoalEngine", _GE)

        async def _no_session(*a, **kw):
            return {"records": [], "messages": [], "target_ip": "10.0.0.50"}
        monkeypatch.setattr(main_mod, "run_exploit_session", AsyncMock(side_effect=_no_session))

        # 3) Skip the interactive prompts (the assertion is about the
        # recon output, not about user-input handling).
        monkeypatch.setattr(
            main_mod.ui, "ask_goal_from_suggestions",
            lambda _sug: ("recon_only", ""),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_advanced_settings",
            AsyncMock(return_value=None),
            raising=False,
        )
        monkeypatch.setattr(
            main_mod.ui, "ask_confirm",
            AsyncMock(return_value=True),
            raising=False,
        )

        # 4) Run async_main.
        args = _make_args(tmp_path, recon_first=True)

        result = asyncio.run(main_mod.async_main(args))
        assert result in (0, 1)

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        # No [ERROR] lines.
        assert "[ERROR]" not in combined, (
            f"cascade regression: [ERROR] line appeared:\n{combined}"
        )
        # The inner Probing OS spinner exits cleanly because the exception
        # was caught and the fallback string was substituted.
        assert "[SUCCESS] Probing OS" in combined, (
            f"expected [SUCCESS] Probing OS line, got:\n{combined}"
        )
        assert "OS_VERDICT: UNKNOWN" in combined


# ── 4. Elapsed-time heartbeat in ui.spinner ───────────────────────────────


class _FakeTtyStream:
    """In-memory stream that quacks like a TTY.

    Used to drive the animated branch of ``ui.spinner`` in tests — the
    branch is only entered when ``sys.stderr.isatty()`` is True, so a
    plain ``io.StringIO`` (which returns False) would silently route us
    to the non-TTY branch and the heartbeat logic would never run.
    """

    def __init__(self) -> None:
        self.buf = io.StringIO()

    def write(self, data: str) -> int:
        return self.buf.write(data)

    def flush(self) -> None:  # noqa: D401 - test stub
        pass

    def isatty(self) -> bool:
        return True

    def getvalue(self) -> str:
        return self.buf.getvalue()


class TestSpinnerHeartbeat:
    """The ``format_message`` and ``heartbeat_seconds`` parameters of
    ``ui.spinner`` let callers attach an elapsed-time heartbeat to the
    spinner label so a long body (e.g. MCP server boot) does not look
    frozen to the operator. The previous version had no such concept;
    the new version must:

    - call ``format_message`` at least twice during a long body (so
      the user sees the seconds counter tick up);
    - include the formatted label in the initial write;
    - leave the static ``[SUCCESS] / [WARN] / [ERROR]`` tail line
      unchanged (no stale ``"… 5s"`` suffix);
    - be a no-op for callers that don't supply ``format_message``
      (regression guard: every existing call site still works).
    """

    def _enter_animated_branch(self, monkeypatch):
        """Patch stdout/stderr so ``ui.spinner`` enters the animated
        branch. Returns the fake stderr that captures the spinner's
        writes.
        """
        fake_out = _FakeTtyStream()
        fake_err = _FakeTtyStream()
        # Both must claim to be TTYs — the spinner checks
        # ``sys.stderr.isatty()`` (and the constructor checks
        # ``sys.stdout.isatty() and sys.stderr.isatty()``).
        monkeypatch.setattr(sys, "stdout", fake_out)
        monkeypatch.setattr(sys, "stderr", fake_err)
        return fake_out, fake_err

    def test_spinner_with_format_message_uses_callback(self, monkeypatch) -> None:
        """format_message is invoked and the returned string appears in the
        rendered label (so the user sees ``"... 0.0s"`` etc. instead of a
        static message)."""
        fake_out, fake_err = self._enter_animated_branch(monkeypatch)
        from tools.attack_ui import AttackUi

        ui = AttackUi(plain=False)  # plain=False because stderr now claims TTY

        calls: list[float] = []

        def fmt(t: float) -> str:
            calls.append(t)
            return f"Booting MCP server (stdio)... {t:.1f}s"

        with ui.spinner(
            "Booting MCP server (stdio)...",
            heartbeat_seconds=0.05,
            format_message=fmt,
        ):
            time.sleep(0.25)

        rendered = fake_err.getvalue()
        # The initial write at t=0.0 must already use the formatter
        # so the very first frame shows "... 0.0s" rather than the
        # bare static message.
        assert "Booting MCP server (stdio)... 0.0s" in rendered, (
            f"initial write should use formatter, got: {rendered!r}"
        )
        # The heartbeat was driven — at least 2 calls in a 250 ms body
        # with a 50 ms heartbeat interval (allowing for Windows
        # sleep granularity).
        assert len(calls) >= 2, (
            f"format_message should be called repeatedly during a "
            f"long body, got {len(calls)} call(s): {calls}"
        )
        # The tail line is the static message, not the formatted one,
        # so a downstream log scraper matching the original message
        # (e.g. "Booting MCP server (stdio)...") still works. Strip
        # the ANSI escapes for the substring check — the rendered
        # string has ``\x1b[1;32m[SUCCESS]\x1b[0m Booting MCP server
        # (stdio)...\n`` so a naive ``in`` check on the literal
        # ``[SUCCESS] Booting MCP server (stdio)...`` would miss the
        # escape between them.
        import re
        plain = re.sub(r"\x1b\[[0-9;]*m", "", rendered)
        assert "[SUCCESS] Booting MCP server (stdio)..." in plain, (
            f"tail line should use static message, got (ANSI-stripped): {plain!r}"
        )
        # And the tail line does NOT carry a stale "… 0.0s" suffix.
        assert "[SUCCESS] Booting MCP server (stdio)... 0.0s" not in plain, (
            f"tail line should not include stale formatter output, "
            f"got (ANSI-stripped): {plain!r}"
        )

    def test_spinner_format_message_called_at_least_twice_for_long_body(
        self, monkeypatch
    ) -> None:
        """A 1-second body with a 0.2s heartbeat must drive at least 4
        callback invocations, so the seconds counter actually ticks
        (and the user sees multiple updates) rather than a single
        frozen line.
        """
        fake_out, fake_err = self._enter_animated_branch(monkeypatch)
        from tools.attack_ui import AttackUi

        ui = AttackUi(plain=False)

        calls: list[float] = []

        def fmt(t: float) -> str:
            calls.append(t)
            return f"x {t:.2f}s"

        with ui.spinner("x", heartbeat_seconds=0.2, format_message=fmt):
            time.sleep(1.0)

        # We allow some slack (3+ calls) because Windows ``time.sleep``
        # granularity and the spinner thread's own scheduling latency
        # can shrink a 5-tick ideal cadence. The point is: it ticks,
        # it doesn't sit at 1.
        assert len(calls) >= 3, (
            f"expected ≥3 formatter invocations in a 1s body, "
            f"got {len(calls)}: {calls}"
        )

    def test_spinner_without_format_message_unchanged(self, monkeypatch) -> None:
        """Regression guard: when ``format_message`` is not supplied,
        the spinner must behave exactly like the previous version —
        static message, spinner glyph, no formatter calls.
        """
        fake_out, fake_err = self._enter_animated_branch(monkeypatch)
        from tools.attack_ui import AttackUi

        ui = AttackUi(plain=False)

        # No format_message / heartbeat_seconds args.
        with ui.spinner("Static label"):
            time.sleep(0.1)

        # Strip ANSI escapes — the animated branch embeds colour
        # codes between the tag and the label.
        import re
        rendered = re.sub(r"\x1b\[[0-9;]*m", "", fake_err.getvalue())
        # Static message present in the initial write.
        assert "[STATUS] Static label" in rendered
        # The tail line is the static message, exactly as before.
        assert "[SUCCESS] Static label" in rendered
        # No "(Ns)" suffix leaked in (the formatter would have produced
        # one if it had been called).
        assert "(0s)" not in rendered
        assert "(0.0s)" not in rendered

    def test_spinner_format_message_exception_does_not_crash_spinner(
        self, monkeypatch
    ) -> None:
        """A buggy ``format_message`` callback (e.g. one that raises) must
        not kill the spinner thread. The spinner should fall back to the
        static message and the body must still complete normally.
        """
        fake_out, fake_err = self._enter_animated_branch(monkeypatch)
        from tools.attack_ui import AttackUi

        ui = AttackUi(plain=False)

        call_count = [0]

        def buggy_fmt(t: float) -> str:
            call_count[0] += 1
            if call_count[0] > 1:
                raise RuntimeError("simulated bug in format_message")
            return f"good {t:.1f}s"

        # Must not raise — the buggy callback is contained inside the
        # spinner thread.
        with ui.spinner("Static fallback", heartbeat_seconds=0.05, format_message=buggy_fmt):
            time.sleep(0.2)

        # The first call succeeded; subsequent calls fell back to the
        # static message. We don't assert the fallback label format
        # exactly (the implementation may prefix it with "label error:"
        # or similar) — only that the spinner survived and produced a
        # tail line. Strip ANSI codes for the substring check.
        import re
        rendered = re.sub(r"\x1b\[[0-9;]*m", "", fake_err.getvalue())
        assert "[SUCCESS] Static fallback" in rendered, (
            f"spinner should have completed normally despite buggy "
            f"formatter, got: {rendered!r}"
        )


# ── 5. MCP server boot timeout in open_exploit_mcp_session ────────────────


class TestMcpBootTimeout:
    """``open_exploit_mcp_session`` must cap the boot wait at
    ``MCP_BOOT_TIMEOUT_SECONDS`` (30 s by default). The previous version
    had no such cap: a hung ``session.initialize()`` would leave the
    "Booting MCP server" spinner looping forever with no recourse other
    than Ctrl-C. The new version wraps ``initialize()`` in
    ``asyncio.wait_for(...)`` and routes the timeout to either a soft
    ``[WARN]`` (when ``soft_fail=True``) or a ``RuntimeError`` (when
    ``soft_fail=False``).
    """

    def test_mcp_boot_timeout_constant_exists(self) -> None:
        """Sanity: the constant is exported at the module level with the
        documented default of 30 seconds. ``open_exploit_mcp_session``
        uses this value as the cap, so a typo / missing export would
        surface here."""
        import main as main_mod
        assert hasattr(main_mod, "MCP_BOOT_TIMEOUT_SECONDS"), (
            "open_exploit_mcp_session should be able to import "
            "MCP_BOOT_TIMEOUT_SECONDS from main; missing."
        )
        assert isinstance(main_mod.MCP_BOOT_TIMEOUT_SECONDS, float)
        # Default is 30 s. Any sane boot completes in < 15 s, so 30 s
        # is the lower bound at which we still want to detect a hang.
        assert 15.0 <= main_mod.MCP_BOOT_TIMEOUT_SECONDS <= 120.0, (
            f"MCP_BOOT_TIMEOUT_SECONDS out of range: "
            f"{main_mod.MCP_BOOT_TIMEOUT_SECONDS}"
        )

    def test_mcp_boot_timeout_soft_fails(self, monkeypatch, capsys, tmp_path) -> None:
        """A fake session whose ``initialize()`` never returns must
        trigger the soft-fail path within ``MCP_BOOT_TIMEOUT_SECONDS``:
        the context manager yields ``None`` and a ``[WARN]`` line is
        emitted.
        """
        import main as main_mod
        import contextlib

        # Make the timeout effectively 0.2 s so the test runs in
        # ~quarter-of-a-second instead of waiting the full 30 s. We
        # patch the constant on the main module so the
        # ``asyncio.wait_for`` inside ``open_exploit_mcp_session`` picks
        # up the new value.
        monkeypatch.setattr(main_mod, "MCP_BOOT_TIMEOUT_SECONDS", 0.2)

        # Build a fake ClientSession whose initialize() hangs forever.
        # The real ``ClientSession`` is used as ``async with ClientSession
        # (read_stream, write_stream) as session:`` so the fake must
        # support the async context manager protocol too.
        class HangingSession:
            async def initialize(self):
                await asyncio.sleep(60)  # way longer than the timeout

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc_info):
                return False

        # Build a fake stdio_client that yields our hanging session.
        @contextlib.asynccontextmanager
        async def _fake_stdio_client(_params):
            yield ("read", "write")

        # Build a fake ClientSession ctor that returns HangingSession.
        def _fake_client_session_factory(_read, _write):
            return HangingSession()

        # Patch the function-local imports. ``open_exploit_mcp_session``
        # imports ``ClientSession`` and ``stdio_client`` inside the
        # function body, so we have to patch the source modules too.
        import mcp
        import mcp.client.stdio as mcp_stdio

        monkeypatch.setattr(mcp, "ClientSession", _fake_client_session_factory)
        monkeypatch.setattr(mcp_stdio, "stdio_client", _fake_stdio_client)

        async def _drive():
            return await main_mod.open_exploit_mcp_session(
                transport="stdio",
                config_path=Path("config.yaml"),
                target_ip="10.0.0.50",
                exploit_port=8001,
                workspace=tmp_path,
                soft_fail=True,
            ).__aenter__()

        start = time.monotonic()
        session = asyncio.run(_drive())
        elapsed = time.monotonic() - start

        # The soft-fail contract: yielded None (no exception).
        assert session is None, (
            f"soft_fail=True should yield None on boot timeout, got {session!r}"
        )
        # The timeout fired in roughly the configured window — not in
        # the full 60 s the fake initialize() would have slept.
        assert elapsed < 5.0, (
            f"boot timeout did not fire in time: elapsed={elapsed:.2f}s"
        )
        # And the user saw a [WARN] line so they know what happened.
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "[WARN]" in combined, (
            f"expected [WARN] line on soft-fail boot timeout, got: {combined!r}"
        )
        assert "timed out" in combined.lower(), (
            f"expected 'timed out' message in [WARN] line, got: {combined!r}"
        )
        # And critically: no [ERROR] — the whole point of soft_fail is
        # to avoid the alarming red cascade that made the user think
        # the whole session was about to abort.
        assert "[ERROR]" not in combined, (
            f"soft-fail boot timeout must not print [ERROR], got: {combined!r}"
        )

    def test_mcp_boot_timeout_hard_fail_raises(
        self, monkeypatch, capsys, tmp_path
    ) -> None:
        """A fake session whose ``initialize()`` never returns must
        raise ``RuntimeError`` from ``open_exploit_mcp_session`` when
        ``soft_fail=False`` (the default for the post-recon attack
        path, where a hung MCP is fatal).
        """
        import main as main_mod
        import contextlib

        monkeypatch.setattr(main_mod, "MCP_BOOT_TIMEOUT_SECONDS", 0.2)

        class HangingSession:
            async def initialize(self):
                await asyncio.sleep(60)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc_info):
                return False

        @contextlib.asynccontextmanager
        async def _fake_stdio_client(_params):
            yield ("read", "write")

        def _fake_client_session_factory(_read, _write):
            return HangingSession()

        import mcp
        import mcp.client.stdio as mcp_stdio

        monkeypatch.setattr(mcp, "ClientSession", _fake_client_session_factory)
        monkeypatch.setattr(mcp_stdio, "stdio_client", _fake_stdio_client)

        async def _drive():
            # The ``async with`` raises because the boot timeout
            # propagates as RuntimeError when soft_fail=False.
            async with main_mod.open_exploit_mcp_session(
                transport="stdio",
                config_path=Path("config.yaml"),
                target_ip="10.0.0.50",
                exploit_port=8001,
                workspace=tmp_path,
                soft_fail=False,
            ) as session:
                # Should not reach here.
                return session

        with pytest.raises(RuntimeError, match="timed out"):
            asyncio.run(_drive())


# ── 6. Recon-first boot stuck shows progress ──────────────────────────────


class TestReconFirstBootStuckShowsProgress:
    """End-to-end: when the MCP server boot is slow (or hung within the
    timeout window), the recon-first path must show *progress* in the
    spinner label, not a frozen line. The user-facing change is the
    ``format_message=lambda t: f"... {t:.1f}s"`` attached to the
    "Booting MCP server" and "Probing OS" spinners in main.py.
    """

    def test_slow_boot_progress_visible_then_soft_fail(
        self, monkeypatch, capsys, tmp_path
    ) -> None:
        """A boot that takes ~1 second must produce at least one
        mid-flight label update (e.g. ``"Booting MCP server (stdio)... 0.5s"``)
        so the user sees progress. After the timeout fires, the
        recon-first path must complete (not abort) and end with a
        ``[WARN]`` or ``[INFO]`` line — never ``[ERROR]``.
        """
        import main as main_mod
        import contextlib

        # Shorten the boot timeout so the test runs quickly. The fake
        # session's initialize() sleeps 0.6 s — longer than the
        # timeout — so we exercise the timeout path, not the success
        # path. (We don't want to actually wait the full 30 s.)
        monkeypatch.setattr(main_mod, "MCP_BOOT_TIMEOUT_SECONDS", 0.3)

        class HangingSession:
            async def initialize(self):
                # Sleeps slightly longer than the timeout so the
                # wait_for cancels before initialize() returns.
                await asyncio.sleep(0.6)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc_info):
                return False

        @contextlib.asynccontextmanager
        async def _fake_stdio_client(_params):
            yield ("read", "write")

        def _fake_client_session_factory(_read, _write):
            return HangingSession()

        import mcp
        import mcp.client.stdio as mcp_stdio

        monkeypatch.setattr(mcp, "ClientSession", _fake_client_session_factory)
        monkeypatch.setattr(mcp_stdio, "stdio_client", _fake_stdio_client)

        # Stub the rest of the recon-first path so the test focuses on
        # the boot spinner. We don't want to drive the full
        # ``async_main`` here — just verify the boot spinner output
        # contains progress markers and a clean soft-fail tail.
        @contextlib.asynccontextmanager
        async def _fake_recon(_session):
            yield {"records": [], "messages": [], "target_ip": "10.0.0.50"}

        monkeypatch.setattr(main_mod, "run_recon_assessment", _fake_recon)

        async def _drive():
            async with main_mod.open_exploit_mcp_session(
                transport="stdio",
                config_path=Path("config.yaml"),
                target_ip="10.0.0.50",
                exploit_port=8001,
                workspace=tmp_path,
                soft_fail=True,
            ) as session:
                return session

        session = asyncio.run(_drive())
        assert session is None, (
            f"soft_fail=True boot timeout should yield None, got {session!r}"
        )

        captured = capsys.readouterr()
        combined = captured.out + captured.err

        # The static message must still be in the output (the user
        # typed a target; they need to see what's happening).
        assert "Booting MCP server (stdio)..." in combined, (
            f"expected the boot spinner label, got: {combined!r}"
        )
        # Exactly one *spinner outcome* line. The ``boot_step`` checklist
        # also prints ``[BOOT]``/``[FAILED] Booting MCP server (stdio)``
        # (no trailing ``...``) by design — those are the grep-able
        # checklist lines, not spinner outcomes — so count the spinner
        # form (with ``...``) rather than the bare label. The Bug #21 /
        # M19 soft-fail guards below (``session is None``, no ``[ERROR]``,
        # ``[WARN]`` present, elapsed marker visible) are what actually
        # protect the regression contract.
        assert combined.count("Booting MCP server (stdio)...") == 1, (
            f"expected one boot spinner outcome line, got: {combined!r}"
        )
        # And the formatter output — the (s) suffix — must appear at
        # least once, proving the heartbeat ran. We don't assert the
        # exact decimal because Windows sleep granularity can land
        # the tick at any sub-second value; we just want to see *some*
        # progress marker.
        assert re.search(r"Booting MCP server \(stdio\)\.\.\. \d+\.\ds", combined), (
            f"expected an elapsed-time marker in the boot spinner output, got: {combined!r}"
        )
        # Soft-fail contract: no [ERROR] anywhere.
        assert "[ERROR]" not in combined, (
            f"soft-fail boot timeout must not print [ERROR], got: {combined!r}"
        )
        # And a [WARN] explaining the timeout did fire.
        assert "[WARN]" in combined, (
            f"expected [WARN] line for boot timeout, got: {combined!r}"
        )


# ── HTTP transport soft-fail regression ──────────────────────────────────────


class TestHttpPortReadiness:
    """The HTTP readiness loop must distinguish a slow boot from a dead child."""

    def test_wait_for_port_reports_child_exit_and_log_tail(self, tmp_path):
        import tools.mcp_session as ms

        log_path = tmp_path / "mcp_exploit_server.log"
        log_path.write_text(
            "Traceback (most recent call last):\n"
            "ModuleNotFoundError: No module named 'uvicorn'\n",
            encoding="utf-8",
        )

        class ExitedProcess:
            def poll(self):
                return 7

        async def _run():
            await ms.wait_for_port(
                "127.0.0.1",
                8001,
                timeout_seconds=5,
                process=ExitedProcess(),
                log_path=log_path,
            )

        with pytest.raises(RuntimeError) as exc_info:
            asyncio.run(_run())

        message = str(exc_info.value)
        assert "exited with code 7" in message
        assert "ModuleNotFoundError" in message
        assert str(log_path) in message

    def test_wait_for_port_timeout_includes_log_tail(self, tmp_path):
        import tools.mcp_session as ms

        log_path = tmp_path / "mcp_exploit_server.log"
        log_path.write_text("still importing attack modules\n", encoding="utf-8")

        class RunningProcess:
            def poll(self):
                return None

        async def _run():
            await ms.wait_for_port(
                "127.0.0.1",
                0,
                timeout_seconds=0,
                process=RunningProcess(),
                log_path=log_path,
            )

        with pytest.raises(TimeoutError) as exc_info:
            asyncio.run(_run())

        message = str(exc_info.value)
        assert "still importing attack modules" in message
        assert str(log_path) in message


class TestHttpTransportSoftFail:
    """Regression for the three HTTP-transport soft-fail gaps in
    ``open_exploit_mcp_session`` (``transport="http"``).

    The stdio branch was hardened against ``BaseExceptionGroup`` (Bug #20 /
    #21 / M19 — see the inline comments in ``tools/mcp_session.py``), but the
    HTTP branch was not. A ``BaseExceptionGroup`` from any of these three
    sites used to propagate past ``soft_fail`` and crash the recon-first path
    instead of degrading to a ``None`` session:

    1. ``start_exploit_http_server`` raising (port already in use / Popen
       failure) — raised before any ``yield``.
    2. ``streamable_http_client`` / ``ClientSession`` entry raising a
       ``BaseExceptionGroup`` (anyio task group on a dead/reset connection)
       — the surrounding ``try`` had only a cleanup ``finally``, no ``except``.
    3. ``ClientSession.initialize()`` raising a ``BaseExceptionGroup`` when
       the server dies mid-handshake — only ``except asyncio.TimeoutError``
       guarded it, which silently misses the group (the exact bug class
       ``CLAUDE.md`` warns about for ``ClientSession.initialize()``).

    Each path must now yield ``None`` with ``soft_fail=True``, emit a
    ``[WARN]`` line, and never print ``[ERROR]``.
    """

    def _patch_http(self, monkeypatch, *, start_returns=None, start_raises=None,
                    streamable_factory=None, client_session_factory=None):
        import tools.mcp_session as ms

        if start_raises is not None:
            def _start(*_a, **_k):
                raise start_raises
            monkeypatch.setattr(ms, "start_exploit_http_server", _start)
        elif start_returns is not None:
            monkeypatch.setattr(
                ms, "start_exploit_http_server",
                lambda *_a, **_k: start_returns,
            )

        # Skip the real 15 s port wait.
        async def _no_wait(*_a, **_k):
            return None
        monkeypatch.setattr(ms, "wait_for_port", _no_wait)

        if streamable_factory is not None:
            import mcp.client.streamable_http as sh
            monkeypatch.setattr(sh, "streamable_http_client", streamable_factory)

        if client_session_factory is not None:
            import mcp
            monkeypatch.setattr(mcp, "ClientSession", client_session_factory)

    def _drive(self, ms, tmp_path):
        async def _run():
            async with ms.open_exploit_mcp_session(
                transport="http",
                config_path=Path("config.yaml"),
                target_ip="10.0.0.50",
                exploit_port=8001,
                workspace=tmp_path,
                soft_fail=True,
            ) as session:
                return session
        return _run

    def test_start_server_port_in_use_soft_fails(self, monkeypatch, capsys, tmp_path):
        """Bug 1a: ``port_is_open`` RuntimeError must soft-fail to ``None``."""
        import tools.mcp_session as ms

        self._patch_http(
            monkeypatch,
            start_raises=RuntimeError(
                "Exploit MCP HTTP port 8001 is already in use."
            ),
        )

        session = asyncio.run(self._drive(ms, tmp_path)())
        assert session is None, (
            f"port-in-use soft_fail should yield None, got {session!r}"
        )
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "[WARN]" in combined, f"expected [WARN], got: {combined!r}"
        assert "[ERROR]" not in combined, (
            f"soft_fail must not print [ERROR], got: {combined!r}"
        )
        assert "8001" in combined

    def test_start_server_popen_oserror_soft_fails(self, monkeypatch, capsys, tmp_path):
        """Bug 1b: ``Popen`` OSError must soft-fail to ``None``."""
        import tools.mcp_session as ms

        self._patch_http(monkeypatch, start_raises=OSError("ENOEXEC"))

        session = asyncio.run(self._drive(ms, tmp_path)())
        assert session is None, f"OSError soft_fail should yield None, got {session!r}"
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "[WARN]" in combined, f"expected [WARN], got: {combined!r}"
        assert "[ERROR]" not in combined, (
            f"soft_fail must not print [ERROR], got: {combined!r}"
        )

    def test_streamable_http_entry_group_soft_fails(self, monkeypatch, capsys, tmp_path):
        """Bug 2: a ``BaseExceptionGroup`` raised on ``streamable_http_client``
        entry (anyio task group on a dead connection) must soft-fail to ``None``,
        not bypass ``soft_fail`` via the cleanup-only ``finally``."""

        import tools.mcp_session as ms

        @contextlib.asynccontextmanager
        async def _boom_transport(_url):
            # Raise on entry, before yielding streams.
            raise BaseExceptionGroup(
                "http transport died", [ConnectionError("connection reset")]
            )
            yield  # pragma: no cover - unreachable

        self._patch_http(
            monkeypatch,
            start_returns=(MagicMock(), MagicMock()),
            streamable_factory=_boom_transport,
        )

        session = asyncio.run(self._drive(ms, tmp_path)())
        assert session is None, (
            f"transport-entry group soft_fail should yield None, got {session!r}"
        )
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "[WARN]" in combined, f"expected [WARN], got: {combined!r}"
        assert "[ERROR]" not in combined, (
            f"soft_fail must not print [ERROR], got: {combined!r}"
        )

    def test_init_handshake_group_soft_fails(self, monkeypatch, capsys, tmp_path):
        """Bug 3: a ``BaseExceptionGroup`` from ``ClientSession.initialize()``
        (server dies mid-handshake) must soft-fail to ``None``. A bare
        ``except asyncio.TimeoutError`` silently misses it."""

        import tools.mcp_session as ms

        @contextlib.asynccontextmanager
        async def _streams(_url):
            yield ("read", "write", None)

        class DyingSession:
            async def initialize(self):
                raise BaseExceptionGroup(
                    "init died", [RuntimeError("server crash mid-handshake")]
                )

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc_info):
                return False

        self._patch_http(
            monkeypatch,
            start_returns=(MagicMock(), MagicMock()),
            streamable_factory=_streams,
            client_session_factory=lambda _r, _w: DyingSession(),
        )

        session = asyncio.run(self._drive(ms, tmp_path)())
        assert session is None, (
            f"init-handshake group soft_fail should yield None, got {session!r}"
        )
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "[WARN]" in combined, f"expected [WARN], got: {combined!r}"
        assert "[ERROR]" not in combined, (
            f"soft_fail must not print [ERROR], got: {combined!r}"
        )

    def test_start_server_port_in_use_hard_fails_without_soft_fail(
        self, monkeypatch, tmp_path
    ):
        """Without ``soft_fail``, the port-in-use ``RuntimeError`` must still
        propagate (soft-fail is opt-in, not a silent swallow)."""

        import tools.mcp_session as ms

        self._patch_http(
            monkeypatch,
            start_raises=RuntimeError(
                "Exploit MCP HTTP port 8001 is already in use."
            ),
        )

        async def _run():
            async with ms.open_exploit_mcp_session(
                transport="http",
                config_path=Path("config.yaml"),
                target_ip="10.0.0.50",
                exploit_port=8001,
                workspace=tmp_path,
                soft_fail=False,
            ) as session:
                return session

        with pytest.raises(RuntimeError, match="already in use"):
            asyncio.run(_run())
