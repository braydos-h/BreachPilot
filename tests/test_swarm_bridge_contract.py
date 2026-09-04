"""Bridge contract tests: attach/re-attach, same-loop guard, snapshot hook.

Companion to ``tests/test_swarm_mcp_bridge.py`` (dispatch approve/deny/error
paths). Covers the load-bearing seams documented on ``SwarmMcpBridge``:

- ``attach`` captures the session/policy/loop/config quadruple; a second
  ``attach`` REPLACES it (single-session invariant — at most one live
  session is ever referenced).
- ``dispatch`` on the bound loop never deadlocks: it surfaces
  ``TOOL_EXECUTION_ERROR`` instead of raising into the agent.
- The destructive-snapshot hook (``_snapshot_before_destructive``) fires
  through ``dispatch`` when configured, stays inert when ``config`` is None,
  and is fail-open (a snapshot failure never blocks the tool call).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from main import SwarmMcpBridge


def _mcp_result(text: str) -> Any:
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])


def _wired_bridge(**kwargs: Any) -> tuple[SwarmMcpBridge, MagicMock, MagicMock]:
    """Bridge attached to a fake session/policy on the running loop."""
    bridge = SwarmMcpBridge()
    policy = MagicMock()
    policy.approve_action = AsyncMock(return_value=True)
    session = MagicMock()
    session.call_tool = AsyncMock(return_value=_mcp_result("ok"))
    bridge.attach(session, [], policy, loop=asyncio.get_running_loop(), **kwargs)
    return bridge, session, policy


@pytest.mark.asyncio
async def test_reattach_replaces_session_single_invariant():
    bridge, session1, _ = _wired_bridge()
    assert bridge.ready() is True
    session2 = MagicMock()
    session2.call_tool = AsyncMock(return_value=_mcp_result("second"))
    policy2 = MagicMock()
    policy2.approve_action = AsyncMock(return_value=True)
    bridge.attach(session2, [], policy2, loop=asyncio.get_running_loop())
    text = await asyncio.to_thread(bridge.dispatch, "run_exploit_terminal", {"command": "echo hi"})
    assert text == "second"
    session1.call_tool.assert_not_awaited()
    session2.call_tool.assert_awaited_once()
    assert bridge.dispatched == 1


@pytest.mark.asyncio
async def test_attach_captures_config():
    cfg = {"snapshots": {"enabled": False}}
    bridge, _, _ = _wired_bridge(config=cfg)
    assert bridge._config is cfg


@pytest.mark.asyncio
async def test_dispatch_on_bound_loop_returns_tool_execution_error():
    # Called directly on the event loop (not via to_thread): _run_async must
    # refuse instead of deadlocking, and dispatch must convert that into a
    # TOOL_EXECUTION_ERROR string rather than raising into the agent.
    bridge, session, _ = _wired_bridge()
    text = bridge.dispatch("run_exploit_terminal", {"command": "echo hi"})
    assert text.startswith("TOOL_EXECUTION_ERROR:")
    assert "cannot run on its MCP event loop" in text
    session.call_tool.assert_not_awaited()
    assert bridge.dispatched == 0


@pytest.mark.asyncio
async def test_snapshot_hook_fires_on_destructive_dispatch(tmp_path, monkeypatch):
    calls: dict[str, Any] = {}

    def _fake_should_snapshot(tool_name: str, payload: str, config: Any) -> bool:
        calls["tool"] = tool_name
        calls["payload"] = payload
        return True

    class _FakeManager:
        def __init__(self, config: Any, index_dir: str = ".") -> None:
            calls["index_dir"] = index_dir

        def before_destructive(self, vm_id: str, label: str) -> Any:
            calls["vm_id"] = vm_id
            calls["label"] = label
            return SimpleNamespace(snapshot_id="snap-1", provider="fake")

    monkeypatch.setattr("tools.snapshots.should_snapshot", _fake_should_snapshot)
    monkeypatch.setattr("tools.snapshots.SnapshotManager", _FakeManager)
    cfg = {"snapshots": {"enabled": True}, "exploit": {"workspace_dir": str(tmp_path)}}
    bridge, session, _ = _wired_bridge(config=cfg)
    text = await asyncio.to_thread(bridge.dispatch, "run_exploit_terminal", {"command": "nmap -sV 10.0.0.5"})
    assert text == "ok"
    # Hook ran before the tool call: tool name passed through, an IP was
    # extracted from the payload for the vm_id, dispatch still proceeded.
    assert calls["tool"] == "run_exploit_terminal"
    assert "10.0.0.5" in str(calls["payload"])
    assert calls["vm_id"] == "10.0.0.5"
    assert calls["label"] == "pre-run_exploit_terminal"
    session.call_tool.assert_awaited_once()
    assert bridge.dispatched == 1


@pytest.mark.asyncio
async def test_snapshot_hook_inert_without_config(monkeypatch):
    def _boom(tool_name: str, payload: str, config: Any) -> bool:  # pragma: no cover
        raise AssertionError("should_snapshot must not run when config is None")

    monkeypatch.setattr("tools.snapshots.should_snapshot", _boom)
    bridge, session, _ = _wired_bridge()  # no config attached
    text = await asyncio.to_thread(bridge.dispatch, "run_exploit_terminal", {"command": "nmap -sV 10.0.0.5"})
    assert text == "ok"
    session.call_tool.assert_awaited_once()


@pytest.mark.asyncio
async def test_snapshot_hook_fail_open(monkeypatch):
    def _fail(tool_name: str, payload: str, config: Any) -> bool:
        raise RuntimeError("snapshot infra down")

    monkeypatch.setattr("tools.snapshots.should_snapshot", _fail)
    cfg = {"snapshots": {"enabled": True}, "exploit": {"workspace_dir": "."}}
    bridge, session, _ = _wired_bridge(config=cfg)
    # A snapshot failure logs and the dispatch proceeds (fail-open contract).
    text = await asyncio.to_thread(bridge.dispatch, "run_exploit_terminal", {"command": "nmap -sV 10.0.0.5"})
    assert text == "ok"
    session.call_tool.assert_awaited_once()
    assert bridge.dispatched == 1
