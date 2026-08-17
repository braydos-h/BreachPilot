"""Tier 5 regression tests: ``SwarmMcpBridge`` wires the sync swarm tool
executor to the live MCP ``ClientSession`` owned by ``run_exploit_session``.

The bridge's ``dispatch(name, args)`` is sync (matches ``AgentLoop``'s
``tool_executor`` shape); it hops to the main loop via
``asyncio.run_coroutine_threadsafe`` to call the session-bound
``approve_action`` / ``call_tool`` coroutines. These tests run ``dispatch``
from a worker thread (``asyncio.to_thread``) so the main loop can service the
scheduled coroutines -- the same arrangement the swarm's recon loop uses.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from main import SwarmMcpBridge


def _mcp_result(text: str) -> Any:
    """Build a minimal MCP call_tool result object with a content block."""
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])


@pytest.mark.asyncio
async def test_dispatch_before_attach_returns_blocked():
    bridge = SwarmMcpBridge()
    # No attach() yet -> ready() is False -> BLOCKED marker (no loop needed).
    result = await asyncio.to_thread(bridge.dispatch, "run_exploit_terminal", {"command": "echo"})
    assert result.startswith("BLOCKED")
    assert "not attached" in result
    assert bridge.dispatched == 0


@pytest.mark.asyncio
async def test_dispatch_approves_and_calls_tool(tmp_path):
    bridge = SwarmMcpBridge()
    policy = MagicMock()
    policy.approve_action = AsyncMock(return_value=True)
    session = MagicMock()
    session.call_tool = AsyncMock(return_value=_mcp_result("hello-world"))

    bridge.attach(session, [{"name": "run_exploit_terminal"}], policy, loop=asyncio.get_running_loop())
    text = await asyncio.to_thread(
        bridge.dispatch, "run_exploit_terminal", {"command": "echo hi"}
    )
    assert text == "hello-world"
    policy.approve_action.assert_awaited_once()
    # call_tool received the tool name + arguments verbatim.
    session.call_tool.assert_awaited_once_with("run_exploit_terminal", arguments={"command": "echo hi"})
    assert bridge.dispatched == 1


@pytest.mark.asyncio
async def test_dispatch_denies_does_not_call_tool(tmp_path):
    bridge = SwarmMcpBridge()
    policy = MagicMock()
    policy.approve_action = AsyncMock(return_value=False)
    session = MagicMock()
    session.call_tool = AsyncMock(return_value=_mcp_result("should-not-happen"))

    bridge.attach(session, [], policy, loop=asyncio.get_running_loop())
    text = await asyncio.to_thread(
        bridge.dispatch, "run_exploit_terminal", {"command": "rm -rf /"}
    )
    assert text.startswith("BLOCKED: ExploitPolicy denied run_exploit_terminal")
    session.call_tool.assert_not_awaited()
    assert bridge.dispatched == 0


@pytest.mark.asyncio
async def test_dispatch_call_tool_error_returns_tool_execution_error(tmp_path):
    bridge = SwarmMcpBridge()
    policy = MagicMock()
    policy.approve_action = AsyncMock(return_value=True)
    session = MagicMock()
    session.call_tool = AsyncMock(side_effect=RuntimeError("connection reset"))

    bridge.attach(session, [], policy, loop=asyncio.get_running_loop())
    text = await asyncio.to_thread(
        bridge.dispatch, "run_exploit_terminal", {"command": "echo"}
    )
    assert text.startswith("TOOL_EXECUTION_ERROR:")
    assert "connection reset" in text
    # A failed call_tool must not count as a dispatched tool call.
    assert bridge.dispatched == 0


@pytest.mark.asyncio
async def test_dispatch_approve_error_returns_tool_execution_error(tmp_path):
    bridge = SwarmMcpBridge()
    policy = MagicMock()
    policy.approve_action = AsyncMock(side_effect=RuntimeError("policy boom"))
    session = MagicMock()
    session.call_tool = AsyncMock(return_value=_mcp_result("x"))

    bridge.attach(session, [], policy, loop=asyncio.get_running_loop())
    text = await asyncio.to_thread(
        bridge.dispatch, "run_exploit_terminal", {"command": "echo"}
    )
    assert text.startswith("TOOL_EXECUTION_ERROR:")
    assert "policy approve failed" in text
    session.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_ready_requires_session_policy_and_loop():
    bridge = SwarmMcpBridge()
    assert bridge.ready() is False
    # loop only -> not ready (no session/policy)
    bridge._loop = asyncio.get_running_loop()
    assert bridge.ready() is False
    bridge.attach(MagicMock(), [], MagicMock(), loop=asyncio.get_running_loop())
    assert bridge.ready() is True


@pytest.mark.asyncio
async def test_run_async_rejects_its_bound_loop_without_waiting():
    bridge = SwarmMcpBridge()
    bridge._loop = asyncio.get_running_loop()

    with pytest.raises(RuntimeError, match="cannot run on its MCP event loop"):
        bridge._run_async(asyncio.sleep(0), timeout=0.01)


@pytest.mark.asyncio
async def test_extract_text_handles_empty_content():
    # A result with no content blocks -> falls back to JSON dump of the result.
    out = SwarmMcpBridge._extract_text(SimpleNamespace(content=[]))
    assert out  # non-empty fallback
    # A result with mixed blocks -> text blocks joined.
    out2 = SwarmMcpBridge._extract_text(
        SimpleNamespace(content=[SimpleNamespace(text="a"), SimpleNamespace(text="b")])
    )
    assert out2 == "a\nb"
