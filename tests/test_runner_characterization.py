"""Runner behavior characterization (packet 04, pre-extraction safety net).

Pins existing `run_exploit_agent` loop behavior with the same fake-stream
harness as `test_exploit_engine_core.py`, so the coming seam extractions
can prove no drift. Focus is intentionally disabled here (branch/drift
behavior already lives in `test_attack_focus_loop.py`); these tests pin the
loop controller, tool-error, and stopping-policy seams:

- unknown tools are never dispatched and are recorded as blocked;
- the command budget caps MCP dispatches even when the model keeps asking;
- empty model replies terminate gracefully instead of looping forever.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_NO_FOCUS = {"agent": {"attack_focus_enabled": False}}


def _settings(tmp_path, **overrides):
    from tools.exploit_agent import ExploitPermission, ExploitSettings

    base = dict(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=3,
        attack_max_commands=20,
        attack_max_duration_minutes=60,
        outcome_judgment_flow_a=False,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    base.update(overrides)
    return ExploitSettings(**base)


def _policy(tmp_path, **overrides):
    from tools.exploit_agent import ExploitPolicy

    return ExploitPolicy(_settings(tmp_path, **overrides), tmp_path)


def _tool_call_msg(name="run_exploit_terminal", args=None):
    return {
        "message": {
            "content": "running tool",
            "tool_calls": [{"function": {"name": name, "arguments": args or {"command": "x"}}}],
        }
    }


def _text_msg(content: str):
    return {"message": {"content": content, "tool_calls": []}}


def _tool_result(text: str):
    return MagicMock(content=[MagicMock(text=text)])


def _check_os_schema():
    return [{"type": "function", "function": {"name": "check_os"}}]


async def _fake_stream(*a, **k):
    return {"role": "assistant", "content": "summary", "thinking": ""}


async def _run(tmp_path, *, messages, session=None, tools=None, config=None, **policy_overrides):
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path, **policy_overrides)
    client = MagicMock()
    client.chat.side_effect = messages
    session = session if session is not None else AsyncMock()
    if isinstance(session, AsyncMock):
        session.call_tool.return_value = _tool_result("ok")
    with (
        patch("tools.exploit_agent.runner._impl._stream_model", side_effect=_fake_stream),
        patch("tools.exploit_agent._stream_model", side_effect=_fake_stream),
    ):
        result = await run_exploit_agent(
            client=client,
            model="fake",
            session=session,
            exploit_tools=tools if tools is not None else _check_os_schema(),
            policy=policy,
            target_ip="10.0.0.50",
            config=config if config is not None else dict(_NO_FOCUS),
        )
    return result, client, session


@pytest.mark.asyncio
async def test_unknown_tool_never_dispatched_and_recorded(tmp_path):
    """A hallucinated tool name is refused locally (no MCP dispatch) and shows
    up in the outcome summary as blocked/unavailable."""
    result, _client, session = await _run(
        tmp_path,
        messages=[_tool_call_msg("no_such_tool"), _text_msg("done")],
    )
    assert session.call_tool.await_count == 0
    assert "no_such_tool" in result["outcome_summary"]


@pytest.mark.asyncio
async def test_command_budget_caps_dispatches(tmp_path):
    """`attack_max_commands=1` lets exactly one MCP dispatch through even when
    the model keeps requesting tool calls."""
    result, _client, session = await _run(
        tmp_path,
        messages=[
            _tool_call_msg("check_os"),
            _tool_call_msg("check_os"),
            _tool_call_msg("check_os"),
            _text_msg("done"),
        ],
        attack_max_commands=1,
    )
    assert session.call_tool.await_count == 1
    assert result["total_actions"] >= 1


@pytest.mark.asyncio
async def test_empty_model_replies_terminate_gracefully(tmp_path):
    """Rounds with no tool calls (plain or backend-ERROR) end the run instead
    of spinning: no dispatches, no hang, zero billed actions."""
    result, client, session = await _run(
        tmp_path,
        messages=[
            _text_msg("thinking out loud"),
            _text_msg("ERROR: provider hiccup"),
            _text_msg("ERROR: provider hiccup"),
            _text_msg("ERROR: provider hiccup"),
            _text_msg("done"),
        ],
        attack_max_rounds=5,
    )
    assert session.call_tool.await_count == 0
    assert result["total_actions"] == 0
    assert client.chat.call_count <= 5
