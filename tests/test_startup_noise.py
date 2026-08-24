from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_adaptive_startup_details_are_hidden_without_debug(tmp_path, capsys, monkeypatch) -> None:
    """Normal attack startup should not print internal adaptive setup details."""
    from tools.exploit_agent import (
        ExploitPermission,
        ExploitPolicy,
        ExploitSettings,
        run_exploit_agent,
    )

    monkeypatch.delenv("AI_NMAP_DEBUG", raising=False)
    settings = ExploitSettings(
        enabled=True,
        mode="standalone",
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        max_rounds=0,
        attack_max_rounds=0,
        adaptive_exploits_enabled=True,
    )
    policy = ExploitPolicy(settings, tmp_path)

    await run_exploit_agent(
        client=MagicMock(),
        model="glm",
        session=MagicMock(),
        exploit_tools=[],
        policy=policy,
        target_ip="10.0.0.1",
    )

    output = capsys.readouterr().out
    assert "[Adaptive Context]" not in output
    assert "[Adaptive Exploits] Enabled" not in output


@pytest.mark.asyncio
async def test_thinking_hidden_without_verbose_reasoning(tmp_path, capsys, monkeypatch) -> None:
    from tools.exploit_agent import (
        ExploitPermission,
        ExploitPolicy,
        ExploitSettings,
        run_exploit_agent,
    )

    monkeypatch.delenv("AI_NMAP_DEBUG", raising=False)
    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.READ_ONLY,
        max_rounds=1,
    )
    policy = ExploitPolicy(settings, tmp_path)
    client = MagicMock()
    client.chat.return_value = {
        "message": {
            "content": "Done.",
            "thinking": "internal chain of thought",
            "tool_calls": [],
        }
    }

    await run_exploit_agent(
        client=client,
        model="glm",
        session=AsyncMock(),
        exploit_tools=[],
        policy=policy,
        target_ip="10.0.0.1",
    )

    output = capsys.readouterr().out
    assert "[Thinking]" not in output
    assert "internal chain of thought" not in output


@pytest.mark.asyncio
async def test_invalid_tool_feedback_lists_actual_available_tools(tmp_path) -> None:
    from tools.exploit_agent import (
        ExploitPermission,
        ExploitPolicy,
        ExploitSettings,
        run_exploit_agent,
    )

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.READ_ONLY,
        max_rounds=2,
    )
    policy = ExploitPolicy(settings, tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        {
            "message": {
                "content": "Trying malformed call.",
                "tool_calls": [{"function": {"name": "", "arguments": {}}}],
            }
        },
        {"message": {"content": "Done.", "tool_calls": []}},
    ]
    tools = [
        {"type": "function", "function": {"name": "check_os"}},
        {"type": "function", "function": {"name": "quick_scan"}},
    ]

    result = await run_exploit_agent(
        client=client,
        model="glm",
        session=AsyncMock(),
        exploit_tools=tools,
        policy=policy,
        target_ip="10.0.0.1",
    )

    user_feedback = "\n".join(msg.get("content", "") for msg in result["messages"] if msg.get("role") == "user")
    assert "Valid tools are: check_os, quick_scan." in user_feedback


@pytest.mark.asyncio
async def test_read_only_block_allows_proposal_finish_without_phase_loop(tmp_path) -> None:
    from tools.exploit_agent import (
        ExploitPermission,
        ExploitPolicy,
        ExploitSettings,
        run_exploit_agent,
    )

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.READ_ONLY,
        max_rounds=5,
    )
    policy = ExploitPolicy(settings, tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        {
            "message": {
                "content": "I'll run a command.",
                "tool_calls": [
                    {
                        "function": {
                            "name": "run_exploit_terminal",
                            "arguments": {"command": "nmap -sV 10.0.0.1"},
                        }
                    }
                ],
            }
        },
        {"message": {"content": "Proposal only.", "tool_calls": []}},
    ]

    result = await run_exploit_agent(
        client=client,
        model="glm",
        session=AsyncMock(),
        exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
        policy=policy,
        target_ip="10.0.0.1",
    )

    tool_feedback = "\n".join(msg.get("content", "") for msg in result["messages"] if msg.get("role") == "tool")
    assert "read_only mode" in tool_feedback
    assert "user denied" not in tool_feedback
    assert client.chat.call_count == 2


@pytest.mark.asyncio
async def test_repeated_blocked_tool_results_stop_with_summary(tmp_path) -> None:
    from tools.exploit_agent import (
        ExploitPermission,
        ExploitPolicy,
        ExploitSettings,
        run_exploit_agent,
    )

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=10,
        attack_max_commands=10,
    )
    policy = ExploitPolicy(settings, tmp_path)
    client = MagicMock()
    blocked_call = {
        "message": {
            "content": "Checking OS.",
            "tool_calls": [
                {
                    "function": {
                        "name": "check_os",
                        "arguments": {"target_ip": "10.0.0.1"},
                    }
                }
            ],
        }
    }
    client.chat.side_effect = [blocked_call, blocked_call, blocked_call]
    session = AsyncMock()
    session.call_tool.return_value = MagicMock(
        content=[{"text": "BLOCKED: require_explicit_allowlist is True but allowed_targets is empty"}]
    )

    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "Blocked summary."}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "check_os"}}],
            policy=policy,
            target_ip="10.0.0.1",
        )

    assert session.call_tool.call_count == 3
    assert stream.await_count == 1
    user_feedback = "\n".join(msg.get("content", "") for msg in result["messages"] if msg.get("role") == "user")
    assert "Repeated blocked or unavailable tool outcomes" in user_feedback


def test_plain_spinner_emits_single_elapsed_line(capsys) -> None:
    from tools.attack_ui import AttackUi

    ui = AttackUi(plain=True)
    with ui.spinner(
        "Booting MCP server (stdio)...",
        format_message=lambda t: f"Booting MCP server (stdio)... {t:.1f}s",
    ):
        pass

    output = capsys.readouterr().out
    assert output.count("Booting MCP server") == 1
    assert "[STATUS]" not in output
    assert "[SUCCESS] Booting MCP server (stdio)..." in output
