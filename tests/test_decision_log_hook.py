"""Tests for the §17 decision-log hook in the exploit-agent loop.

Drives ``run_exploit_agent`` with a faked MCP session that returns one tool
call + one tool result, and asserts the decision-log hook fires with the
expected fields. The hook is best-effort and fail-silent; we verify it is
called and that a real ``decision_log.jsonl`` row lands on disk.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch


def _tool_call_msg(name="run_exploit_terminal", args=None):
    return {
        "message": {
            "content": "running exploit",
            "tool_calls": [
                {"function": {"name": name, "arguments": args or {"command": "exploit"}}}
            ],
        }
    }


def _done_msg():
    return {"message": {"content": "done", "tool_calls": []}}


def _tool_result(text: str):
    return MagicMock(content=[MagicMock(text=text)])


def _policy(tmp_path):
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=1,
        attack_max_commands=5,
        outcome_judgment_flow_a=False,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    return ExploitPolicy(settings, tmp_path)


import pytest  # noqa: E402


@pytest.mark.asyncio
async def test_decision_log_hook_writes_row_on_success(tmp_path):
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    reports = tmp_path / "reports"

    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result(
        "COMPROMISE: shell gained target=10.0.0.50\n"
        "evidence saved to exploit_workspace/10.0.0.50/ATT-1/terminal.log"
    )

    with patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[
                {"type": "function", "function": {"name": "run_exploit_terminal"}}
            ],
            policy=policy,
            target_ip="10.0.0.50",
            reports_dir=reports,
            config={"outcome_judgment": {"flow_a": False}},
        )

    log_path = reports / "decision_log.jsonl"
    assert log_path.exists(), "decision_log.jsonl was not written"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows, "decision_log.jsonl is empty"
    # At least one row for the exploit action.
    exploit_rows = [r for r in rows if r.get("capability") == "run_exploit_terminal"]
    assert exploit_rows, f"no row for run_exploit_terminal: {rows}"
    row = exploit_rows[0]
    assert row["target"] == "10.0.0.50"
    assert row["round"] == 1
    # success True on compromise; failure_class empty for a success.
    assert row["success"] is True
    assert row["failure_class"] == ""
    assert row["evidence_refs"] is not None


@pytest.mark.asyncio
async def test_decision_log_hook_records_failure_class_on_failure(tmp_path):
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    reports = tmp_path / "reports"

    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    # A failure result: non-zero exit + failure marker. classify_failure maps
    # "VULN_NOT_CONFIRMED" to FALSE_POSITIVE.
    session.call_tool.return_value = _tool_result(
        "VULN_NOT_CONFIRMED: target not vulnerable\nexit code: 1"
    )

    with patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[
                {"type": "function", "function": {"name": "run_exploit_terminal"}}
            ],
            policy=policy,
            target_ip="10.0.0.50",
            reports_dir=reports,
            config={"outcome_judgment": {"flow_a": False}},
        )

    rows = [
        json.loads(line)
        for line in (reports / "decision_log.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    exploit_rows = [r for r in rows if r.get("capability") == "run_exploit_terminal"]
    assert exploit_rows
    row = exploit_rows[0]
    assert row["success"] is False
    # FALSE_POSITIVE is the classified failure class for VULN_NOT_CONFIRMED.
    assert row["failure_class"] == "false_positive_hypothesis"


@pytest.mark.asyncio
async def test_decision_log_hook_never_breaks_loop_when_logdir_unwritable(tmp_path):
    """A logging failure must not abort the loop. Point reports_dir at a path
    whose parent is a file so mkdir fails; the hook swallows and the run still
    completes."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    # A path whose parent is a regular file → mkdir/write will raise.
    blocker = tmp_path / "blocker_file"
    blocker.write_text("x")
    reports = blocker / "reports"

    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result(
        "COMPROMISE: shell gained target=10.0.0.50"
    )

    with patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        # Should not raise even though logging cannot write.
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[
                {"type": "function", "function": {"name": "run_exploit_terminal"}}
            ],
            policy=policy,
            target_ip="10.0.0.50",
            reports_dir=reports,
            config={"outcome_judgment": {"flow_a": False}},
        )

    assert result is not None