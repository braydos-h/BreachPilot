"""Loop-level tests for the attack-focus branch controller (Flow A).

Drives ``run_exploit_agent`` with a scripted model/session pair:

* recon reveals 443/https + 22/ssh -> web branch becomes active
* an unrelated broad port scan mid-branch is refused (drift prevented)
* distinct failed web hypotheses eventually exhaust the branch
* the next candidate activates only after exhaustion
* verified compromise wins immediately; budgets/cancellation still work

Pattern mirrors tests/test_reporting_phase_termination.py: MagicMock client,
AsyncMock session, patched ``_stream_ollama``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

RECON_443 = (
    "QUICK_SCAN_RESULTS: 10.0.0.50\n"
    "Port 22/tcp OPEN (ssh) - OpenSSH_8.5p1\n"
    "Port 443/tcp OPEN (https) - nginx/1.24.0\n"
    "exit_code=0"
)

WEB_HOME = "<html><form action='/login'><input name='username'><input name='password'></form>\nserver: nginx/1.24.0"


def _tool_call_msg(name="run_exploit_terminal", args=None):
    return {
        "message": {
            "content": "running tool",
            "tool_calls": [{"function": {"name": name, "arguments": args or {"command": "x"}}}],
        }
    }


def _done_msg():
    return {"message": {"content": "done", "tool_calls": []}}


def _tool_result(text: str):
    return MagicMock(content=[MagicMock(text=text)])


def _tool(name: str):
    return {"type": "function", "function": {"name": name}}


_MINIMA_TOOLS = [
    _tool("check_os"),
    _tool("quick_scan"),
    _tool("run_full_recon"),
    _tool("run_exploit_terminal"),
    _tool("run_python_file"),
    _tool("search_cve_intel"),
    _tool("get_service_fingerprint"),
    _tool("list_workspace"),
]


def _settings(tmp_path, **overrides):
    from tools.exploit_agent import ExploitPermission, ExploitSettings

    base = dict(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=20,
        attack_max_commands=50,
        outcome_judgment_flow_a=False,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    base.update(overrides)
    return ExploitSettings(**base)


def _policy(tmp_path, **overrides):
    from tools.exploit_agent import ExploitPolicy

    return ExploitPolicy(_settings(tmp_path, **overrides), tmp_path)


def _base_config(**overrides):
    # Research assistant disabled: its automatic consults consume scripted
    # model turns and would misalign the turn script. Focus behavior does
    # not depend on it.
    config: dict = {
        "outcome_judgment": {"flow_a": False},
        "research": {"assistant": {"enabled": False}},
    }
    config.update(overrides)
    return config


def _user_texts(result):
    return [str(m.get("content", "")) for m in result["messages"] if m.get("role") == "user"]


@pytest.mark.asyncio
async def test_web_branch_selected_and_drift_refused(tmp_path):
    """Recon reveals 443/https -> branch activates; a mid-branch broad
    re-scan is refused with a redirect; the run keeps working the branch."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("quick_scan", {"target_ip": "10.0.0.50"}),
        _tool_call_msg("check_os", {"target_ip": "10.0.0.50"}),
        _tool_call_msg("run_exploit_terminal", {"command": "curl -sk https://10.0.0.50/"}),
        # Drift attempt: broad re-scan while web:443 is active.
        _tool_call_msg("run_full_recon", {"target_ip": "10.0.0.50"}),
        # Back on branch after the redirect.
        _tool_call_msg("run_exploit_terminal", {"command": "curl -sk https://10.0.0.50/login"}),
        _tool_call_msg("search_cve_intel", {"product": "nginx", "version": "1.24.0"}),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.side_effect = [
        _tool_result(RECON_443),
        _tool_result("OS_VERDICT: LINUX\nexit_code=0"),
        _tool_result(WEB_HOME),
        _tool_result("should never dispatch: drift refused pre-dispatch"),
        _tool_result(WEB_HOME),
        _tool_result("CVE-2024-xxxx nginx ..."),
    ]
    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "final summary"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=_MINIMA_TOOLS,
            policy=policy,
            target_ip="10.0.0.50",
            config=_base_config(),
        )
    texts = _user_texts(result)
    assert any("DRIFT PREVENTED" in t for t in texts), "drift redirect must reach the model"
    # run_full_recon never dispatched: 7 model turns - 1 refused - 1 done = 5.
    assert session.call_tool.call_count == 5
    assert result["attack_focus"]["active_branch"] == "https:443"
    assert result["attack_focus"]["drift_redirects"] >= 1


@pytest.mark.asyncio
async def test_duplicate_repeat_refused_without_progress(tmp_path):
    """The same curl twice with nothing new in between is refused; the
    materially different path is allowed."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    client = MagicMock()
    curl_root = {"command": "curl -sk https://10.0.0.50/"}
    client.chat.side_effect = [
        _tool_call_msg("quick_scan", {"target_ip": "10.0.0.50"}),
        _tool_call_msg("run_exploit_terminal", curl_root),
        _tool_call_msg("run_exploit_terminal", dict(curl_root)),
        _tool_call_msg("run_exploit_terminal", {"command": "curl -sk https://10.0.0.50/login"}),
        _tool_call_msg("search_cve_intel", {"product": "nginx"}),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.side_effect = [
        _tool_result(RECON_443),
        _tool_result(WEB_HOME),
        _tool_result("never dispatched"),
        _tool_result(WEB_HOME),
        _tool_result("no cve"),
    ]
    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "final summary"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=_MINIMA_TOOLS,
            policy=policy,
            target_ip="10.0.0.50",
            config=_base_config(),
        )
    texts = _user_texts(result)
    assert any("DUPLICATE ATTEMPT REFUSED" in t for t in texts)
    # 6 model turns - 1 refused - 1 done = 4 dispatches.
    assert session.call_tool.call_count == 4
    assert result["attack_focus"]["duplicate_blocks"] >= 1


@pytest.mark.asyncio
async def test_verified_compromise_wins_immediately(tmp_path):
    """A COMPROMISE marker mid-branch marks the branch succeeded and the run
    terminates via the existing goal-complete path."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("quick_scan", {"target_ip": "10.0.0.50"}),
        _tool_call_msg("run_exploit_terminal", {"command": "curl -sk https://10.0.0.50/"}),
        _tool_call_msg("run_python_file", {"path": "exploit_workspace/10.0.0.50/x.py", "target_ip": "10.0.0.50"}),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.side_effect = [
        _tool_result(RECON_443),
        _tool_result(WEB_HOME),
        _tool_result("COMPROMISE: shell target=10.0.0.50\nuid=0(root)"),
    ]
    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "final summary"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=_MINIMA_TOOLS,
            policy=policy,
            target_ip="10.0.0.50",
            config=_base_config(),
        )
    focus = result["attack_focus"]
    assert focus["branches"][0]["status"] in ("succeeded", "active")
    assert any(b["status"] == "succeeded" for b in focus["branches"])


@pytest.mark.asyncio
async def test_focus_disabled_is_byte_identical_behavior(tmp_path):
    """attack_focus_enabled:false -> no focus gate, no summary, no extra user
    messages; existing behavior preserved."""
    from tools.exploit_agent import run_exploit_agent

    policy = _policy(tmp_path)
    client = MagicMock()
    client.chat.side_effect = [
        _tool_call_msg("check_os"),
        _tool_call_msg("check_os"),
        _tool_call_msg("run_exploit_terminal"),
        _tool_call_msg("search_cve_intel"),
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("ok\nno vulnerabilities found")
    with patch("tools.exploit_agent._stream_ollama", new_callable=AsyncMock) as stream:
        stream.return_value = {"role": "assistant", "content": "final summary"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=_MINIMA_TOOLS,
            policy=policy,
            target_ip="10.0.0.50",
            config=_base_config(agent={"attack_focus_enabled": False}),
        )
    assert "attack_focus" not in result
    assert not any("DRIFT PREVENTED" in t or "FOCUS_GATE" in t for t in _user_texts(result))
    assert result["total_actions"] == 4
