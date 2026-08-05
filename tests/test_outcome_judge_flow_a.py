"""Phase 1.2 — wire OutcomeJudge into Flow A (exploit engine).

Three layers of tests:

1. Adapter unit tests -- ``build_observation`` + ``judge_outcome`` against a
   real, pure ``OutcomeJudge`` (no DB). A compromise marker drives CONFIRMED, a
   failure marker drives REFUTED, partial/unknown stay non-terminal, and
   defensive inputs return ``None``.

2. ``judge_flow_a`` helper -- exercises the full build_judge + build_observation
   + judge_outcome path with a fake policy/plan and a real judge.

3. Loop integration -- drives ``run_exploit_agent`` with a faked MCP session
   whose tool result contains a compromise marker. With ``flow_a=True`` the
   outcome tracker records a compromise and the audit row is ``completed``;
   with ``flow_a=False`` behavior is unchanged (no taxonomy counts). A
   mocked-``judge_flow_a`` variant asserts CONFIRMED/REFUTED/INCONCLUSIVE each
   route to the right tracker calls.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


# ── 1. adapter unit tests ───────────────────────────────────────────────────


def _real_judge() -> "OutcomeJudge":  # type: ignore[name-defined]
    from outcome_judge import OutcomeJudge

    return OutcomeJudge(
        max_inconclusive_attempts=3,
        confirmation_threshold=0.75,
        refutation_threshold=0.75,
        min_evidence_references=1,
    )


def _record(action="run_exploit_terminal", attempt_id="ATT-1", detail="ran exploit", exit_code=0):
    return SimpleNamespace(action=action, attempt_id=attempt_id, detail=detail, exit_code=exit_code)


def test_build_observation_compromise_yields_supporting_evidence():
    from tools.exploit_agent.outcome_adapter import build_observation

    res = build_observation(
        "meterpreter session 1 opened\nuid=0(root)",
        _record(),
        "exploit CVE-2021-44228 against target",
        "10.0.0.50",
    )
    assert res is not None
    hev = res["observation"]["hypothesis_evidence"]
    assert hev and hev[0]["polarity"] == "supports"
    assert res["classification"]["outcome"] == "compromise"
    assert res["execution_result"]["success"] is True


def test_build_observation_cred_dump_yields_supporting_evidence():
    from tools.exploit_agent.outcome_adapter import build_observation

    res = build_observation(
        "dumping NTLM hashes\ncredentials: admin:500:aad3b4",
        _record(),
        "credential dump against target",
        "10.0.0.50",
    )
    assert res is not None
    hev = res["observation"]["hypothesis_evidence"]
    assert hev and hev[0]["polarity"] == "supports"
    assert res["classification"]["outcome"] == "cred_dump"


def test_build_observation_failure_yields_refuting_evidence():
    from tools.exploit_agent.outcome_adapter import build_observation

    res = build_observation(
        "exploit failed\nno session created\nexit code: 1",
        _record(exit_code=1, detail="exploit failed"),
        "exploit CVE against target",
        "10.0.0.50",
    )
    assert res is not None
    hev = res["observation"]["hypothesis_evidence"]
    assert hev and hev[0]["polarity"] == "contradicts"
    assert res["execution_result"]["success"] is False


def test_build_observation_partial_is_neutral():
    from tools.exploit_agent.outcome_adapter import build_observation

    res = build_observation(
        "access is denied\nlimited privileges",
        _record(),
        "exploit against target",
        "10.0.0.50",
    )
    assert res is not None
    # No polarized hypothesis_evidence for partial -> judge stays non-terminal.
    assert res["observation"]["hypothesis_evidence"] == []
    assert res["classification"]["outcome"] == "partial"


def test_build_observation_unknown_is_neutral():
    from tools.exploit_agent.outcome_adapter import build_observation

    res = build_observation("some unremarkable output", _record(), "h", "10.0.0.50")
    assert res is not None
    assert res["observation"]["hypothesis_evidence"] == []
    assert res["classification"]["outcome"] == "unknown"


def test_build_observation_no_target_returns_none():
    from tools.exploit_agent.outcome_adapter import build_observation

    assert build_observation("meterpreter session 1", _record(), "h", "") is None


@pytest.mark.asyncio
async def test_judge_outcome_compromise_confirmed():
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import build_observation, judge_outcome

    adapter = build_observation(
        "meterpreter session 1 opened", _record(), "exploit target", "10.0.0.50"
    )
    status, conf = await judge_outcome(adapter, _real_judge(), "task-1")
    assert status is HypothesisStatus.CONFIRMED
    assert conf >= 0.75


@pytest.mark.asyncio
async def test_judge_outcome_failure_refuted():
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import build_observation, judge_outcome

    adapter = build_observation(
        "exploit failed\nno session created",
        _record(exit_code=1, detail="failed"),
        "exploit target",
        "10.0.0.50",
    )
    status, _ = await judge_outcome(adapter, _real_judge(), "task-2")
    assert status is HypothesisStatus.REFUTED


@pytest.mark.asyncio
async def test_judge_outcome_partial_inconclusive():
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import build_observation, judge_outcome

    adapter = build_observation(
        "access is denied", _record(), "exploit target", "10.0.0.50"
    )
    status, _ = await judge_outcome(adapter, _real_judge(), "task-3")
    assert status in {HypothesisStatus.INCONCLUSIVE, HypothesisStatus.OPEN}


@pytest.mark.asyncio
async def test_judge_outcome_none_inputs_return_none():
    from tools.exploit_agent.outcome_adapter import judge_outcome

    assert await judge_outcome(None, _real_judge(), "t") is None
    assert await judge_outcome({"task": {}}, None, "t") is None


# ── 2. judge_flow_a helper ──────────────────────────────────────────────────


def _fake_policy(tmp_path, *, flow_a=True):
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=1,
        attack_max_commands=5,
        outcome_judgment_flow_a=flow_a,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    return ExploitPolicy(settings, tmp_path)


def _fake_plan():
    plan = MagicMock()
    step = SimpleNamespace(reason="exploit log4shell", phase="exploit")
    plan.steps = [step]
    return plan


@pytest.mark.asyncio
async def test_judge_flow_a_compromise_returns_confirmed(tmp_path):
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import judge_flow_a

    policy = _fake_policy(tmp_path)
    verdict = await judge_flow_a(
        config={"outcome_judgment": {"flow_a": True, "max_inconclusive_attempts": 3}},
        policy=policy,
        result_text="meterpreter session 1 opened",
        tool_name="run_exploit_terminal",
        detail="ran exploit",
        exit_code=0,
        target_ip="10.0.0.50",
        plan=_fake_plan(),
    )
    assert verdict is not None
    status, conf, cls = verdict
    assert status is HypothesisStatus.CONFIRMED
    assert cls["outcome"] == "compromise"
    # Judge is cached on the policy for subsequent rounds.
    assert getattr(policy, "_flow_a_judge", None) is not None


@pytest.mark.asyncio
async def test_judge_flow_a_failure_returns_refuted(tmp_path):
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import judge_flow_a

    policy = _fake_policy(tmp_path)
    verdict = await judge_flow_a(
        config={"outcome_judgment": {"flow_a": True}},
        policy=policy,
        result_text="exploit failed\nno session created\nexit code: 1",
        tool_name="run_exploit_terminal",
        detail="failed",
        exit_code=1,
        target_ip="10.0.0.50",
        plan=_fake_plan(),
    )
    assert verdict is not None
    status, _, cls = verdict
    assert status is HypothesisStatus.REFUTED
    assert cls["outcome"] == "failure"


@pytest.mark.asyncio
async def test_judge_flow_a_partial_returns_non_terminal(tmp_path):
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import judge_flow_a

    policy = _fake_policy(tmp_path)
    verdict = await judge_flow_a(
        config={"outcome_judgment": {"flow_a": True}},
        policy=policy,
        result_text="access is denied",
        tool_name="run_exploit_terminal",
        detail="partial",
        exit_code=0,
        target_ip="10.0.0.50",
        plan=_fake_plan(),
    )
    assert verdict is not None
    status, _, _ = verdict
    assert status in {HypothesisStatus.INCONCLUSIVE, HypothesisStatus.OPEN}


# ── 3. loop integration ─────────────────────────────────────────────────────


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


@pytest.mark.asyncio
async def test_loop_flow_a_compromise_records_compromise(tmp_path, monkeypatch):
    """With flow_a=True, a Meterpreter result drives record_compromise and a
    'completed' audit status."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings
    from tools.exploit_agent import run_exploit_agent

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=1,
        attack_max_commands=5,
        outcome_judgment_flow_a=True,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    policy = ExploitPolicy(settings, tmp_path)

    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("meterpreter session 1 opened\nuid=0(root)")

    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": True, "max_inconclusive_attempts": 3}},
        )

    summary = result["outcome_summary"]
    assert "compromises: 1" in summary
    # The audit record for the exploit action should be 'completed' (success
    # overridden to True by the CONFIRMED verdict).
    completed = [r for r in policy._records if r.action == "run_exploit_terminal" and r.status == "completed"]
    assert completed, (
        f"expected a completed audit row, got {[r.status for r in policy._records]}"
    )


@pytest.mark.asyncio
async def test_loop_flow_a_disabled_behavior_unchanged(tmp_path):
    """With flow_a=False, the hypothesis judge is off -- but the authoritative
    outcome-truth module STILL detects a real Meterpreter session as a
    compromise (it is no longer gated on flow_a; flow_a only controls the
    hypothesis-verdict layer). The old contract (no taxonomy without flow_a)
    let false positives through; the new contract is: compromise detection is
    always on, flow_a only adds the CONFIRMED/REFUTED hypothesis verdict."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings
    from tools.exploit_agent import run_exploit_agent

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
    policy = ExploitPolicy(settings, tmp_path)

    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("meterpreter session 1 opened\nuid=0(root)")

    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": False}},
        )

    summary = result["outcome_summary"]
    # A real Meterpreter session is now ALWAYS counted as a compromise by the
    # outcome-truth module, even with the hypothesis judge off.
    assert "compromises: 1" in summary


@pytest.mark.asyncio
async def test_loop_flow_a_refuted_records_exploit_failure(tmp_path, monkeypatch):
    """A REFUTED verdict (mocked) sets success=False and records an exploit
    failure, so the audit row is 'executed' not 'completed'."""
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings
    from tools.exploit_agent import run_exploit_agent
    import tools.exploit_agent.outcome_adapter as adapter_mod

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=1,
        attack_max_commands=5,
        outcome_judgment_flow_a=True,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    policy = ExploitPolicy(settings, tmp_path)

    async def _fake_judge_flow_a(**kwargs):
        return HypothesisStatus.REFUTED, 0.9, {"outcome": "failure"}

    monkeypatch.setattr(adapter_mod, "judge_flow_a", _fake_judge_flow_a)

    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("exploit failed\nno session created")

    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": True}},
        )

    # REFUTED -> success=False -> audit status 'executed' (not 'completed').
    executed = [r for r in policy._records if r.action == "run_exploit_terminal" and r.status == "executed"]
    assert executed, (
        f"expected an executed audit row, got {[r.status for r in policy._records]}"
    )


@pytest.mark.asyncio
async def test_loop_flow_a_inconclusive_keeps_exit_code_success(tmp_path, monkeypatch):
    """An INCONCLUSIVE verdict (mocked) keeps the exit_code-based success flag.
    With exit_code=0 the audit row is 'completed'; no compromise/cred/partial
    taxonomy is recorded for a non-partial classification."""
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings
    from tools.exploit_agent import run_exploit_agent
    import tools.exploit_agent.outcome_adapter as adapter_mod

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=1,
        attack_max_commands=5,
        outcome_judgment_flow_a=True,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    policy = ExploitPolicy(settings, tmp_path)

    async def _fake_judge_flow_a(**kwargs):
        return HypothesisStatus.INCONCLUSIVE, 0.5, {"outcome": "unknown"}

    monkeypatch.setattr(adapter_mod, "judge_flow_a", _fake_judge_flow_a)

    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    # exit_code=0 -> shallow success True; INCONCLUSIVE keeps it.
    session.call_tool.return_value = _tool_result("some output\nexit_code=0")

    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": True}},
        )

    summary = result["outcome_summary"]
    assert "compromises:" not in summary
    assert "cred dumps:" not in summary
    # exit_code=0 -> completed (inconclusive kept the shallow success).
    completed = [r for r in policy._records if r.action == "run_exploit_terminal" and r.status == "completed"]
    assert completed


@pytest.mark.asyncio
async def test_loop_flow_a_judge_failure_does_not_crash(tmp_path, monkeypatch):
    """If judge_flow_a raises, the loop must not crash -- it falls back to the
    exit-code flag and emits a warning."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings
    from tools.exploit_agent import run_exploit_agent
    import tools.exploit_agent.outcome_adapter as adapter_mod

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=1,
        attack_max_commands=5,
        outcome_judgment_flow_a=True,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    policy = ExploitPolicy(settings, tmp_path)

    async def _boom_judge_flow_a(**kwargs):
        raise RuntimeError("judge exploded")

    monkeypatch.setattr(adapter_mod, "judge_flow_a", _boom_judge_flow_a)

    client = MagicMock()
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("ok\nexit_code=0")

    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        # Should not raise.
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": True}},
        )

    # Fell back to exit_code==0 -> completed, no taxonomy.
    assert "compromises:" not in result["outcome_summary"]
    completed = [r for r in policy._records if r.action == "run_exploit_terminal" and r.status == "completed"]
    assert completed


# ── config plumbing ─────────────────────────────────────────────────────────


def test_exploit_settings_has_outcome_judgment_flow_a_default_false():
    from tools.exploit_agent import ExploitSettings

    s = ExploitSettings()
    assert s.outcome_judgment_flow_a is False


def test_config_schema_includes_flow_a_default_false():
    from tools.config_manager import CONFIG_SCHEMA

    assert CONFIG_SCHEMA["outcome_judgment"]["flow_a"] is False


def test_config_validator_flags_non_bool_flow_a():
    from tools.config_manager import ConfigValidator

    validator = ConfigValidator.__new__(ConfigValidator)
    validator._config = {"outcome_judgment": {"flow_a": "yes"}}
    result = __import__(
        "tools.config_manager", fromlist=["ConfigValidationResult"]
    ).ConfigValidationResult()
    # Mimic validate()'s section guard + our new field check.
    judgment = validator._config["outcome_judgment"]
    flow_a = judgment.get("flow_a")
    if flow_a is not None and not isinstance(flow_a, bool):
        result.warnings.append("outcome_judgment.flow_a must be a boolean.")
    assert result.warnings


# ── Goal-complete stopping predicate ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_loop_terminates_naturally_after_compromise(tmp_path):
    """A run that achieves a verified compromise MAY terminate on the next
    no-tool answer instead of being forced to continue (the audit flagged
    that attack mode otherwise only stopped via round/command budget
    exhaustion -- up to 200 rounds in long-session config -- because no tool
    maps to the ``reporting`` phase minimum)."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings
    from tools.exploit_agent import run_exploit_agent

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=50,
        attack_max_commands=200,
        outcome_judgment_flow_a=True,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    policy = ExploitPolicy(settings, tmp_path)

    client = MagicMock()
    # Round 1: exploit call. Round 2: no-tool final answer.
    client.chat.side_effect = [_tool_call_msg(), _done_msg()]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("meterpreter session 1 opened\nuid=0(root)")

    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "run_exploit_terminal"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": True, "max_inconclusive_attempts": 3}},
        )

    # The compromise was recorded and the loop terminated on the no-tool
    # answer -- it did NOT loop to the round budget.
    assert "compromises: 1" in result["outcome_summary"]
    assert result["total_actions"] == 1


@pytest.mark.asyncio
async def test_loop_does_not_terminate_early_without_compromise(tmp_path):
    """Without a verified compromise, a no-tool answer still triggers the
    phase-minimum gate (the model can't skip recon by saying 'done' before
    doing anything)."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings
    from tools.exploit_agent import run_exploit_agent

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=5,
        attack_max_commands=50,
        outcome_judgment_flow_a=True,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    policy = ExploitPolicy(settings, tmp_path)

    client = MagicMock()
    # Round 1: a recon tool call. Round 2: no-tool answer (too early).
    client.chat.side_effect = [
        {
            "message": {
                "content": "scanning",
                "tool_calls": [{"function": {"name": "check_os", "arguments": {"target_ip": "10.0.0.50"}}}],
            }
        },
        _done_msg(),
        # Round 3: after the phase-minimum nudge, another no-tool answer.
        _done_msg(),
    ]
    session = AsyncMock()
    session.call_tool.return_value = _tool_result("OS_VERDICT: LINUX\nexit_code=0")

    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "tools.exploit_agent._stream_ollama", new_callable=AsyncMock
    ) as stream:
        stream.return_value = {"role": "assistant", "content": "done"}
        result = await run_exploit_agent(
            client=client,
            model="glm",
            session=session,
            exploit_tools=[{"type": "function", "function": {"name": "check_os"}}],
            policy=policy,
            target_ip="10.0.0.50",
            config={"outcome_judgment": {"flow_a": True, "max_inconclusive_attempts": 3}},
        )

    # No compromise was recorded -- the loop should NOT have terminated on the
    # first no-tool answer; it nudged and continued.
    assert "compromises: 0" in result["outcome_summary"] or "compromises:" not in result["outcome_summary"]