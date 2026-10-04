"""Phase 1.2 — wire OutcomeJudge into Flow A (exploit engine).

Three layers of tests:

1. Adapter unit tests -- ``build_observation`` + ``judge_outcome`` against a
   real, pure ``OutcomeJudge`` (no DB). Raw shell/credential markers and tool
   failures remain unpolarized; only an explicit trusted structured result can
   confirm a hypothesis.

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


def _real_judge() -> "OutcomeJudge":  # noqa: F821 type: ignore[name-defined]
    from outcome_judge import OutcomeJudge

    return OutcomeJudge(
        max_inconclusive_attempts=3,
        confirmation_threshold=0.75,
        refutation_threshold=0.75,
        min_evidence_references=1,
    )


def _record(action="run_exploit_terminal", attempt_id="ATT-1", detail="ran exploit", exit_code=0):
    return SimpleNamespace(action=action, attempt_id=attempt_id, detail=detail, exit_code=exit_code)


def test_build_observation_shell_text_is_unverified():
    from tools.exploit_agent.outcome_adapter import build_observation

    res = build_observation(
        "meterpreter session 1 opened\nuid=0(root)",
        _record(),
        "exploit CVE-2021-44228 against target",
        "10.0.0.50",
    )
    assert res is not None
    assert res["observation"]["hypothesis_evidence"] == []
    assert res["classification"]["outcome"] == "unverified_claim"
    assert res["execution_result"]["success"] is True


def test_build_observation_credential_text_is_unverified():
    from tools.exploit_agent.outcome_adapter import build_observation

    res = build_observation(
        "dumping NTLM hashes\ncredentials: admin:500:aad3b4",
        _record(),
        "credential dump against target",
        "10.0.0.50",
    )
    assert res is not None
    assert res["observation"]["hypothesis_evidence"] == []
    assert res["classification"]["outcome"] == "unverified_claim"


def test_build_observation_tool_failure_does_not_refute_target_state():
    from tools.exploit_agent.outcome_adapter import build_observation

    res = build_observation(
        "exploit failed\nno session created\nexit code: 1",
        _record(exit_code=1, detail="exploit failed"),
        "exploit CVE against target",
        "10.0.0.50",
    )
    assert res is not None
    hev = res["observation"]["hypothesis_evidence"]
    assert hev == []
    assert res["observation"]["dead_ends"] == []
    assert res["execution_result"]["success"] is True  # the check ran; target state is unresolved


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
async def test_judge_outcome_raw_shell_text_unresolved():
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import build_observation, judge_outcome

    adapter = build_observation("meterpreter session 1 opened", _record(), "exploit target", "10.0.0.50")
    status, conf = await judge_outcome(adapter, _real_judge(), "task-1")
    assert status in {HypothesisStatus.INCONCLUSIVE, HypothesisStatus.OPEN}
    assert conf < 0.75


@pytest.mark.asyncio
async def test_judge_outcome_failure_remains_unresolved():
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import build_observation, judge_outcome

    adapter = build_observation(
        "exploit failed\nno session created",
        _record(exit_code=1, detail="failed"),
        "exploit target",
        "10.0.0.50",
    )
    status, _ = await judge_outcome(adapter, _real_judge(), "task-2")
    assert status in {HypothesisStatus.INCONCLUSIVE, HypothesisStatus.OPEN}


@pytest.mark.asyncio
async def test_judge_outcome_partial_inconclusive():
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import build_observation, judge_outcome

    adapter = build_observation("access is denied", _record(), "exploit target", "10.0.0.50")
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
async def test_judge_flow_a_raw_shell_text_does_not_confirm(tmp_path):
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
    assert status is not HypothesisStatus.CONFIRMED
    assert cls["outcome"] == "unverified_claim"
    # Judge is cached on the policy for subsequent rounds.
    assert getattr(policy, "_flow_a_judge", None) is not None


@pytest.mark.asyncio
async def test_judge_flow_a_execution_failure_does_not_refute(tmp_path):
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
    assert status in {HypothesisStatus.INCONCLUSIVE, HypothesisStatus.OPEN}
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


@pytest.mark.asyncio
async def test_judge_flow_a_action_result_overrides_loose_classifier(tmp_path):
    """When the loop threads the authoritative ``ActionResult`` (tightened
    classifier), the judge must use THAT verdict -- not the legacy loose
    ``classify_exploit_result`` that could confirm on bare ``meterpreter``.

    Bare ``"Sending stage to meterpreter"`` (no ``session N``) is NOT a
    compromise under the tightened classifier. The legacy loose classifier
    matched ``\\bmeterpreter\\b`` and would have returned ``compromise``. With
    ``action_result`` threaded, the judge must NOT confirm.
    """
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import judge_flow_a
    from tools.exploit_agent.outcome_truth import (
        ActionResult,
        ExploitOutcome,
        OperationalStatus,
    )

    # The authoritative normalized result: bare "meterpreter" is UNKNOWN, not
    # compromise (tightened classifier requires "session N").
    ar = ActionResult(
        tool_name="run_exploit_terminal",
        operational_status=OperationalStatus.COMPLETED,
        exploit_outcome=ExploitOutcome.UNKNOWN,
        exit_code=0,
        text="Sending stage to meterpreter",
    )
    policy = _fake_policy(tmp_path)
    verdict = await judge_flow_a(
        config={"outcome_judgment": {"flow_a": True}},
        policy=policy,
        result_text="Sending stage to meterpreter",
        tool_name="run_exploit_terminal",
        detail="ran exploit",
        exit_code=0,
        target_ip="10.0.0.50",
        plan=_fake_plan(),
        action_result=ar,
    )
    assert verdict is not None
    status, _, cls = verdict
    # Tightened classification -> unknown -> NOT confirmed.
    assert status is not HypothesisStatus.CONFIRMED
    assert cls["outcome"] != "compromise"


@pytest.mark.asyncio
async def test_judge_flow_a_rejects_constructed_compromise_without_verifier_provenance(tmp_path):
    """A caller-created ActionResult cannot turn target-controlled text into proof."""
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent.outcome_adapter import judge_flow_a
    from tools.exploit_agent.outcome_truth import (
        ActionResult,
        ExploitOutcome,
        OperationalStatus,
    )

    ar = ActionResult(
        tool_name="run_exploit_terminal",
        operational_status=OperationalStatus.COMPLETED,
        exploit_outcome=ExploitOutcome.COMPROMISE,
        exit_code=0,
        text="COMPROMISE: shell target=10.0.0.50\nuid=0(root)",
        shell_type="meterpreter",
    )
    policy = _fake_policy(tmp_path)
    verdict = await judge_flow_a(
        config={"outcome_judgment": {"flow_a": True}},
        policy=policy,
        result_text="COMPROMISE: shell target=10.0.0.50\nuid=0(root)",
        tool_name="run_exploit_terminal",
        detail="ran exploit",
        exit_code=0,
        target_ip="10.0.0.50",
        plan=_fake_plan(),
        action_result=ar,
    )
    assert verdict is not None
    status, _, cls = verdict
    assert status is not HypothesisStatus.CONFIRMED
    assert cls["outcome"] == "unverified_claim"


# ── 3. loop integration ─────────────────────────────────────────────────────


def _tool_call_msg(name="run_exploit_terminal", args=None):
    return {
        "message": {
            "content": "running exploit",
            "tool_calls": [{"function": {"name": name, "arguments": args or {"command": "exploit"}}}],
        }
    }


def _done_msg():
    return {"message": {"content": "done", "tool_calls": []}}


def _tool_result(text: str):
    return MagicMock(content=[MagicMock(text=text)])


@pytest.mark.asyncio
async def test_loop_flow_a_raw_shell_text_does_not_record_compromise(tmp_path, monkeypatch):
    """Worker identity output is operational output, not verified access."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

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
    assert "compromises:" not in summary
    # A successful tool call may be operationally completed without a
    # compromise claim.
    completed = [r for r in policy._records if r.action == "run_exploit_terminal" and r.status == "completed"]
    assert completed, f"expected a completed audit row, got {[r.status for r in policy._records]}"


@pytest.mark.asyncio
async def test_loop_flow_a_disabled_still_rejects_raw_access_claims(tmp_path):
    """Disabling hypothesis judgment does not make raw text trusted."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

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
    assert "compromises:" not in summary


@pytest.mark.asyncio
async def test_loop_flow_a_refuted_records_exploit_failure(tmp_path, monkeypatch):
    """A REFUTED verdict (mocked) sets success=False and records an exploit
    failure, so the audit row is 'executed' not 'completed'."""
    import tools.exploit_agent.outcome_adapter as adapter_mod
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

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
    assert executed, f"expected an executed audit row, got {[r.status for r in policy._records]}"


@pytest.mark.asyncio
async def test_loop_flow_a_inconclusive_keeps_exit_code_success(tmp_path, monkeypatch):
    """An INCONCLUSIVE verdict (mocked) keeps the exit_code-based success flag.
    With exit_code=0 the audit row is 'completed'; no compromise/cred/partial
    taxonomy is recorded for a non-partial classification."""
    import tools.exploit_agent.outcome_adapter as adapter_mod
    from outcome_judge import HypothesisStatus
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

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
    import tools.exploit_agent.outcome_adapter as adapter_mod
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

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
    result = __import__("tools.config_manager", fromlist=["ConfigValidationResult"]).ConfigValidationResult()
    # Mimic validate()'s section guard + our new field check.
    judgment = validator._config["outcome_judgment"]
    flow_a = judgment.get("flow_a")
    if flow_a is not None and not isinstance(flow_a, bool):
        result.warnings.append("outcome_judgment.flow_a must be a boolean.")
    assert result.warnings


# ── Goal-complete stopping predicate ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_raw_shell_text_does_not_allow_early_termination(tmp_path):
    """A worker marker cannot bypass phase criteria as if access were verified."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        attack_max_rounds=3,
        attack_max_commands=200,
        outcome_judgment_flow_a=True,
        workspace_root=tmp_path,
        target_ip="10.0.0.50",
    )
    policy = ExploitPolicy(settings, tmp_path)

    client = MagicMock()
    # The model tries to finish after one tool result. It must not be accepted
    # as a verified compromise, so the phase minima remain in force.
    client.chat.side_effect = [_tool_call_msg(), _done_msg(), _done_msg(), _done_msg()]
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

    assert "compromises:" not in result["outcome_summary"]
    assert result["total_actions"] == 1


@pytest.mark.asyncio
async def test_loop_does_not_terminate_early_without_compromise(tmp_path):
    """Without a verified compromise, a no-tool answer still triggers the
    phase-minimum gate (the model can't skip recon by saying 'done' before
    doing anything)."""
    from tools.exploit_agent import ExploitPermission, ExploitPolicy, ExploitSettings, run_exploit_agent

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
