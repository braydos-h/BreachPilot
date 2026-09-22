"""Runner services characterization (todo 05, Step 2 pre-extraction safety net).

Pins the six extracted services' behavior (planning-loop / dispatch /
telemetry / termination / evidence-promotion / retry-recovery) with pure
unit tests — no subprocess, no network, no live model. The loop delegates
to these helpers, so this file proves the split points are behavior-stable:

- seam identity: ``runner._impl.X is service.X`` for every re-export;
- pure predicates/state machines: budgets, round-tools narrowing, invalid
  triage, termination gates, evidence shaping, loopback/counterfactual.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest


def _schema(name: str) -> dict[str, object]:
    return {"type": "function", "function": {"name": name, "parameters": {}}}


# ---------------------------------------------------------------------------
# Seam identity: historical ``runner._impl`` paths resolve to the SAME objects
# ---------------------------------------------------------------------------


def test_impl_reexports_are_single_source():
    import tools.exploit_agent.runner._impl as impl
    from tools.exploit_agent.runner import (
        dispatch,
        evidence_promotion,
        planning_loop,
        retry_recovery,
        telemetry,
        termination,
    )

    assert impl.build_round_tools is planning_loop.build_round_tools
    assert impl.is_exploit_action is dispatch.is_exploit_action
    assert impl.unknown_tool_text is dispatch.unknown_tool_text
    assert impl.extract_cves is evidence_promotion.extract_cves
    assert impl.record_phase_for_tool is evidence_promotion.record_phase_for_tool
    assert impl.LoopbackBreaker is retry_recovery.LoopbackBreaker
    assert impl.close_counterfactual_row is retry_recovery.close_counterfactual_row
    assert impl.new_counterfactual_row is retry_recovery.new_counterfactual_row
    assert impl.log_decision_hook is telemetry.log_decision_hook
    assert impl.EmptyRoundsTracker is termination.EmptyRoundsTracker
    assert impl.build_final_result is termination.build_final_result
    assert impl.goal_complete is termination.goal_complete


def test_loop_entry_still_delegates_to_impl():
    import tools.exploit_agent.runner._impl as impl
    from tools.exploit_agent.runner import loop

    assert loop.run_exploit_agent is impl.run_exploit_agent


# ---------------------------------------------------------------------------
# planning-loop service
# ---------------------------------------------------------------------------


def test_loop_budget_predicates():
    from tools.exploit_agent.runner.planning_loop import LoopBudget, budget_exceeded

    now = [100.0]
    assert budget_exceeded(lambda: now[0], 100.0, 0) is False
    budget = LoopBudget(start_time=100.0, max_duration_s=60.0, clock=lambda: now[0])
    assert budget.exceeded() is False
    now[0] = 200.0
    assert budget.exceeded() is True
    assert LoopBudget(start_time=0.0, max_duration_s=0.0, clock=lambda: 1e9).exceeded() is False


def test_build_round_tools_never_invents_and_surfaces_focus():
    from tools.exploit_agent.runner.planning_loop import build_round_tools

    tools = [_schema("check_os"), _schema("search_cve_intel")]

    class _Focus:
        enabled = True

        def needed_tool_names(self) -> list[str]:
            return ["search_cve_intel"]

    narrowed = build_round_tools(
        tools,
        "recon",
        available_mcp_names=["check_os", "search_cve_intel"],
        multi_model_enabled=False,
        focus=_Focus(),
    )
    names = {t.get("function", {}).get("name") if isinstance(t.get("function"), dict) else "" for t in narrowed}
    assert names == {"check_os", "search_cve_intel"}
    assert names <= {"check_os", "search_cve_intel"}


def test_build_round_tools_hides_peer_tool_when_disabled():
    from tools.exploit_agent.runner.planning_loop import build_round_tools

    tools = [_schema("check_os"), _schema("consult_peer_models")]
    narrowed = build_round_tools(tools, "recon", available_mcp_names=None, multi_model_enabled=False)
    names = [t.get("function", {}).get("name") if isinstance(t.get("function"), dict) else "" for t in narrowed]
    assert "check_os" in names
    assert "consult_peer_models" not in names


def test_build_round_tools_unknown_phase_falls_back_to_full_list():
    from tools.exploit_agent.runner.planning_loop import build_round_tools

    tools = [_schema("check_os"), _schema("made_up_tool")]
    assert build_round_tools(tools, "bogus-phase-xyz", available_mcp_names=None, multi_model_enabled=True) == tools


def test_triage_invalid_calls_recoverable_replans():
    from tools.exploit_agent.runner.planning_loop import triage_invalid_calls
    from tools.exploit_agent.tool_calls import _ToolOutcomeTracker

    tracker = _ToolOutcomeTracker()
    triage = triage_invalid_calls([{"reason": "typo", "recoverable": True}], tracker, ["check_os"])
    assert triage.stop_agent is False
    assert not tracker.terminal_constraint_reached
    roles = [m["role"] for m in triage.messages_to_append]
    assert roles == ["tool", "user"]
    assert triage.messages_to_append[0]["content"].startswith("RECOVERABLE_ERROR:")
    assert "malformed" in str(triage.messages_to_append[1]["content"])
    assert len(triage.ui_errors) == 1


def test_triage_invalid_calls_terminal_stops():
    from tools.exploit_agent.runner.planning_loop import triage_invalid_calls
    from tools.exploit_agent.tool_calls import _ToolOutcomeTracker

    tracker = _ToolOutcomeTracker()
    for _ in range(10):
        tracker.record_blocked("x", {}, "blocked")
    assert tracker.terminal_constraint_reached
    triage = triage_invalid_calls([{"reason": "bad"}], tracker, ["check_os"])
    assert triage.stop_agent is True
    assert triage.messages_to_append[-1]["role"] == "user"


def test_model_error_response_shape():
    from tools.exploit_agent.runner.planning_loop import model_error_response

    resp = model_error_response(RuntimeError("down"))
    assert resp["role"] == "assistant"
    assert resp["tool_calls"] == []
    assert str(resp["content"]).startswith("ERROR:")


def test_reflection_interval_for():
    from tools.exploit_agent.runner.planning_loop import reflection_interval_for

    assert reflection_interval_for({}) == 0
    assert reflection_interval_for({"reflection_every_n_actions": 5}) == 5
    assert reflection_interval_for({"ultrathink": True}) == 3
    assert (
        reflection_interval_for(
            {"reflection_every_n_actions": 10, "ultrathink": True, "ultrathink_reflection_interval": 3}
        )
        == 3
    )


def test_maybe_compact_context_noop_when_disabled():
    from tools.exploit_agent.runner.planning_loop import maybe_compact_context

    messages: list[dict[str, object]] = [{"role": "user", "content": "hi"}]
    ledger = SimpleNamespace(sync=lambda msgs: 10)
    policy = SimpleNamespace(is_attack_mode=False)
    out = maybe_compact_context(
        messages=messages,
        ledger=ledger,
        policy=policy,
        round_num=1,
        round_tools=[],
        profile={"keep_full": 8, "output_max_chars": 4000},
        system_prompt="sys",
        plan=None,
        target_ip="10.0.0.1",
        target_cve="",
        target_os=None,
        known_cves=None,
        service_context="",
        attacker_os="Linux",
        session_mgr=None,
    )
    assert out is messages


# ---------------------------------------------------------------------------
# dispatch service
# ---------------------------------------------------------------------------


def test_is_exploit_action_and_banner_sources():
    from tools.exploit_agent.runner.dispatch import is_banner_source, is_exploit_action

    assert is_exploit_action("run_exploit_terminal") is True
    assert is_exploit_action("run_msf_module") is True
    assert is_exploit_action("check_os") is False
    assert is_banner_source("quick_scan") is True
    assert is_banner_source("ping") is False


def test_unknown_tool_text_names_tool():
    from tools.exploit_agent.runner.dispatch import unknown_tool_text

    text = unknown_tool_text("no_such_tool", ["check_os"])
    assert "no_such_tool" in text
    assert text.startswith("UNKNOWN_TOOL:")


def test_extract_result_text_prefers_text_blocks():
    from tools.exploit_agent.runner.dispatch import extract_result_text

    assert extract_result_text({"content": [{"text": "hello"}]}) == "hello"
    fallback = extract_result_text({"weird": 1})
    assert "weird" in fallback


def test_try_retry_correction_none_for_unrecognized():
    from tools.exploit_agent.runner.dispatch import try_retry_correction

    assert try_retry_correction("nope", {"a": 1}, "totally unrelated boom") is None


def test_focus_gate_messages_shape():
    from tools.exploit_agent.runner.dispatch import focus_gate_messages

    msgs = focus_gate_messages("check_os", "drift", "stay on target")
    assert msgs[0]["role"] == "tool"
    assert "FOCUS_GATE_DRIFT" in str(msgs[0]["content"])
    assert msgs[1] == {"role": "user", "content": "stay on target"}


def test_snapshot_label():
    from tools.exploit_agent.runner.dispatch import snapshot_label

    assert snapshot_label("run_exploit_terminal", 3) == "pre-run_exploit_terminal-3"


# ---------------------------------------------------------------------------
# telemetry service
# ---------------------------------------------------------------------------


def test_telemetry_payload_keys():
    from tools.exploit_agent.runner.telemetry import (
        assistant_payload,
        phase_change_payload,
        snapshot_taken_payload,
        tool_request_payload,
        tool_result_payload,
        tool_start_payload,
    )

    assert assistant_payload("hi", 1, "recon")["round"] == 1
    assert tool_request_payload("n", {"a": 1}, 2, 1, "recon")["action"] == 2
    assert tool_start_payload("n", 2, "10.0.0.1", "recon")["target"] == "10.0.0.1"
    result = tool_result_payload("n", 2, True, 0, "ok", "recon")
    assert result["success"] is True and result["exit_code"] == 0
    assert phase_change_payload("validation", "recon", 2, 5)["previous"] == "recon"
    snap = snapshot_taken_payload("n", 1, "10.0.0.1", "snap-1", "prov", "lbl")
    assert snap["snapshot_id"] == "snap-1"


def test_update_heartbeat_never_raises():
    from tools.exploit_agent.runner.telemetry import update_heartbeat

    update_heartbeat(None, round=1)

    class _Boom:
        def update(self, **kwargs: Any) -> None:
            raise RuntimeError("sink down")

    update_heartbeat(_Boom(), round=1)


def test_evidence_refs_and_failure_class():
    from tools.exploit_agent.runner.telemetry import evidence_refs_from_text, failure_class_for

    assert failure_class_for("ok", True) == ""
    assert isinstance(failure_class_for("denied", False), str)
    refs = evidence_refs_from_text("see exploit_workspace/10.0.0.1/proof.txt for details")
    assert refs and refs[0].endswith("proof.txt")


@pytest.mark.asyncio
async def test_log_decision_hook_no_sink_never_raises(tmp_path):
    from tools.exploit_agent.runner.telemetry import log_decision_hook

    await log_decision_hook(
        tmp_path,
        None,
        tmp_path,
        round_num=1,
        tool_name="check_os",
        target_ip="10.0.0.1",
        result_text="ok",
        outcome="completed",
        failure_class="",
        success=True,
        evidence_refs=[],
        action_count=1,
        phase="recon",
    )


# ---------------------------------------------------------------------------
# termination service
# ---------------------------------------------------------------------------


def test_goal_complete_and_phase_minima():
    from tools.exploit_agent.policy import ExploitPermission
    from tools.exploit_agent.runner.termination import enforce_phase_minima, goal_complete

    assert goal_complete(1, 0) is True
    assert goal_complete(0, 1) is True
    assert goal_complete(0, 0) is False
    assert enforce_phase_minima(ExploitPermission.FULL_ACCESS, False) is True
    assert enforce_phase_minima(ExploitPermission.READ_ONLY, False) is False
    assert enforce_phase_minima(ExploitPermission.FULL_ACCESS, True) is False


def test_empty_rounds_tracker_circuit_timing():
    from tools.exploit_agent.runner.termination import EmptyRoundsTracker

    tracker = EmptyRoundsTracker()
    assert tracker.note_round(has_tool_calls=False, content="thinking") is False
    assert tracker.consecutive == 0
    for _ in range(3):
        tracker.note_round(has_tool_calls=False, content="ERROR: down")
    assert tracker.consecutive == 3
    assert tracker.should_emit_circuit_open() is False
    tracker.note_round(has_tool_calls=False, content="ERROR: down")
    assert tracker.consecutive == 4
    assert tracker.should_emit_circuit_open() is True
    tracker.note_round(has_tool_calls=True, content="")
    assert tracker.consecutive == 0


def test_no_path_checkpoint_matrix():
    from tools.exploit_agent.policy import ExploitPermission
    from tools.exploit_agent.runner.termination import should_offer_no_path_checkpoint

    good = dict(
        checkpoint_hook=object(),
        is_goal_complete=False,
        terminal_constraint_reached=False,
        permission=ExploitPermission.FULL_ACCESS,
        action_count=5,
        last_no_path_action=2,
    )
    assert should_offer_no_path_checkpoint(**good) is True
    assert should_offer_no_path_checkpoint(**{**good, "checkpoint_hook": None}) is False
    assert should_offer_no_path_checkpoint(**{**good, "is_goal_complete": True}) is False
    assert should_offer_no_path_checkpoint(**{**good, "action_count": 2}) is False
    assert should_offer_no_path_checkpoint(**{**good, "permission": ExploitPermission.READ_ONLY}) is False


def test_apply_checkpoint_outcome_mapping():
    from tools.exploit_agent.runner.termination import apply_checkpoint_outcome

    assert apply_checkpoint_outcome("continue") == "continue"
    assert apply_checkpoint_outcome("change_goal") == "continue"
    assert apply_checkpoint_outcome("privesc") == "continue"
    assert apply_checkpoint_outcome("finish") == "finish"
    assert apply_checkpoint_outcome("cancel") == "cancel"
    assert apply_checkpoint_outcome("another_goal") is None


def test_no_path_and_access_evidence_keys():
    from tools.exploit_agent.phase_tracker import _PhaseTracker
    from tools.exploit_agent.runner.termination import access_evidence, no_path_evidence
    from tools.exploit_agent.tool_calls import _ToolOutcomeTracker

    phase = _PhaseTracker()
    outcome = _ToolOutcomeTracker()
    evidence = no_path_evidence(phase, outcome, None)
    assert {"services_detected", "phase_counts", "blocked_summary"} <= set(evidence)
    access = access_evidence(outcome, "meterpreter", "root", True)
    assert access["outcome"] == "compromise"


def test_build_final_result_shape(tmp_path):
    from tools.exploit_agent.runner.termination import build_final_result
    from tools.exploit_agent.tool_calls import _ToolOutcomeTracker

    policy = SimpleNamespace(
        _audit_path=tmp_path / "audit.jsonl",
        workspace=tmp_path,
        settings=SimpleNamespace(target_context={}),
        is_attack_mode=False,
        read_audit_records=lambda: [],
    )
    result = build_final_result(
        target_ip="10.0.0.1",
        target_cve="",
        target_os=None,
        attacker_os="Linux",
        action_count=0,
        policy=policy,
        messages=[],
        research_assistant=None,
        outcome_tracker=_ToolOutcomeTracker(),
        focus=None,
        counterfactual_rows=[],
        cancelled_by_operator=False,
        attack_memory=None,
        verdict_mismatch="",
    )
    assert result["target_ip"] == "10.0.0.1"
    assert result["total_actions"] == 0
    assert "outcome_summary" in result
    assert result["cancelled_by_operator"] is False
    assert "verdict_mismatch" not in result
    assert result["research_assistant"]["enabled"] is False


@pytest.mark.asyncio
async def test_record_stuck_loop_noop_when_clean(tmp_path):
    from tools.exploit_agent.runner.termination import record_stuck_loop_if_needed
    from tools.exploit_agent.tool_calls import _ToolOutcomeTracker

    await record_stuck_loop_if_needed(None, tmp_path, _ToolOutcomeTracker(), "recon", 10, 0)


@pytest.mark.asyncio
async def test_invoke_checkpoint_hook_none_passthrough(tmp_path):
    from tools.exploit_agent.runner.termination import invoke_checkpoint_hook

    assert (
        await invoke_checkpoint_hook(
            None,
            object(),
            hook_name="x",
            event_sink=None,
            reports_dir=tmp_path,
            action_count=0,
            round_num=0,
            phase="recon",
        )
        is None
    )


@pytest.mark.asyncio
async def test_invoke_checkpoint_hook_calls_hook(tmp_path):
    from tools.exploit_agent.runner.checkpoint import CheckpointContext, CheckpointOutcome
    from tools.exploit_agent.runner.termination import invoke_checkpoint_hook

    async def _hook(ctx):
        assert ctx.kind == "no_path"
        return CheckpointOutcome(action="finish")

    ctx = CheckpointContext(kind="no_path", target_ip="10.0.0.1", action_count=3)
    out = await invoke_checkpoint_hook(
        _hook,
        ctx,
        hook_name="checkpoint_no_path",
        event_sink=None,
        reports_dir=tmp_path,
        action_count=3,
        round_num=1,
        phase="recon",
    )
    assert out is not None and out.action == "finish"


# ---------------------------------------------------------------------------
# evidence-promotion service
# ---------------------------------------------------------------------------


def test_extract_cves_and_banner_summary():
    from tools.exploit_agent.runner.evidence_promotion import banner_summary, extract_cves

    assert extract_cves("found CVE-2021-44228 and cve-2021-44228 twice") == ["CVE-2021-44228"]
    assert extract_cves("nothing here") == []
    banners = [{"service": "http", "version": "2.4", "host": "10.0.0.1", "port": "80"}]
    assert banner_summary(banners) == "http 2.4 on 10.0.0.1:80"


def test_record_phase_for_tool_routing():
    from tools.exploit_agent.runner.evidence_promotion import record_phase_for_tool

    seen: list[str] = []

    class _Tracker:
        def record_action(self, phase: str) -> None:
            seen.append(phase)

    record_phase_for_tool(_Tracker(), "check_os", ["check_os"])
    record_phase_for_tool(_Tracker(), "run_python_file", ["run_python_file"])
    record_phase_for_tool(_Tracker(), "mystery_tool", ["mystery_tool"])
    record_phase_for_tool(_Tracker(), "ghost", ["check_os"])
    assert seen == ["recon", "validation", "unmapped:mystery_tool", "unknown:ghost"]


def test_record_phase_for_tool_real_tracker_earns_no_ghost_credit():
    from tools.exploit_agent.phase_tracker import _PhaseTracker
    from tools.exploit_agent.runner.evidence_promotion import record_phase_for_tool

    tracker = _PhaseTracker()
    record_phase_for_tool(tracker, "check_os", ["check_os"])
    assert tracker._counts["recon"] == 1
    record_phase_for_tool(tracker, "ghost", ["check_os"])
    assert sum(tracker._counts.values()) == 1


def test_peer_and_reflection_messages_mark_advisory():
    from tools.exploit_agent.runner.evidence_promotion import peer_advisory_message, reflection_message

    peer = peer_advisory_message("try harder")
    assert "PEER ADVISORY" in peer and "try harder" in peer
    refl = reflection_message(3, {"what_worked": ["a"], "what_failed": [], "why": "w"})
    assert "ADVISORY REFLECTION" in refl and "Reflection after 3 actions" in refl


def test_failure_fingerprint_stable_hex():
    from tools.exploit_agent.runner.evidence_promotion import failure_fingerprint

    fp1 = failure_fingerprint("nmap_scan", {"target": "10.0.0.1"}, "output")
    fp2 = failure_fingerprint("nmap_scan", {"target": "10.0.0.1"}, "output")
    assert fp1 == fp2 and len(fp1) == 16 and all(c in "0123456789abcdef" for c in fp1)
    assert failure_fingerprint("other", {}, "output") != fp1


def test_resolve_verdict_evidence_ref():
    from tools.exploit_agent.runner.evidence_promotion import resolve_verdict_evidence_ref

    assert resolve_verdict_evidence_ref(None, None, "10.0.0.1", "nmap_scan") is None
    signal = {"status": "confirmed", "confidence": 0.9, "tool_name": "nmap_scan"}
    record = SimpleNamespace(attempt_id="abc123", action="nmap_scan")
    resolved = resolve_verdict_evidence_ref(signal, record, "10.0.0.1", "nmap_scan")
    assert resolved is not None
    assert resolved["evidence_refs"] == ["exploit_audit:10.0.0.1:abc123"]
    assert "tool_name" not in resolved


def test_research_evidence_from_banners():
    from tools.exploit_agent.runner.evidence_promotion import research_evidence_from_banners

    banners = [{"service": "http", "version": "2.4", "port": "80"}]
    assert research_evidence_from_banners(banners, False) == ([], [])
    topics, lines = research_evidence_from_banners(banners, True)
    assert topics == ["service:http:2.4:80"]
    assert lines == ["http 2.4 on port 80"]


def test_recent_context_and_advisory_helpers():
    from tools.exploit_agent.runner.evidence_promotion import (
        append_research_advisory,
        recent_research_context,
    )

    messages: list[dict[str, object]] = [{"role": "user", "content": "hello"}]
    ctx = recent_research_context(
        messages,
        target_ip="10.0.0.1",
        target_os=None,
        known_cves=None,
        target_cve="",
        service_context="",
    )
    assert "Target: 10.0.0.1" in ctx
    assert append_research_advisory(messages, None, {"a": 1}) == ""
    assert len(messages) == 1

    class _Assistant:
        def format_for_main(self, advisory):
            return "ADVISORY"

        def compact_ui_hint(self, advisory):
            return "hint"

    assert append_research_advisory(messages, _Assistant(), {"a": 1}) == "ADVISORY"
    assert messages[-1] == {"role": "user", "content": "ADVISORY"}


@pytest.mark.asyncio
async def test_automatic_research_disabled_short_circuits():
    from tools.exploit_agent.runner.evidence_promotion import automatic_research

    out = await automatic_research(
        research_assistant=None,
        heartbeat=None,
        action_count=0,
        policy=None,
        messages=[],
        target_ip="10.0.0.1",
        target_os=None,
        known_cves=None,
        target_cve="",
        service_context="",
        question="q",
        trigger="t",
        topics=["x"],
    )
    assert out == {}


@pytest.mark.asyncio
async def test_judge_flow_a_outcome_disabled_keeps_success():
    from tools.exploit_agent.runner.evidence_promotion import judge_flow_a_outcome
    from tools.exploit_agent.tool_calls import _ToolOutcomeTracker

    success, signal = await judge_flow_a_outcome(
        enabled=False,
        config=None,
        policy=None,
        result_text="ok",
        tool_name="check_os",
        detail="",
        exit_code=0,
        target_ip="10.0.0.1",
        plan=None,
        action_result=None,
        attempt_id="a1",
        success=True,
        outcome_tracker=_ToolOutcomeTracker(),
        event_sink=None,
        reports_dir=None,
        action_count=1,
        round_num=1,
        phase="recon",
    )
    assert (success, signal) == (True, None)


@pytest.mark.asyncio
async def test_persist_verdict_signal_noops():
    from tools.exploit_agent.runner.evidence_promotion import persist_verdict_signal

    await persist_verdict_signal(
        event_sink=None,
        reports_dir=None,
        experience_store=None,
        verdict_signal={"status": "confirmed"},
        target_ip="10.0.0.1",
        tool_name="check_os",
        action_count=1,
        round_num=1,
        phase="recon",
        last_record=None,
        exploit_outcome=None,
        is_exploit_action=True,
    )


# ---------------------------------------------------------------------------
# retry-recovery service
# ---------------------------------------------------------------------------


def test_loopback_breaker_trips_and_resets():
    from tools.exploit_agent.runner.retry_recovery import LoopbackBreaker

    breaker = LoopbackBreaker()
    assert breaker.should_stop() is False
    breaker.note_result("x map_host_loopback:false y", is_loopback_target=True, success=False)
    breaker.note_result("x map_host_loopback:false y", is_loopback_target=True, success=False)
    assert breaker.should_stop() is False
    breaker.note_result("x map_host_loopback:false y", is_loopback_target=True, success=False)
    assert breaker.should_stop() is True
    assert "sandbox.enabled:false" in breaker.stop_message("127.0.0.1")
    breaker.note_result("clean ok", is_loopback_target=True, success=True)
    assert breaker.should_stop() is False


def test_is_loopback_target_pure():
    from tools.exploit_agent.runner.retry_recovery import is_loopback_target

    assert is_loopback_target("127.0.0.1") is True
    assert is_loopback_target("8.8.8.8") is False


def test_counterfactual_open_close_bounds():
    from tools.exploit_agent.runner.retry_recovery import (
        close_counterfactual_row,
        new_counterfactual_row,
        should_open_counterfactual,
    )

    assert should_open_counterfactual(pending={}, snapshot_ref_taken=object(), counterfactual_enabled=True) is False
    assert should_open_counterfactual(pending=None, snapshot_ref_taken=None, counterfactual_enabled=True) is False
    assert should_open_counterfactual(pending=None, snapshot_ref_taken=object(), counterfactual_enabled=False) is False
    assert should_open_counterfactual(pending=None, snapshot_ref_taken=object(), counterfactual_enabled=True) is True
    row = new_counterfactual_row(action=1, tool="t", mutation_strategy="s", snapshot_id="snap", reverted=True)
    assert row["payload_b_outcome"] == "pending"
    close_counterfactual_row(row, tool="t2", action=2, success=True)
    assert row["payload_b_outcome"] == "verified"
    assert row["payload_b_action"] == 2
    close_counterfactual_row(None, tool="t", action=1, success=False)
