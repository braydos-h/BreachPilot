"""TODO 006: every layer maps success/failure to the canonical outcome identically."""

from __future__ import annotations

from tools.exploit_agent.outcome_truth import ActionResult, ExploitOutcome, OperationalStatus
from tools.kernel.action_result import (
    EvidentialStatus,
    action_from_campaign_result,
    action_from_exploit_result,
    action_from_flowb_finding,
    action_from_swarm_result,
)
from tools.swarm.base import AgentResult, AgentStatus


def test_exploit_compromise_maps_to_holding_not_verified():
    r = ActionResult(tool_name="run_exploit_terminal", exploit_outcome=ExploitOutcome.COMPROMISE)
    c = action_from_exploit_result(r, run_id="r1")
    assert c.operational_status == OperationalStatus.COMPLETED
    assert c.exploit_outcome == ExploitOutcome.COMPROMISE
    # Only an oracle promotes to VERIFIED.
    assert c.evidential_status == EvidentialStatus.HOLDING
    assert c.verified_success is False


def test_exploit_failure_maps_to_inconclusive():
    r = ActionResult(
        tool_name="run_exploit_terminal",
        operational_status=OperationalStatus.FAILED,
        exploit_outcome=ExploitOutcome.FAILURE,
    )
    c = action_from_exploit_result(r)
    assert c.operational_success is False
    assert c.evidential_status == EvidentialStatus.INCONCLUSIVE


def test_swarm_success_without_probe_never_verified():
    ar = AgentResult(
        agent_type="exploit",
        status=AgentStatus.COMPLETE,
        task_id="t1",
        output={"access_achieved": True},
        evidence_refs=["audit:1"],
        findings=[{"id": "f1"}],
    )
    c = action_from_swarm_result(ar, run_id="r1")
    assert c.exploit_outcome == ExploitOutcome.COMPROMISE
    assert c.evidential_status == EvidentialStatus.HOLDING
    assert c.finding_ids == ["f1"]


def test_campaign_status_mapping():
    ok = action_from_campaign_result({"task_id": "c1", "phase": "exploit", "result": {"status": "exploited"}})
    assert ok.exploit_outcome == ExploitOutcome.COMPROMISE
    assert ok.evidential_status == EvidentialStatus.HOLDING
    blocked = action_from_campaign_result({"task_id": "c2", "phase": "exploit", "result": {"status": "blocked"}})
    assert blocked.operational_status == OperationalStatus.BLOCKED
    denied = action_from_campaign_result(
        {"task_id": "c3", "phase": "exploit", "result": {"status": "failed", "scope_denied": True}}
    )
    assert denied.scope_verdict == "deny"


def test_flowb_terminal_states_preserved():
    for status, expected in [
        ("CONFIRMED", EvidentialStatus.VERIFIED),
        ("REFUTED", EvidentialStatus.REFUTED),
        ("INCONCLUSIVE", EvidentialStatus.INCONCLUSIVE),
        ("OPEN", EvidentialStatus.PROPOSED),
    ]:
        c = action_from_flowb_finding({"id": "f1", "status": status, "hypothesis_id": "h1"})
        assert c.evidential_status == expected, status
        assert c.hypothesis_id == "h1"


def test_operational_vs_evidential_separation():
    # Tool exited 0 != exploit worked != finding evidenced.
    r = ActionResult(tool_name="nmap_scan", operational_status=OperationalStatus.COMPLETED)
    c = action_from_exploit_result(r)
    assert c.operational_success is True
    assert c.verified_success is False
    assert c.exploit_outcome == ExploitOutcome.NONE
