"""Finding-lifecycle enforcement tests (P1-02 / BP-05).

The canonical machine (``tools.kernel.finding_lifecycle``) must be enforced
— not merely defined — at every write surface: ``record_hitl_decision``
(actor ``human``), ``record_verify`` (actor ``oracle``), and
``record_retest`` (actor ``retest``) all route through ``check_transition``
and raise/block on ``ValueError``. Covers: illegal edges, wrong actors,
terminal immutability, VERIFIED-after-REJECTED, the REFUTED legacy alias,
swarm/campaign HOLDING caps, the read-surface gate, and the full
propose → approve → verify → retest happy path.
"""

from __future__ import annotations

from typing import Any

import pytest

from tools.kernel.finding_lifecycle import (
    APPROVED,
    FIXED,
    HOLDING,
    INCONCLUSIVE,
    PROPOSED,
    REJECTED,
    STILL_OPEN,
    VERIFIED,
    check_transition,
    current_state,
)
from tools.mcp_tools.hitl import propose_new_finding, record_hitl_decision
from tools.mcp_tools.retest import record_retest
from tools.mcp_tools.verify import record_verify

NOW = "2026-01-01T00:00:00+00:00"


def _proposed(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"technical_findings": []}
    finding = propose_new_finding(data, title="t", affected_asset="10.0.0.5", summary="s", now=NOW)
    finding.update(overrides)
    return finding


def _verify_history(verdict: str) -> list[dict[str, Any]]:
    return [{"timestamp": NOW, "verdict": verdict, "evidence": "ev"}]


# ── happy path ─────────────────────────────────────────────────────────────


def test_propose_approve_verify_retest_happy_path() -> None:
    finding = _proposed()
    assert current_state(finding) == PROPOSED

    record_hitl_decision(finding, APPROVED, "real", actor="human", now=NOW)
    assert current_state(finding) == APPROVED

    record_verify(finding, VERIFIED, "probe output: uid=0(root)", now=NOW)
    assert current_state(finding) == VERIFIED

    record_retest(finding, STILL_OPEN, "still lands", now=NOW)
    assert current_state(finding) == STILL_OPEN

    record_retest(finding, FIXED, "patched", now=NOW)
    assert current_state(finding) == FIXED


# ── illegal edges raise ────────────────────────────────────────────────────


def test_retest_cannot_touch_proposed() -> None:
    with pytest.raises(ValueError):
        record_retest(_proposed(), STILL_OPEN, "ev")
    with pytest.raises(ValueError):
        record_retest(_proposed(), FIXED, "ev")


def test_retest_cannot_touch_approved_without_verify() -> None:
    finding = _proposed()
    record_hitl_decision(finding, APPROVED, "real", actor="human", now=NOW)
    with pytest.raises(ValueError):
        record_retest(finding, STILL_OPEN, "ev")
    with pytest.raises(ValueError):
        record_retest(finding, FIXED, "ev")


def test_oracle_cannot_verify_rejected_or_fixed() -> None:
    rejected = _proposed()
    record_hitl_decision(rejected, REJECTED, "nope", actor="human", now=NOW)
    with pytest.raises(ValueError):
        record_verify(rejected, VERIFIED, "ev")

    fixed = _proposed()
    record_hitl_decision(fixed, APPROVED, "real", actor="human", now=NOW)
    record_verify(fixed, VERIFIED, "ev", now=NOW)
    record_retest(fixed, FIXED, "patched", now=NOW)
    with pytest.raises(ValueError):
        record_verify(fixed, VERIFIED, "ev")


def test_verified_after_rejected_blocked() -> None:
    """An oracle VERIFIED must never land on a human-REJECTED finding."""
    finding = _proposed()
    record_hitl_decision(finding, REJECTED, "false positive", actor="human", now=NOW)
    assert current_state(finding) == REJECTED
    with pytest.raises(ValueError):
        record_verify(finding, VERIFIED, "probe output: uid=0(root)")
    with pytest.raises(ValueError):
        record_verify(finding, HOLDING, "flaky")
    with pytest.raises(ValueError):
        check_transition(REJECTED, VERIFIED, "oracle")


# ── wrong actors raise ─────────────────────────────────────────────────────


def test_human_decision_rejects_nonhuman_actor() -> None:
    for actor in ("", "agent", "llm", "oracle", "retest"):
        with pytest.raises(PermissionError):
            record_hitl_decision(_proposed(), APPROVED, "self-approve", actor=actor)


def test_machine_steps_reject_wrong_actor_at_the_machine() -> None:
    with pytest.raises(ValueError):
        check_transition(PROPOSED, APPROVED, "agent")
    with pytest.raises(ValueError):
        check_transition(PROPOSED, APPROVED, "oracle")
    with pytest.raises(ValueError):
        check_transition(APPROVED, VERIFIED, "human")
    with pytest.raises(ValueError):
        check_transition(VERIFIED, FIXED, "oracle")
    with pytest.raises(ValueError):
        check_transition(VERIFIED, STILL_OPEN, "human")


# ── terminal immutability ──────────────────────────────────────────────────


@pytest.mark.parametrize("terminal", [REJECTED, FIXED])
def test_terminal_states_accept_no_transitions(terminal: str) -> None:
    if terminal == REJECTED:
        finding = _proposed()
        record_hitl_decision(finding, REJECTED, "nope", actor="human", now=NOW)
    else:
        finding = _proposed()
        record_hitl_decision(finding, APPROVED, "real", actor="human", now=NOW)
        record_verify(finding, VERIFIED, "ev", now=NOW)
        record_retest(finding, FIXED, "patched", now=NOW)
    assert current_state(finding) == terminal
    with pytest.raises(ValueError):
        record_hitl_decision(finding, APPROVED, "revive", actor="human", now=NOW)
    with pytest.raises(ValueError):
        record_verify(finding, VERIFIED, "ev")
    with pytest.raises(ValueError):
        record_retest(finding, STILL_OPEN, "ev")
    # INCONCLUSIVE records an attempt, not a state change — it stamps without
    # moving the terminal state.
    record_verify(finding, INCONCLUSIVE, "ambiguous")
    assert current_state(finding) == terminal


# ── evidential vocabulary alignment ────────────────────────────────────────


def test_refuted_is_legacy_alias_only() -> None:
    """REFUTED exists for Flow B mapping; it is never a lifecycle state and
    is never stamped by any record path."""
    from tools.kernel.action_result import EvidentialStatus

    assert EvidentialStatus.REFUTED == "REFUTED"
    for state in (PROPOSED, APPROVED, REJECTED, HOLDING, INCONCLUSIVE, VERIFIED, STILL_OPEN, FIXED):
        assert state != EvidentialStatus.REFUTED
    # Unknown verdicts raise on every lane — REFUTED is accepted nowhere.
    with pytest.raises(ValueError):
        record_hitl_decision(_proposed(), "REFUTED", "x", actor="human")
    with pytest.raises(ValueError):
        record_verify(_proposed(), "REFUTED", "x")
    with pytest.raises(ValueError):
        record_retest(_proposed(), "REFUTED", "x")


def test_swarm_and_campaign_cap_at_holding() -> None:
    """Swarm/campaign layers never self-grade to VERIFIED — only the oracle
    path (record_verify) sets VERIFIED."""
    from tools.kernel.action_result import EvidentialStatus, action_from_campaign_result, action_from_swarm_result

    class _AgentResult:
        status = "complete"
        output = {"access_achieved": True}
        findings: list = []
        evidence_refs: list = []
        task_id = "t1"
        agent_type = "exploit"
        error = ""

    assert action_from_swarm_result(_AgentResult()).evidential_status == EvidentialStatus.HOLDING
    task = {"task_id": "c1", "phase": "exploit", "result": {"status": "exploited", "access_achieved": True}}
    assert action_from_campaign_result(task).evidential_status == EvidentialStatus.HOLDING
    assert action_from_campaign_result(task).evidential_status != EvidentialStatus.VERIFIED


# ── read-surface gate ──────────────────────────────────────────────────────


def test_approved_findings_surfaces_only_reportable_states() -> None:
    from tools.enhanced_reporting import approved_findings

    def _f(fid: str, **kw: Any) -> dict[str, Any]:
        base = {"finding_id": fid}
        base.update(kw)
        return base

    human = [{"timestamp": NOW, "decision": APPROVED, "note": "", "actor": "human"}]
    approved = _f("F-a", hitl_status=APPROVED, hitl_history=human)
    verified = _f(
        "F-v",
        hitl_status=APPROVED,
        hitl_history=human,
        verify_status=VERIFIED,
        verify_history=_verify_history(VERIFIED),
    )
    still_open = _f(
        "F-o",
        hitl_status=APPROVED,
        hitl_history=human,
        verify_status=VERIFIED,
        verify_history=_verify_history(VERIFIED),
        retest_status=STILL_OPEN,
        retest_history=[{"timestamp": NOW, "verdict": STILL_OPEN, "evidence": "open"}],
    )
    assert [f["finding_id"] for f in approved_findings([approved, verified, still_open])] == ["F-a", "F-v", "F-o"]

    hidden = [
        _f("F-p", hitl_status=PROPOSED),
        _f(
            "F-h",
            hitl_status=APPROVED,
            hitl_history=human,
            verify_status=HOLDING,
            verify_history=_verify_history(HOLDING),
        ),
        _f(
            "F-i",
            hitl_status=APPROVED,
            hitl_history=human,
            verify_status=INCONCLUSIVE,
            verify_history=_verify_history(INCONCLUSIVE),
        ),
        _f("F-r", hitl_status=REJECTED),
        _f(
            "F-x",
            hitl_status=APPROVED,
            hitl_history=human,
            verify_status=VERIFIED,
            verify_history=_verify_history(VERIFIED),
            retest_status=FIXED,
            retest_history=[{"timestamp": NOW, "verdict": FIXED, "evidence": "closed"}],
        ),
        _f("F-m"),  # undecided
        "not-a-dict",
        None,
    ]
    assert approved_findings(hidden) == []
