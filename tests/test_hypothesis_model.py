"""TODO 021: terminal-state + sibling-invalidation + confidence preserved."""

from __future__ import annotations

from tools.kernel.hypothesis import Hypothesis, sibling_invalidate, transition, update_confidence


def test_terminal_state_transitions():
    h = Hypothesis(hypothesis_id="h1", statement="sqli", target="10.0.0.1")
    assert h.is_terminal is False
    transition(h, "confirmed", evidence_ref="audit:1", confidence=0.95)
    assert h.status == "confirmed"
    assert h.is_terminal is True
    assert h.evidence_refs == ["audit:1"]
    assert h.belief_transitions[-1]["from"] == "open"


def test_sibling_invalidation():
    a = Hypothesis(hypothesis_id="a", statement="sqli", target="t")
    b = Hypothesis(hypothesis_id="b", statement="xss", target="t")
    transition(a, "confirmed", confidence=0.9)
    sibling_invalidate([a, b], "a")
    assert b.status == "refuted"
    assert a.status == "confirmed"


def test_confidence_updates():
    h = Hypothesis(hypothesis_id="h", confidence=0.5)
    update_confidence(h, supporting=True, weight=0.2)
    assert abs(h.confidence - 0.7) < 1e-9
    update_confidence(h, supporting=False, weight=0.9)
    assert h.confidence >= 0.0


def test_finding_cites_hypothesis_end_to_end():
    from tools.kernel.action_result import action_from_flowb_finding

    c = action_from_flowb_finding({"id": "f1", "status": "CONFIRMED", "hypothesis_id": "h1"})
    assert c.hypothesis_id == "h1"
    h = Hypothesis(hypothesis_id="h1", statement="sqli", target="t", evidence_refs=["audit:1"])
    assert h.hypothesis_id == c.hypothesis_id
