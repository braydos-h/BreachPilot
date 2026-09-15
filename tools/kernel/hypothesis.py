"""Hypothesis/evidence epistemic model for Flow A (TODO 021).

Extracted from Flow B's data model (outcome_judge.HypothesisStatus,
research.db schema v10) into a Flow A-importable module with no Flow B
execution dependency. Flow A findings carry hypothesis lineage: statement,
confidence, checks, evidence refs, belief transitions, terminal state.

Three distinct concepts (docs/outcome-evidence.md):
- execution status (did the tool run?)
- evidential status (is the finding proven by oracle?)
- belief state (what do we believe about the hypothesis?)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

TERMINAL_STATES = frozenset({"confirmed", "refuted", "exhausted", "inconclusive"})
OPEN_STATES = frozenset({"open"})


@dataclass
class Hypothesis:
    hypothesis_id: str = ""
    statement: str = ""
    target: str = ""
    confidence: float = 0.5
    status: str = "open"
    checks: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    belief_transitions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_terminal(self) -> bool:
        return (
            self.status in TERMINAL_STATES
            and self.status != "open"
            and self.status in ("confirmed", "refuted", "exhausted")
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def transition(
    hyp: Hypothesis, to_status: str, *, evidence_ref: str = "", confidence: float | None = None
) -> Hypothesis:
    """Record a belief transition on confirm/refute (terminal states stick)."""
    frm = hyp.status
    hyp.status = to_status
    if confidence is not None:
        hyp.confidence = max(0.0, min(1.0, confidence))
    if evidence_ref and evidence_ref not in hyp.evidence_refs:
        hyp.evidence_refs.append(evidence_ref)
    hyp.belief_transitions.append(
        {"from": frm, "to": to_status, "evidence_ref": evidence_ref, "confidence": hyp.confidence}
    )
    return hyp


def sibling_invalidate(siblings: list[Hypothesis], confirmed_id: str) -> list[Hypothesis]:
    """Confirming one hypothesis refutes its open siblings (preserved semantics)."""
    for sib in siblings:
        if sib.hypothesis_id != confirmed_id and sib.status == "open":
            transition(sib, "refuted", confidence=0.2)
    return siblings


def update_confidence(hyp: Hypothesis, *, supporting: bool, weight: float = 0.1) -> Hypothesis:
    """Bayesian-lite confidence update, clamped 0..1."""
    delta = abs(weight) if supporting else -abs(weight)
    hyp.confidence = max(0.0, min(1.0, hyp.confidence + delta))
    return hyp
