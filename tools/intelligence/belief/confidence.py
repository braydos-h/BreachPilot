"""Deterministic confidence update rules.

Confidence changes ONLY as a function of registered evidence. The update
rules are pure arithmetic over the observation's polarity, weight, and
independence — nothing here trusts a model's claim of certainty.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from .state import (
    EvidenceObservation,
    EvidencePolarity,
    HypothesisState,
    HypothesisStatus,
    _apply_evidence,
)

CONFIRMED_THRESHOLD = 0.75
REFUTED_THRESHOLD = 0.25
SUSPECTED_LIKELY_BOUND = 0.45
_DEPENDENT_BONUS = 0.6


def _clamp01(value: float) -> float:
    """Clamp a confidence value into the unit interval."""
    return min(1.0, max(0.0, value))


def _independence_bonus(obs: EvidenceObservation) -> float:
    """1.0 for independent evidence, 0.6 for dependent (re-stated) evidence."""
    return 1.0 if obs.independent else _DEPENDENT_BONUS


class EvidenceUpdateRule:
    """The default MIXED update rule: additive on support, multiplicative on
    contradiction, scaled by weight and independence."""

    @staticmethod
    def update_confidence(
        current: float, obs: EvidenceObservation, state: HypothesisState
    ) -> float:
        """Return the updated confidence for one observation."""
        if obs.polarity is EvidencePolarity.NEUTRAL or obs.weight <= 0.0:
            return current
        bonus = _independence_bonus(obs)
        if obs.polarity is EvidencePolarity.SUPPORTING:
            return _clamp01(current + (1 - current) * obs.weight * bonus)
        return _clamp01(current * (1 - obs.weight * bonus))


class ConfidenceUpdateRule(str, Enum):
    """Named families of update rules (STEP, MULTIPLICATIVE, BAYESIAN_BETA)."""

    STEP = "step"
    MULTIPLICATIVE = "multiplicative"
    BAYESIAN_BETA = "bayesian_beta"

    def apply(self, current: float, weight: float, polarity: EvidencePolarity) -> float:
        """Apply this rule for one weighted observation."""
        if polarity is EvidencePolarity.NEUTRAL or weight <= 0.0:
            return current
        if polarity is EvidencePolarity.SUPPORTING:
            if self is ConfidenceUpdate.MULTIPLICATIVE:
                return _clamp01(current * (1 + weight))
            return _clamp01(current + (1 - current) * weight)
        if self is ConfidenceUpdate.MULTIPLICATIVE:
            return _clamp01(current * (1 - weight))
        return _clamp01(current * (1 - weight))


ConfidenceUpdate = ConfidenceUpdateRule


def apply_observation(state: HypothesisState, obs: EvidenceObservation) -> None:
    """Record an observation and apply the default update rule in one step."""
    _apply_evidence(state, obs)
    state.current_confidence = ConfidenceCalculator().update(
        ConfidenceCalculator.default_rule, state.current_confidence, obs, state
    )


class ConfidenceCalculator:
    """Dispatches an observation to a rule for a hypothesis state."""

    default_rule: ConfidenceUpdate = ConfidenceUpdate.BAYESIAN_BETA

    def update(
        self,
        rule: ConfidenceUpdateRule,
        current: float,
        obs: EvidenceObservation,
        state: HypothesisState,
    ) -> float:
        """Compute the updated confidence under `rule` for `obs` on `state`."""
        if rule is ConfidenceUpdate.BAYESIAN_BETA:
            return self._bayesian_beta(current, obs, state)
        return rule.apply(current, obs.weight, obs.polarity)

    def _bayesian_beta(
        self, current: float, obs: EvidenceObservation, state: HypothesisState
    ) -> float:
        """Approximate Beta-posterior mean update.

        Pseudo-count K scales with the independent observation count seen so
        far (at least 2); support increments alpha, contradiction beta.
        """
        if obs.polarity is EvidencePolarity.NEUTRAL or obs.weight <= 0.0:
            return current
        k = max(2, state.independent_observation_count)
        alpha = current * k
        beta = (1 - current) * k
        if obs.polarity is EvidencePolarity.SUPPORTING:
            alpha += obs.weight
        else:
            beta += obs.weight
        return _clamp01(alpha / (alpha + beta))


def compute_status(
    confidence: float,
    evidence_count: int = 0,
    supporting_count: int = 0,
    contradicting_count: int = 0,
    exhausted: bool = False,
) -> HypothesisStatus:
    """Map a confidence value to a hypothesis status from the evidence base.

    A status can only be CONFIRMED/REFUTED when there is evidence on the
    matching side; a bare numeric claim never reaches those states.
    """
    if exhausted:
        return HypothesisStatus.EXHAUSTED
    if confidence < 0.1 or evidence_count == 0:
        return HypothesisStatus.UNKNOWN
    if confidence >= CONFIRMED_THRESHOLD and supporting_count > 0:
        return HypothesisStatus.CONFIRMED
    if confidence <= REFUTED_THRESHOLD and contradicting_count > 0:
        return HypothesisStatus.REFUTED
    if confidence < SUSPECTED_LIKELY_BOUND:
        return HypothesisStatus.SUSPECTED
    if confidence < CONFIRMED_THRESHOLD:
        return HypothesisStatus.LIKELY
    return HypothesisStatus.LIKELY


class DeterministicUpdater:
    """Applies observations in order and mutates the hypothesis state."""

    def __init__(self, rule: ConfidenceUpdateRule = ConfidenceUpdate.BAYESIAN_BETA) -> None:
        """Configure which update rule the updater uses."""
        self.rule = rule
        self._calculator = ConfidenceCalculator()

    def apply(
        self,
        hypothesis: HypothesisState,
        observations: list[EvidenceObservation],
    ) -> float:
        """Fold observations into the hypothesis in order; return final confidence."""
        for obs in observations:
            _apply_evidence(hypothesis, obs)
            hypothesis.current_confidence = self._calculator.update(
                self.rule, hypothesis.current_confidence, obs, hypothesis
            )
        hypothesis.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return hypothesis.current_confidence


class NonModelConfidence(str, Enum):
    """Typed tags for confidence concepts that are NOT belief confidence.

    These are distinct scales on different phenomena; they must never be
    collapsed into, or compared with, hypothesis confidence.
    """

    TOOL_EXECUTION_SUCCESS = "tool_execution_success"
    OBSERVATION_CONFIDENCE = "observation_confidence"
    VULNERABILITY_LIKELIHOOD = "vulnerability_likelihood"
    PATH_VIABILITY = "path_viability"
    FINDING_CONFIRMATION = "finding_confirmation"

    def apply(self, value: float, source: str = "", note: str = "") -> "TaggedConfidence":
        """Tag a value on this concept's scale without touching belief confidence."""
        return TaggedConfidence(concept=self, value=min(1.0, max(0.0, value)), source=source, note=note)


NonModelConfidenceTag = NonModelConfidence


@dataclass(slots=True)
class TaggedConfidence:
    """A value on one of the non-model confidence scales, with provenance."""

    concept: NonModelConfidenceTag
    value: float
    source: str = ""
    note: str = ""
