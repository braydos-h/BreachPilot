"""Belief modelling: evidence-driven confidence for hypotheses.

Confidence changes ONLY through registered evidence — never because a model
claims greater certainty. Pure logic, stdlib only, no persistence.
"""

from .confidence import (
    CONFIRMED_THRESHOLD,
    REFUTED_THRESHOLD,
    SUSPECTED_LIKELY_BOUND,
    ConfidenceCalculator,
    ConfidenceUpdate,
    ConfidenceUpdateRule,
    DeterministicUpdater,
    EvidenceUpdateRule,
    NonModelConfidence,
    NonModelConfidenceTag,
    TaggedConfidence,
    compute_status,
)
from .state import (
    BeliefState,
    Claim,
    EpistemicKind,
    EvidenceObservation,
    EvidencePolarity,
    HypothesisState,
    HypothesisStatus,
    promote_to_verified,
)
from .store import BeliefStore

__all__ = [
    "CONFIRMED_THRESHOLD",
    "REFUTED_THRESHOLD",
    "SUSPECTED_LIKELY_BOUND",
    "ConfidenceCalculator",
    "ConfidenceUpdate",
    "ConfidenceUpdateRule",
    "DeterministicUpdater",
    "EvidenceUpdateRule",
    "NonModelConfidence",
    "NonModelConfidenceTag",
    "TaggedConfidence",
    "compute_status",
    "BeliefState",
    "Claim",
    "EpistemicKind",
    "EvidenceObservation",
    "EvidencePolarity",
    "HypothesisState",
    "HypothesisStatus",
    "promote_to_verified",
    "BeliefStore",
]
