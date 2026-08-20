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
    EvidenceObservation,
    EvidencePolarity,
    HypothesisState,
    HypothesisStatus,
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
    "EvidenceObservation",
    "EvidencePolarity",
    "HypothesisState",
    "HypothesisStatus",
    "BeliefStore",
]
