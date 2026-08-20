"""Structured output schemas for the intelligence layer.

Typed validation/repair/fallback for model outputs: validate, repair once,
fall back safely, log telemetry. Never silently accept malformed output.
"""

from .base import (
    BaseSchema,
    ValidationResult,
    _clamp_float,
    _require_str,
    _safe_enum,
    dump_telemetry,
    log_validation,
)
from .critic import CRITIC_DECISIONS, CriticReview, CriticReviewSchema
from .graph import GRAPH_MUTATIONS, GraphMutationProposal, GraphMutationSchema
from .outcome import OUTCOME_VERDICTS, OutcomeAssessment, OutcomeAssessmentSchema
from .planner import (
    CandidatePath,
    CandidatePathSchema,
    HypothesisUpdate,
    HypothesisUpdateSchema,
    PlannerProposal,
    PlannerProposalSchema,
)
from .strategy import StrategyReview, StrategyReviewSchema
from .validator import SafeSchemaLoader, extract_json_block, parse_json_block

__all__ = [
    "BaseSchema",
    "ValidationResult",
    "log_validation",
    "dump_telemetry",
    "_clamp_float",
    "_require_str",
    "_safe_enum",
    "CriticReview",
    "CriticReviewSchema",
    "CRITIC_DECISIONS",
    "GraphMutationProposal",
    "GraphMutationSchema",
    "GRAPH_MUTATIONS",
    "OutcomeAssessment",
    "OutcomeAssessmentSchema",
    "OUTCOME_VERDICTS",
    "PlannerProposal",
    "PlannerProposalSchema",
    "CandidatePath",
    "CandidatePathSchema",
    "HypothesisUpdate",
    "HypothesisUpdateSchema",
    "StrategyReview",
    "StrategyReviewSchema",
    "SafeSchemaLoader",
    "extract_json_block",
    "parse_json_block",
]
