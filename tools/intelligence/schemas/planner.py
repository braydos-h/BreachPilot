"""Schema for planner proposals, candidate paths, and hypothesis updates."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .base import BaseSchema, ValidationResult, _clamp_float, _require_str

MAX_STATEMENT_LEN = 500
PLANNER_STATUSES = ("open", "confirmed", "refuted", "inconclusive", "exhausted")


@dataclass(slots=True)
class PlannerProposal:
    """A single hypothesis the planner proposes to investigate."""

    hypothesis_id: str
    statement: str
    target: str
    entity: str = ""
    technique_category: str = ""
    rationale: str = ""
    confidence: float = 0.5
    expected_information_gain: float = 0.0
    suggested_checks: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CandidatePath:
    """A ranked next-step path through the attack graph."""

    steps: list[str]
    score: float = 0.0
    evidence_confidence: float = 0.5
    uncertainty: float = 0.5
    assumptions: list[str] = field(default_factory=list)
    expected_information_gain: float = 0.0
    estimated_cost: int = 0
    explanation: str = ""


@dataclass(slots=True)
class HypothesisUpdate:
    """An update to an existing hypothesis' status or confidence."""

    statement: str
    target: str
    status: str = "open"
    confidence: float = 0.5
    evidence_refs: list[str] = field(default_factory=list)
    reason: str = ""


class PlannerProposalSchema(BaseSchema):
    """PlannerProposal validation: statement required, confidence in [0,1]."""

    def validate(self, raw: dict) -> ValidationResult:
        errors: list[str] = []
        if not isinstance(raw, dict):
            return ValidationResult(valid=False, errors=["not a dict"])
        statement = raw.get("statement")
        if not isinstance(statement, str):
            errors.append("statement must be a string")
        elif not statement.strip():
            errors.append("statement is empty")
        elif len(statement) > MAX_STATEMENT_LEN:
            errors.append(f"statement exceeds {MAX_STATEMENT_LEN} chars")
        if not isinstance(raw.get("suggested_checks"), (list, type(None))):
            errors.append("suggested_checks must be a list")
        confidence = raw.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            errors.append(f"confidence {confidence!r} out of range [0,1]")
        return ValidationResult(valid=not errors, errors=errors)

    def repair(self, raw: dict, errors: list[str]) -> dict:
        fixed = dict(raw)
        statement = fixed.get("statement")
        if not isinstance(statement, str) or not statement.strip():
            fixed["statement"] = "untitled hypothesis"
            errors.append("statement repaired to 'untitled hypothesis'")
        confidence = fixed.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            fixed["confidence"] = _clamp_float(confidence, 0.0, 1.0)
            errors.append(f"confidence clamped to {fixed['confidence']}")
        if not isinstance(fixed.get("suggested_checks"), list):
            fixed["suggested_checks"] = []
        return fixed

    def coerce(self, raw: dict) -> PlannerProposal:
        raw = self.repair(dict(raw), []) if not self.validate(raw).valid else raw
        return PlannerProposal(
            hypothesis_id=str(raw.get("hypothesis_id", "")),
            statement=str(raw.get("statement", "")),
            target=str(raw.get("target", "")),
            entity=str(raw.get("entity", "")),
            technique_category=str(raw.get("technique_category", "")),
            rationale=str(raw.get("rationale", "")),
            confidence=_clamp_float(raw.get("confidence", 0.5), 0.0, 1.0),
            expected_information_gain=_clamp_float(raw.get("expected_information_gain", 0.0), 0.0, 1.0),
            suggested_checks=self._str_list(raw.get("suggested_checks", [])),
        )


class CandidatePathSchema(BaseSchema):
    """CandidatePath validation: steps must be a non-empty list of strings."""

    def validate(self, raw: dict) -> ValidationResult:
        errors: list[str] = []
        if not isinstance(raw, dict):
            return ValidationResult(False, ["not a dict"])
        steps = raw.get("steps")
        if not isinstance(steps, list) or not steps or not all(isinstance(s, str) for s in steps):
            errors.append("steps must be a non-empty list of strings")
        score = raw.get("score", 0.0)
        if not isinstance(score, (int, float)) or score < 0:
            errors.append(f"score {score!r} is negative or not numeric")
        return ValidationResult(valid=not errors, errors=errors)

    def repair(self, raw: dict, errors: list[str]) -> dict:
        fixed = dict(raw)
        steps = fixed.get("steps")
        if not isinstance(steps, list) or not steps or not all(isinstance(s, str) for s in steps):
            fixed["steps"] = []
            errors.append("steps repaired to []")
        score = fixed.get("score", 0.0)
        if not isinstance(score, (int, float)) or score < 0:
            fixed["score"] = max(0.0, _clamp_float(score, 0.0, 1e9))
            errors.append(f"score repaired to {fixed['score']}")
        return fixed

    def coerce(self, raw: dict) -> CandidatePath:
        if not self.validate(raw).valid:
            raw = self.repair(dict(raw), [])
        return CandidatePath(
            steps=self._str_list(raw.get("steps", [])),
            score=_clamp_float(raw.get("score", 0.0), 0.0, 1e9),
            evidence_confidence=_clamp_float(raw.get("evidence_confidence", 0.5), 0.0, 1.0),
            uncertainty=_clamp_float(raw.get("uncertainty", 0.5), 0.0, 1.0),
            assumptions=self._str_list(raw.get("assumptions", [])),
            expected_information_gain=_clamp_float(raw.get("expected_information_gain", 0.0), 0.0, 1.0),
            estimated_cost=int(raw.get("estimated_cost", 0) or 0),
            explanation=str(raw.get("explanation", "")),
        )


class HypothesisUpdateSchema(BaseSchema):
    """HypothesisUpdate validation: status in the allowed set, confidence in [0,1]."""

    def validate(self, raw: dict) -> ValidationResult:
        errors: list[str] = []
        if not isinstance(raw, dict):
            return ValidationResult(False, ["not a dict"])
        status = raw.get("status", "open")
        if status not in PLANNER_STATUSES:
            errors.append(f"status {status!r} not in {PLANNER_STATUSES}")
        confidence = raw.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            errors.append(f"confidence {confidence!r} out of range [0,1]")
        return ValidationResult(valid=not errors, errors=errors)

    def repair(self, raw: dict, errors: list[str]) -> dict:
        fixed = dict(raw)
        if fixed.get("status") not in PLANNER_STATUSES:
            fixed["status"] = "open"
            errors.append("status repaired to 'open'")
        confidence = fixed.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            fixed["confidence"] = _clamp_float(confidence, 0.0, 1.0)
            errors.append(f"confidence clamped to {fixed['confidence']}")
        return fixed

    def coerce(self, raw: dict) -> HypothesisUpdate:
        if not self.validate(raw).valid:
            raw = self.repair(dict(raw), [])
        return HypothesisUpdate(
            statement=str(raw.get("statement", "")),
            target=str(raw.get("target", "")),
            status=str(raw.get("status", "open")),
            confidence=_clamp_float(raw.get("confidence", 0.5), 0.0, 1.0),
            evidence_refs=self._str_list(raw.get("evidence_refs", [])),
            reason=str(raw.get("reason", "")),
        )
