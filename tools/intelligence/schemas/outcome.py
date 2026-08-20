"""Schema for outcome assessments after evidence collection."""

from __future__ import annotations

from dataclasses import dataclass, field

from .base import BaseSchema, ValidationResult, _clamp_float

OUTCOME_VERDICTS = ("confirmed", "refuted", "inconclusive", "exhausted", "unknown")


@dataclass(slots=True)
class OutcomeAssessment:
    """The final verdict on a hypothesis given collected evidence."""

    verdict: str
    confidence: float = 0.5
    supporting_evidence: list[str] = field(default_factory=list)
    contradictory_evidence: list[str] = field(default_factory=list)
    criteria_satisfied: list[str] = field(default_factory=list)
    criteria_not_satisfied: list[str] = field(default_factory=list)
    next_recommended_evidence: str = ""
    explanation: str = ""


class OutcomeAssessmentSchema(BaseSchema):
    """OutcomeAssessment validation: verdict in the allowed set.

    Repair maps missing/invalid verdicts to "unknown" — never "confirmed".
    Criteria/evidence lists are normalized to lists.
    """

    def validate(self, raw: dict) -> ValidationResult:
        errors: list[str] = []
        if not isinstance(raw, dict):
            return ValidationResult(False, ["not a dict"])
        if raw.get("verdict") not in OUTCOME_VERDICTS:
            errors.append(f"verdict {raw.get('verdict')!r} not in {OUTCOME_VERDICTS}")
        for key in ("supporting_evidence", "contradictory_evidence", "criteria_satisfied", "criteria_not_satisfied"):
            if not isinstance(raw.get(key), (list, type(None))):
                errors.append(f"{key} must be a list")
        confidence = raw.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            errors.append(f"confidence {confidence!r} out of range [0,1]")
        return ValidationResult(valid=not errors, errors=errors)

    def repair(self, raw: dict, errors: list[str]) -> dict:
        fixed = dict(raw)
        if fixed.get("verdict") not in OUTCOME_VERDICTS:
            fixed["verdict"] = "unknown"
            errors.append("verdict repaired to 'unknown'")
        for key in ("supporting_evidence", "contradictory_evidence", "criteria_satisfied", "criteria_not_satisfied"):
            if not isinstance(fixed.get(key), list):
                fixed[key] = []
                errors.append(f"{key} repaired to []")
        confidence = fixed.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            fixed["confidence"] = _clamp_float(confidence, 0.0, 1.0)
            errors.append(f"confidence clamped to {fixed['confidence']}")
        return fixed

    def coerce(self, raw: dict) -> OutcomeAssessment:
        if not self.validate(raw).valid:
            raw = self.repair(dict(raw), [])
        return OutcomeAssessment(
            verdict=str(raw.get("verdict", "unknown")),
            confidence=_clamp_float(raw.get("confidence", 0.5), 0.0, 1.0),
            supporting_evidence=self._str_list(raw.get("supporting_evidence", [])),
            contradictory_evidence=self._str_list(raw.get("contradictory_evidence", [])),
            criteria_satisfied=self._str_list(raw.get("criteria_satisfied", [])),
            criteria_not_satisfied=self._str_list(raw.get("criteria_not_satisfied", [])),
            next_recommended_evidence=str(raw.get("next_recommended_evidence", "")),
            explanation=str(raw.get("explanation", "")),
        )
