"""Schema for strategy-layer review of the overall investigation."""

from __future__ import annotations

from dataclasses import dataclass

from .base import BaseSchema, ValidationResult, _clamp_float

REQUIRED_LIST_FIELDS = (
    "top_unresolved",
    "uncertainty_areas",
    "weak_assumption_paths",
    "duplicate_work",
    "recommended_evidence",
)


@dataclass(slots=True)
class StrategyReview:
    """The strategy reviewer's assessment of the investigation plan."""

    top_unresolved: list[str]
    uncertainty_areas: list[str]
    weak_assumption_paths: list[str]
    duplicate_work: list[str]
    recommended_evidence: list[str]
    overall_assessment: str = ""
    confidence: float = 0.5


class StrategyReviewSchema(BaseSchema):
    """StrategyReview validation: all five list fields required, trimmed text."""

    def validate(self, raw: dict) -> ValidationResult:
        errors: list[str] = []
        if not isinstance(raw, dict):
            return ValidationResult(False, ["not a dict"])
        for key in REQUIRED_LIST_FIELDS:
            if not isinstance(raw.get(key), list):
                errors.append(f"{key} must be a list")
        confidence = raw.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            errors.append(f"confidence {confidence!r} out of range [0,1]")
        return ValidationResult(valid=not errors, errors=errors)

    def repair(self, raw: dict, errors: list[str]) -> dict:
        fixed = dict(raw)
        for key in REQUIRED_LIST_FIELDS:
            if not isinstance(fixed.get(key), list):
                fixed[key] = []
                errors.append(f"{key} repaired to []")
        if isinstance(fixed.get("overall_assessment"), str):
            fixed["overall_assessment"] = fixed["overall_assessment"].strip()
        else:
            fixed["overall_assessment"] = ""
        confidence = fixed.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            fixed["confidence"] = _clamp_float(confidence, 0.0, 1.0)
            errors.append(f"confidence clamped to {fixed['confidence']}")
        return fixed

    def coerce(self, raw: dict) -> StrategyReview:
        if not self.validate(raw).valid:
            raw = self.repair(dict(raw), [])
        return StrategyReview(
            top_unresolved=self._str_list(raw.get("top_unresolved", [])),
            uncertainty_areas=self._str_list(raw.get("uncertainty_areas", [])),
            weak_assumption_paths=self._str_list(raw.get("weak_assumption_paths", [])),
            duplicate_work=self._str_list(raw.get("duplicate_work", [])),
            recommended_evidence=self._str_list(raw.get("recommended_evidence", [])),
            overall_assessment=str(raw.get("overall_assessment", "")).strip(),
            confidence=_clamp_float(raw.get("confidence", 0.5), 0.0, 1.0),
        )
