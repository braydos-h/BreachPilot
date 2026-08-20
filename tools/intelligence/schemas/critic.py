"""Schema for critic reviews of plans and evidence."""

from __future__ import annotations

from dataclasses import dataclass, field

from .base import BaseSchema, ValidationResult, _clamp_float

CRITIC_DECISIONS = ("approve", "deny", "modify")


@dataclass(frozen=True, slots=True)
class CriticReview:
    """The critic's verdict on a plan, with objections and gaps."""

    decision: str
    objections: list[str] = field(default_factory=list)
    evidence_missing: list[str] = field(default_factory=list)
    alternate_explanations: list[str] = field(default_factory=list)
    stale_data: bool = False
    single_source: bool = False
    confidence: float = 0.5
    reasoning: str = ""


class CriticReviewSchema(BaseSchema):
    """CriticReview validation: decision in {approve, deny, modify}.

    Repair defaults invalid/missing decisions to "modify" — the fail-safe
    choice per repo convention (see critic_agent.py:278).
    """

    def validate(self, raw: dict) -> ValidationResult:
        errors: list[str] = []
        if not isinstance(raw, dict):
            return ValidationResult(False, ["not a dict"])
        if raw.get("decision") not in CRITIC_DECISIONS:
            errors.append(f"decision {raw.get('decision')!r} not in {CRITIC_DECISIONS}")
        for key in ("objections", "evidence_missing", "alternate_explanations"):
            if not isinstance(raw.get(key), (list, type(None))):
                errors.append(f"{key} must be a list")
        confidence = raw.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            errors.append(f"confidence {confidence!r} out of range [0,1]")
        return ValidationResult(valid=not errors, errors=errors)

    def repair(self, raw: dict, errors: list[str]) -> dict:
        fixed = dict(raw)
        if fixed.get("decision") not in CRITIC_DECISIONS:
            fixed["decision"] = "modify"
            errors.append("decision repaired to 'modify'")
        for key in ("objections", "evidence_missing", "alternate_explanations"):
            if not isinstance(fixed.get(key), list):
                fixed[key] = []
                errors.append(f"{key} repaired to []")
        confidence = fixed.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            fixed["confidence"] = _clamp_float(confidence, 0.0, 1.0)
            errors.append(f"confidence clamped to {fixed['confidence']}")
        return fixed

    def coerce(self, raw: dict) -> CriticReview:
        if not self.validate(raw).valid:
            raw = self.repair(dict(raw), [])
        return CriticReview(
            decision=str(raw.get("decision", "modify")),
            objections=self._str_list(raw.get("objections", [])),
            evidence_missing=self._str_list(raw.get("evidence_missing", [])),
            alternate_explanations=self._str_list(raw.get("alternate_explanations", [])),
            stale_data=bool(raw.get("stale_data", False)),
            single_source=bool(raw.get("single_source", False)),
            confidence=_clamp_float(raw.get("confidence", 0.5), 0.0, 1.0),
            reasoning=str(raw.get("reasoning", "")),
        )
