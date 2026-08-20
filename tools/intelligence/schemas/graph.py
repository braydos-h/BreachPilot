"""Schema for attack-graph mutation proposals."""

from __future__ import annotations

from dataclasses import dataclass

from .base import BaseSchema, ValidationResult, _clamp_float

GRAPH_MUTATIONS = ("add_node", "add_edge", "update_confidence", "remove_node")


@dataclass(slots=True)
class GraphMutationProposal:
    """A proposed mutation to the attack graph."""

    node: str
    edge: str = ""
    mutation: str = ""
    confidence: float = 0.5
    evidence_ref: str = ""
    reason: str = ""


class GraphMutationSchema(BaseSchema):
    """GraphMutationProposal validation: mutation in the allowed set.

    Repair maps invalid mutations to "update_confidence" — the least
    destructive action. Confidence is clamped to [0,1].
    """

    def validate(self, raw: dict) -> ValidationResult:
        errors: list[str] = []
        if not isinstance(raw, dict):
            return ValidationResult(False, ["not a dict"])
        if raw.get("mutation") not in GRAPH_MUTATIONS:
            errors.append(f"mutation {raw.get('mutation')!r} not in {GRAPH_MUTATIONS}")
        confidence = raw.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            errors.append(f"confidence {confidence!r} out of range [0,1]")
        return ValidationResult(valid=not errors, errors=errors)

    def repair(self, raw: dict, errors: list[str]) -> dict:
        fixed = dict(raw)
        if fixed.get("mutation") not in GRAPH_MUTATIONS:
            fixed["mutation"] = "update_confidence"
            errors.append("mutation repaired to 'update_confidence'")
        confidence = fixed.get("confidence", 0.5)
        if not isinstance(confidence, (int, float)) or not 0.0 <= confidence <= 1.0:
            fixed["confidence"] = _clamp_float(confidence, 0.0, 1.0)
            errors.append(f"confidence clamped to {fixed['confidence']}")
        return fixed

    def coerce(self, raw: dict) -> GraphMutationProposal:
        if not self.validate(raw).valid:
            raw = self.repair(dict(raw), [])
        return GraphMutationProposal(
            node=str(raw.get("node", "")),
            edge=str(raw.get("edge", "")),
            mutation=str(raw.get("mutation", "update_confidence")),
            confidence=_clamp_float(raw.get("confidence", 0.5), 0.0, 1.0),
            evidence_ref=str(raw.get("evidence_ref", "")),
            reason=str(raw.get("reason", "")),
        )
