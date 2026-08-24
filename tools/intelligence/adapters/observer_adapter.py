"""Flow B adapters: Observer -> v2 intelligence primitives (defect C4).

Wires the dead ``Observation`` fields (``hypothesis_evidence``,
``graph_updates``, ``confidence``) into the v2 evidence model so
``outcome_judge._explicit_evidence_scores`` reads structured claims instead
of falling back to raw-text substring scanning.
"""

from __future__ import annotations

from typing import Any

from observer import Observation
from tools.intelligence.belief.state import EvidenceObservation, EvidencePolarity
from tools.intelligence.fingerprint.tracker import is_permanent_failure

# Tokens outcome_judge._explicit_evidence_scores actually matches
# (outcome_judge.py:804-807). The enum values ("supporting"/"contradicting")
# are NOT in its support/refute sets, so entries must use these tokens.
_SUPPORT_TOKEN = "supports"
_CONTRADICT_TOKEN = "contradicts"


class ObserverAdapter:
    """Converts structured Observations into v2 evidence primitives."""

    def populate_hypothesis_evidence(self, observation: Observation) -> list[EvidenceObservation]:
        """Build one SUPPORTING EvidenceObservation per fact/technology/endpoint.

        Returns the EvidenceObservation objects AND sets
        ``observation.hypothesis_evidence`` to plain dicts shaped for
        outcome_judge._explicit_evidence_scores: each entry carries the
        ``polarity`` and ``confidence`` keys outcome_judge reads
        (outcome_judge.py:797-800).
        """
        values = list(dict.fromkeys(observation.facts + observation.new_technologies + observation.new_endpoints))
        entries = [
            EvidenceObservation(
                evidence_ref=f"obs:{observation.target}:{i}",
                polarity=EvidencePolarity.SUPPORTING,
                weight=0.5,
                source="observer",
                timestamp="",
                independent=True,
            )
            for i in range(len(values))
        ]
        observation.hypothesis_evidence = [
            {
                "evidence_ref": entry.evidence_ref,
                "polarity": _SUPPORT_TOKEN,
                "claim": value,
                "confidence": entry.weight,
            }
            for entry, value in zip(entries, values)
        ]
        return entries

    def populate_graph_updates(self, observation: Observation, node_map: dict) -> list[dict[str, Any]]:
        """Emit endpoint/technology -> target graph_updates entries (pure dicts)."""
        updates: list[dict[str, Any]] = []
        for endpoint in observation.new_endpoints:
            updates.append(
                {
                    "node": node_map.get(endpoint, endpoint),
                    "type": "endpoint",
                    "edge_to": observation.target,
                    "relation": "exposes",
                }
            )
        for tech in observation.new_technologies:
            updates.append(
                {
                    "node": node_map.get(tech, tech),
                    "type": "technology",
                    "edge_to": observation.target,
                    "relation": "runs",
                }
            )
        return updates

    def infer_confidence(self, observation: Observation) -> float:
        """Deterministic confidence: 0.3 + 0.1/fact + 0.1 if evidence_refs, capped 0.9.

        Sets the otherwise-dead ``observation.confidence`` field.
        """
        confidence = 0.3 + 0.1 * len(observation.facts)
        if observation.evidence_refs:
            confidence += 0.1
        observation.confidence = round(min(confidence, 0.9), 2)
        return observation.confidence

    @staticmethod
    def classify_dead_end(raw_output: str) -> bool:
        """True if the output matches the shared permanent-failure vocabulary."""
        return is_permanent_failure(raw_output)
