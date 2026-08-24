"""Belief state data model: hypotheses, evidence observations, statuses."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class HypothesisStatus(str, Enum):
    """Lifecycle status of a hypothesis."""

    UNKNOWN = "unknown"
    SUSPECTED = "suspected"
    LIKELY = "likely"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    EXHAUSTED = "exhausted"


class EvidencePolarity(str, Enum):
    """Which way an observation pushes a hypothesis."""

    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    NEUTRAL = "neutral"


@dataclass(slots=True)
class EvidenceObservation:
    """A single piece of evidence gathered about a hypothesis.

    `independent` marks whether the observation is a fresh, independent probe
    or a re-statement of already-seen evidence; dependent evidence counts
    less in confidence updates.
    """

    evidence_ref: str
    polarity: EvidencePolarity
    weight: float = 0.5
    source: str = ""
    timestamp: str = ""
    independent: bool = True
    agent_interpretation: str = ""

    def __post_init__(self) -> None:
        """Normalise weight into 0.0..1.0 and provide defaults."""
        self.weight = min(1.0, max(0.0, self.weight))
        if not self.timestamp:
            self.timestamp = _now_iso()


@dataclass(slots=True)
class HypothesisState:
    """Mutable belief state for a single hypothesis.

    Confidence is derived from evidence by the confidence layer; callers must
    not set current_confidence directly to claim certainty.
    """

    hypothesis_id: str
    statement: str
    target: str
    entity: str = ""
    current_confidence: float = 0.5
    supporting_evidence: list[EvidenceObservation] = field(default_factory=list)
    contradicting_evidence: list[EvidenceObservation] = field(default_factory=list)
    independent_observation_count: int = 0
    check_fingerprints_attempted: set[str] = field(default_factory=set)
    candidate_checks: list[str] = field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.UNKNOWN
    created_at: str = ""
    updated_at: str = ""
    provenance: str = ""
    derived_from: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Timestamp the state and normalise confidence."""
        self.current_confidence = min(1.0, max(0.0, self.current_confidence))
        if not self.created_at:
            self.created_at = _now_iso()
        self.updated_at = _now_iso()


@dataclass(slots=True)
class BeliefState:
    """Collection of hypothesis states for a mission, keyed by id."""

    mission_id: str
    hypotheses: dict[str, HypothesisState] = field(default_factory=dict)

    def add_hypothesis(
        self,
        statement: str,
        target: str,
        entity: str = "",
        provenance: str = "",
    ) -> str:
        """Create a hypothesis and return its generated id."""
        hypothesis_id = str(uuid.uuid4())
        self.hypotheses[hypothesis_id] = HypothesisState(
            hypothesis_id=hypothesis_id,
            statement=statement,
            target=target,
            entity=entity,
            provenance=provenance,
        )
        return hypothesis_id

    def get(self, hypothesis_id: str) -> HypothesisState | None:
        """Return the hypothesis state, or None if unknown."""
        return self.hypotheses.get(hypothesis_id)

    def register_evidence(
        self, hypothesis_id: str, evidence_observation: EvidenceObservation
    ) -> HypothesisState | None:
        """Record evidence against a hypothesis and update its confidence.

        Appends to the matching polarity list (deduped by evidence_ref), then
        applies the deterministic default update rule so confidence moves with
        the evidence. Returns the updated state, or None if unknown.
        """
        state = self.hypotheses.get(hypothesis_id)
        if state is None:
            return None
        from .confidence import apply_observation

        apply_observation(state, evidence_observation)
        return state

    def register_observation(
        self,
        hypothesis_id: str,
        evidence_ref: str,
        polarity: str,
        weight: float = 0.5,
        source: str = "",
        independent: bool = True,
        agent_interpretation: str = "",
    ) -> HypothesisState | None:
        """DEPRECATED: register evidence by fields instead of an object."""
        obs = EvidenceObservation(
            evidence_ref=evidence_ref,
            polarity=EvidencePolarity(polarity),
            weight=weight,
            source=source,
            independent=independent,
            agent_interpretation=agent_interpretation,
        )
        return self.register_evidence(hypothesis_id, obs)

    def next_discriminating_check(self, hypothesis_id: str, available_checks: list[str]) -> str | None:
        """Pick the best un-attempted check from the candidates.

        Candidate checks are listed in freshness order (newest first); a check
        that is both listed and still un-attempted is preferred, in that
        order, over one that has already been tried.
        """
        state = self.hypotheses.get(hypothesis_id)
        if not state or not available_checks:
            return None
        for check in state.candidate_checks:
            if check in available_checks and check not in state.check_fingerprints_attempted:
                return check
        for check in available_checks:
            if check not in state.check_fingerprints_attempted:
                return check
        return None

    def snapshot(self) -> dict[str, Any]:
        """Serialisable plain-dict copy of this belief state."""
        return {
            "mission_id": self.mission_id,
            "hypotheses": {hid: _state_to_dict(s) for hid, s in self.hypotheses.items()},
        }

    @classmethod
    def load(cls, snapshot_dict: dict[str, Any]) -> "BeliefState":
        """Reconstruct a belief state from a snapshot dictionary."""
        return cls(
            mission_id=snapshot_dict["mission_id"],
            hypotheses={hid: _state_from_dict(hid, hd) for hid, hd in snapshot_dict["hypotheses"].items()},
        )

    def top_unresolved(self, limit: int = 5) -> list[HypothesisState]:
        """Hypotheses with the highest uncertainty, unresolved first.

        Uncertainty = 1 - abs(confidence - 0.5) * 2; states already
        CONFIRMED/REFUTED/EXHAUSTED are excluded.
        """
        unresolved = [
            h
            for h in self.hypotheses.values()
            if h.status not in (HypothesisStatus.CONFIRMED, HypothesisStatus.REFUTED, HypothesisStatus.EXHAUSTED)
        ]
        unresolved.sort(
            key=lambda h: (1 - abs(h.current_confidence - 0.5) * 2, h.created_at),
            reverse=True,
        )
        return unresolved[:limit]

    def to_json(self) -> str:
        """Serialise this belief state to JSON."""
        return json.dumps(self.snapshot(), default=str, sort_keys=True)

    @classmethod
    def from_json(cls, payload: str) -> "BeliefState":
        """Rehydrate a belief state from to_json() output."""
        return cls.load(json.loads(payload))


def _now_iso() -> str:
    """Current UTC time in ISO 8601 form."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _apply_evidence(state: HypothesisState, obs: EvidenceObservation) -> None:
    """Record an observation into the right polarity list (deduped)."""
    target_list = (
        state.supporting_evidence if obs.polarity is EvidencePolarity.SUPPORTING else state.contradicting_evidence
    )
    if any(e.evidence_ref == obs.evidence_ref for e in target_list):
        return
    target_list.append(obs)
    if obs.independent:
        state.independent_observation_count += 1
    state.updated_at = _now_iso()


def _state_to_dict(state: HypothesisState) -> dict[str, Any]:
    """Convert a hypothesis state to a plain dict."""
    return {
        "statement": state.statement,
        "target": state.target,
        "entity": state.entity,
        "current_confidence": state.current_confidence,
        "supporting_evidence": [_obs_to_dict(o) for o in state.supporting_evidence],
        "contradicting_evidence": [_obs_to_dict(o) for o in state.contradicting_evidence],
        "independent_observation_count": state.independent_observation_count,
        "check_fingerprints_attempted": sorted(state.check_fingerprints_attempted),
        "candidate_checks": list(state.candidate_checks),
        "status": state.status.value,
        "created_at": state.created_at,
        "updated_at": state.updated_at,
        "provenance": state.provenance,
        "derived_from": list(state.derived_from),
    }


def _state_from_dict(hypothesis_id: str, data: dict[str, Any]) -> HypothesisState:
    """Rebuild a hypothesis state from a plain dict."""
    return HypothesisState(
        hypothesis_id=hypothesis_id,
        statement=data["statement"],
        target=data["target"],
        entity=data.get("entity", ""),
        current_confidence=data.get("current_confidence", 0.5),
        supporting_evidence=[_obs_from_dict(o) for o in data.get("supporting_evidence", [])],
        contradicting_evidence=[_obs_from_dict(o) for o in data.get("contradicting_evidence", [])],
        independent_observation_count=data.get("independent_observation_count", 0),
        check_fingerprints_attempted=set(data.get("check_fingerprints_attempted", [])),
        candidate_checks=list(data.get("candidate_checks", [])),
        status=HypothesisStatus(data.get("status", HypothesisStatus.UNKNOWN.value)),
        created_at=data.get("created_at", ""),
        updated_at=data.get("updated_at", ""),
        provenance=data.get("provenance", ""),
        derived_from=list(data.get("derived_from", [])),
    )


def _obs_to_dict(obs: EvidenceObservation) -> dict[str, Any]:
    """Convert an observation to a plain dict."""
    return {
        "evidence_ref": obs.evidence_ref,
        "polarity": obs.polarity.value,
        "weight": obs.weight,
        "source": obs.source,
        "timestamp": obs.timestamp,
        "independent": obs.independent,
        "agent_interpretation": obs.agent_interpretation,
    }


def _obs_from_dict(data: dict[str, Any]) -> EvidenceObservation:
    """Rebuild an observation from a plain dict."""
    return EvidenceObservation(
        evidence_ref=data["evidence_ref"],
        polarity=EvidencePolarity(data["polarity"]),
        weight=data.get("weight", 0.5),
        source=data.get("source", ""),
        timestamp=data.get("timestamp", ""),
        independent=data.get("independent", False),
        agent_interpretation=data.get("agent_interpretation", ""),
    )
