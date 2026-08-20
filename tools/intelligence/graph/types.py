"""Typed graph model for AttackGraph v2.

Defines the node/edge enums, frozen node/edge dataclasses with resilient
dict round-trips, the proposed-mutation record used by CorrelationAgent and
blackboard events, and the credential-redaction helpers that keep raw
secrets out of graph properties.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeVar

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class NodeType(str, Enum):
    """Kinds of graph nodes; drives typed lookups in GraphTraversal."""

    ASSET = "asset"
    HOST = "host"
    DOMAIN = "domain"
    IP = "ip"
    SERVICE = "service"
    PORT = "port"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    TECHNOLOGY = "technology"
    VERSION = "version"
    IDENTITY = "identity"
    ROLE = "role"
    CREDENTIAL_REFERENCE = "credential_reference"
    TRUST_BOUNDARY = "trust_boundary"
    NETWORK_SEGMENT = "network_segment"
    VULNERABILITY_CANDIDATE = "vulnerability_candidate"
    FINDING = "finding"
    HYPOTHESIS = "hypothesis"
    EVIDENCE = "evidence"
    CAPABILITY = "capability"
    SECURITY_CONTROL = "security_control"
    OBSERVATION = "observation"

    @classmethod
    def _unknown_fallback(cls, value: object) -> "NodeType":
        """Map an unrecognized string to OBSERVATION (legacy data migration)."""
        return cls.OBSERVATION


class EdgeType(str, Enum):
    """Typed relationships between graph nodes."""

    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    EXPOSES = "exposes"
    RUNS = "runs"
    DEPENDS_ON = "depends_on"
    REACHABLE_FROM = "reachable_from"
    AUTHENTICATES_TO = "authenticates_to"
    HAS_ROLE = "has_role"
    TRUSTS = "trusts"
    RELATED_TO = "related_to"
    SUPPORTED_BY = "supported_by"
    CONTRADICTED_BY = "contradicted_by"
    DERIVED_FROM = "derived_from"
    AFFECTED_BY = "affected_by"
    PROTECTED_BY = "protected_by"
    CONNECTED_TO = "connected_to"
    SAME_AS = "same_as"
    OBSERVED_ON = "observed_on"


class NodeStatus(str, Enum):
    """Belief state of a finding/hypothesis node."""

    UNKNOWN = "unknown"
    SUSPECTED = "suspected"
    LIKELY = "likely"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    EXHAUSTED = "exhausted"


# ---------------------------------------------------------------------------
# Fallback helpers
# ---------------------------------------------------------------------------

_T = TypeVar("_T", bound=Enum)


def _enum_or_default(value: Any, enum_cls: type[_T], default: _T) -> _T:
    """Coerce ``value`` to ``enum_cls`` or fall back to ``default``."""
    try:
        return enum_cls(value)
    except (ValueError, TypeError):
        return default


def _node_type_or_observation(value: Any) -> NodeType:
    """Coerce a string to NodeType, mapping unknown values to OBSERVATION."""
    try:
        return NodeType(value)
    except (ValueError, TypeError):
        return NodeType._unknown_fallback(str(value))


# ---------------------------------------------------------------------------
# Credential safety
# ---------------------------------------------------------------------------

REDACTED_CRED_VALUE = "***"
"""Placeholder substituted for credential-like values in graph properties."""

_CRED_KEYS = ("credential", "password", "secret", "token", "key")


def redact_properties(props: dict[str, Any]) -> dict[str, Any]:
    """Return a new dict with credential-like values masked; never mutates input."""
    out = dict(props)
    for key, value in props.items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in _CRED_KEYS):
            out[key] = REDACTED_CRED_VALUE
    return out


@dataclass(frozen=True, slots=True)
class CredentialRef:
    """Opaque reference to a credential in protected storage, never a raw value."""

    value_ref: str

    @classmethod
    def from_reference(cls, reference: str) -> "CredentialRef":
        """Extract the credential ref from an ``ev:credential:...`` evidence string."""
        parts = reference.split(":")
        if len(parts) >= 3 and parts[0] == "ev" and parts[1] == "credential":
            return cls(value_ref=parts[2])
        return cls(value_ref=reference)


def make_evidence_ref(
    source_tool: str,
    target: str,
    timestamp: str,
    content_hash: str,
    excerpt: str = "",
    producing_action: str = "",
    confidence: float = 0.5,
) -> str:
    """Normalize an evidence reference: ``ev:{source_tool}:{target}:{hash12}:{timestamp}``.

    ``excerpt``, ``producing_action`` and ``confidence`` are accepted for
    provenance traceability but are not part of the compact reference format.
    """
    digest = content_hash[:12] if content_hash else hashlib.sha256(target.encode()).hexdigest()[:12]
    return f"ev:{source_tool}:{target}:{digest}:{timestamp}"


def _cred_evidence_ref(
    ref: str,
    timestamp: str,
    excerpt: str = "",
    producing_action: str = "",
    confidence: float = 0.95,
) -> str:
    """Build an evidence reference pointing at a protected credential store entry."""
    return make_evidence_ref(
        source_tool="credential",
        target=ref,
        timestamp=timestamp,
        content_hash=hashlib.sha256(ref.encode()).hexdigest(),
        excerpt=excerpt,
        producing_action=producing_action,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GraphNode:
    """A typed entity in the attack graph (host, finding, hypothesis, ...)."""

    node_id: str
    node_type: NodeType
    value: str
    scope: str
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    first_seen: str = ""
    last_seen: str = ""
    evidence_refs: tuple[str, ...] = ()
    observation_count: int = 0
    contradiction_count: int = 0
    status: NodeStatus = NodeStatus.UNKNOWN
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict; credentials inside properties are redacted."""
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "value": self.value,
            "scope": self.scope,
            "properties": redact_properties(self.properties),
            "confidence": self.confidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "evidence_refs": list(self.evidence_refs),
            "observation_count": self.observation_count,
            "contradiction_count": self.contradiction_count,
            "status": self.status.value,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GraphNode":
        """Rebuild a node from a dict, tolerating unknown/missing keys."""
        refs = data.get("evidence_refs") or ()
        if isinstance(refs, str):
            refs = (refs,)
        return cls(
            node_id=str(data.get("node_id", "")),
            node_type=_node_type_or_observation(data.get("node_type")),
            value=str(data.get("value", "")),
            scope=str(data.get("scope", "")),
            properties=dict(data.get("properties") or {}),
            confidence=float(data.get("confidence", 0.5)),
            first_seen=str(data.get("first_seen", "")),
            last_seen=str(data.get("last_seen", "")),
            evidence_refs=tuple(refs),
            observation_count=int(data.get("observation_count", 0)),
            contradiction_count=int(data.get("contradiction_count", 0)),
            status=_enum_or_default(data.get("status"), NodeStatus, NodeStatus.UNKNOWN),
            source=str(data.get("source", "")),
        )


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A typed relationship between two graph nodes."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: EdgeType
    scope: str
    properties: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    source: str = ""
    first_seen: str = ""
    last_seen: str = ""
    evidence_refs: tuple[str, ...] = ()
    observation_count: int = 0
    contradiction_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict; dict inside properties are redacted."""
        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "edge_type": self.edge_type.value,
            "scope": self.scope,
            "properties": redact_properties(self.properties),
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "evidence_refs": list(self.evidence_refs),
            "observation_count": self.observation_count,
            "contradiction_count": self.contradiction_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GraphEdge":
        """Rebuild an edge from a dict, never raising on unknown/missing keys."""
        refs = data.get("evidence_refs") or ()
        if isinstance(refs, str):
            refs = (refs,)
        return cls(
            edge_id=str(data.get("edge_id", "")),
            source_node_id=str(data.get("source_node_id", "")),
            target_node_id=str(data.get("target_node_id", "")),
            edge_type=_enum_or_default(data.get("edge_type"), EdgeType, EdgeType.RELATED_TO),
            scope=str(data.get("scope", "")),
            properties=dict(data.get("properties") or {}),
            confidence=float(data.get("confidence", 0.5)),
            source=str(data.get("source", "")),
            first_seen=str(data.get("first_seen", "")),
            last_seen=str(data.get("last_seen", "")),
            evidence_refs=tuple(refs),
            observation_count=int(data.get("observation_count", 0)),
            contradiction_count=int(data.get("contradiction_count", 0)),
        )


@dataclass(slots=True)
class GraphUpdate:
    """Proposed mutation: nodes/edges to add, attributed to a source agent."""

    node_updates: list[GraphNode] = field(default_factory=list)
    edge_updates: list[GraphEdge] = field(default_factory=list)
    source_agent: str = ""
    timestamp: str = ""
    reason: str = ""
