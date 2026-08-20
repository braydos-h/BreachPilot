"""Normalized evidence reference model with deterministic hashing.

The ref_id is a deterministic hash of (source_tool, target, timestamp,
content_hash), so identical content produced by the same source at the same
moment dedups to the same id. This makes evidence ingestion idempotent.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

MAX_EXCERPT_LEN = 500
HIGH_QUALITY_MIN_CONF = 0.8

_WS_RE = re.compile(r"\s+")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


class EvidenceSource(str, Enum):
    """Where an evidence artifact originated."""

    TOOL_OUTPUT = "tool_output"
    BANNER = "banner"
    SCANNER = "scanner"
    NVD_CVE = "nvd_cve"
    EXPLOIT_DB = "exploit_db"
    MANUAL = "manual"
    AGENT_OBSERVATION = "agent_observation"
    HTTP_RESPONSE = "http_response"
    FILE_ARTIFACT = "file_artifact"
    SCREENSHOT = "screenshot"
    NOTE = "note"
    TARGET_SIDE_ORACLE = "target_side_oracle"


class EvidenceLevel(str, Enum):
    """How far the artifact is from raw tool output."""

    RAW = "raw"
    DERIVED = "derived"
    SUMMARIZED = "summarized"


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """A normalized, provenance-tracked piece of evidence.

    ``content`` holds the raw artifact or a path to it; if a path, callers
    must resolve it before use. ``relevant_excerpt`` is always normalized
    (single line, no control chars) via :meth:`normalize`.
    """

    ref_id: str
    source_tool: str
    target: str
    timestamp: str
    content_hash: str
    relevant_excerpt: str = ""
    structured_fields: dict[str, Any] = field(default_factory=dict)
    producing_action: str = ""
    parent_evidence: str = ""
    agent_interpretation: str = ""
    confidence: float = 0.5
    content: str = ""

    @classmethod
    def create(
        cls,
        source_tool: str,
        target: str,
        timestamp: str,
        content: str,
        producing_action: str = "",
        relevant_excerpt: str = "",
        structured_fields: dict[str, Any] | None = None,
        parent_evidence: str = "",
        agent_interpretation: str = "",
        confidence: float = 0.5,
    ) -> "EvidenceReference":
        """Build a reference with a deterministic ref_id.

        Identical (source_tool, target, timestamp, content) inputs produce the
        same ref_id — idempotent evidence dedup by design.
        """
        content_hash = cls.hash_content(content)
        ref_id = cls._make_ref_id(source_tool, target, timestamp, content_hash)
        return cls(
            ref_id=ref_id,
            source_tool=source_tool,
            target=target,
            timestamp=timestamp,
            content_hash=content_hash,
            relevant_excerpt=cls.normalize(relevant_excerpt),
            structured_fields=dict(structured_fields or {}),
            producing_action=producing_action,
            parent_evidence=parent_evidence,
            agent_interpretation=agent_interpretation,
            confidence=confidence,
            content=content,
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EvidenceReference":
        """Build a reference from a dict, tolerating missing keys."""
        return cls(
            ref_id=d.get("ref_id", ""),
            source_tool=d.get("source_tool", ""),
            target=d.get("target", ""),
            timestamp=d.get("timestamp", ""),
            content_hash=d.get("content_hash", ""),
            relevant_excerpt=d.get("relevant_excerpt", ""),
            structured_fields=dict(d.get("structured_fields") or {}),
            producing_action=d.get("producing_action", ""),
            parent_evidence=d.get("parent_evidence", ""),
            agent_interpretation=d.get("agent_interpretation", ""),
            confidence=float(d.get("confidence", 0.5)),
            content=d.get("content", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "ref_id": self.ref_id,
            "source_tool": self.source_tool,
            "target": self.target,
            "timestamp": self.timestamp,
            "content_hash": self.content_hash,
            "relevant_excerpt": self.relevant_excerpt,
            "structured_fields": dict(self.structured_fields),
            "producing_action": self.producing_action,
            "parent_evidence": self.parent_evidence,
            "agent_interpretation": self.agent_interpretation,
            "confidence": self.confidence,
            "content": self.content,
        }

    @staticmethod
    def hash_content(content: str) -> str:
        """sha256 hex digest of the raw content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def normalize(excerpt: str) -> str:
        """Collapse whitespace, strip control chars, trim to MAX_EXCERPT_LEN."""
        cleaned = _CTRL_RE.sub(" ", excerpt)
        cleaned = _WS_RE.sub(" ", cleaned).strip()
        return cleaned[:MAX_EXCERPT_LEN]

    @staticmethod
    def _make_ref_id(source_tool: str, target: str, timestamp: str, content_hash: str) -> str:
        seed = f"{source_tool}|{target}|{timestamp}|{content_hash}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]

    def __str__(self) -> str:
        """Canonical ref id."""
        return self.ref_id
