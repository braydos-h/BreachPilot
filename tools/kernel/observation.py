"""Canonical observation schema (#69).

One typed record for "the agent saw/did X": tool invocations, scanner
output, verifier verdicts, and planner notes all reduce to
:class:`Observation` before they enter prompts, memory, or reports. Raw
tool output stays in artifacts; the observation carries the summary plus a
content hash so consumers can re-fetch the bytes without trusting a
re-statement.

Bridges: :func:`observation_from_trial_dict` lifts the eval/benchmark
telemetry dicts into observations so old and new code share one shape.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "Observation",
    "ToolInvocation",
    "make_observation",
    "observation_from_trial_dict",
]

SCHEMA_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@dataclass(slots=True)
class ToolInvocation:
    """One typed tool call: the auditable half of an observation."""

    tool_name: str = ""
    target: str = ""
    status: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Observation:
    """Canonical runtime observation (schema v1).

    ``source`` names the producer (tool name, ``verifier``, ``planner``);
    ``kind`` is a short category (``tool_result``, ``scan``, ``verdict``,
    ``note``); ``subject`` is the target/entity; ``summary`` is the
    trusted-short-text; ``content_hash`` pins the full bytes in artifacts.
    """

    source: str = ""
    kind: str = ""
    subject: str = ""
    summary: str = ""
    content_hash: str = ""
    schema_version: int = SCHEMA_VERSION
    observation_id: str = ""
    timestamp: str = ""
    invocation: ToolInvocation = field(default_factory=ToolInvocation)

    def __post_init__(self) -> None:
        if not self.observation_id:
            self.observation_id = uuid.uuid4().hex[:12]
        if not self.timestamp:
            self.timestamp = _now_iso()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_observation(
    *,
    source: str,
    kind: str,
    subject: str = "",
    summary: str = "",
    full_content: str = "",
    tool_name: str = "",
    target: str = "",
    status: str = "",
    duration_seconds: float = 0.0,
) -> Observation:
    """Build an observation, hashing the full content when provided."""
    return Observation(
        source=str(source or ""),
        kind=str(kind or ""),
        subject=str(subject or ""),
        summary=str(summary or ""),
        content_hash=_content_hash(full_content) if full_content else "",
        invocation=ToolInvocation(
            tool_name=str(tool_name or source or ""),
            target=str(target or subject or ""),
            status=str(status or ""),
            duration_seconds=float(duration_seconds or 0.0),
        ),
    )


def observation_from_trial_dict(payload: dict[str, Any]) -> Observation:
    """Lift an eval/benchmark telemetry dict into the canonical shape.

    Missing keys degrade to safe defaults so custom runners that return
    only findings never break aggregation.
    """
    if not isinstance(payload, dict):
        payload = {}
    target = str(payload.get("target_id", payload.get("scenario_id", "")) or "")
    summary = str(payload.get("outcome_summary", "") or "")
    return make_observation(
        source="trial",
        kind="trial_result",
        subject=target,
        summary=summary[:500],
        full_content=summary,
        target=target,
        status="verified" if payload.get("verified_success") or payload.get("oracle_verified_success") else "",
    )
