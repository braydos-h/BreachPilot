"""Canonical finding/evidence/retest lifecycle (#04).

One state machine for every finding, enforced in storage, APIs, UI,
reports, and integrations:

    PROPOSED --human Approve--> APPROVED --oracle VERIFIED--> VERIFIED
         \\--human Reject--> REJECTED        \\--oracle HOLDING--> HOLDING (candidate)
              \\--oracle VERIFIED/HOLDING/INCONCLUSIVE--> (same, via stored probe)

Invariants (the LLM may propose or explain, never promote):

- Agents create PROPOSED only (hitl propose_finding).
- Only ``actor="human"`` transitions PROPOSED -> APPROVED/REJECTED.
- Only an independent oracle/verifier transitions -> VERIFIED/HOLDING/
  INCONCLUSIVE, from PROPOSED (stored probe) or APPROVED.
- Only a retest probe transitions VERIFIED -> STILL_OPEN/FIXED.
- Terminal states (REJECTED, FIXED) accept no further transitions.

:func:`allowed_transitions` and :func:`check_transition` are the single
enforcement point; all surfaces must consult them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "LIFECYCLE_VERSION",
    "PROPOSED",
    "APPROVED",
    "REJECTED",
    "HOLDING",
    "INCONCLUSIVE",
    "VERIFIED",
    "STILL_OPEN",
    "FIXED",
    "FindingTransition",
    "allowed_transitions",
    "check_transition",
]

LIFECYCLE_VERSION = 1

PROPOSED = "PROPOSED"
APPROVED = "APPROVED"
REJECTED = "REJECTED"
HOLDING = "HOLDING"
INCONCLUSIVE = "INCONCLUSIVE"
VERIFIED = "VERIFIED"
STILL_OPEN = "STILL_OPEN"
FIXED = "FIXED"

#: State -> {next_state: authorized actor}. Actors: agent, human, oracle, retest.
_TRANSITIONS: dict[str, dict[str, str]] = {
    PROPOSED: {
        APPROVED: "human",
        REJECTED: "human",
        VERIFIED: "oracle",
        HOLDING: "oracle",
        INCONCLUSIVE: "oracle",
    },
    APPROVED: {VERIFIED: "oracle", HOLDING: "oracle", INCONCLUSIVE: "oracle", REJECTED: "human"},
    HOLDING: {VERIFIED: "oracle", INCONCLUSIVE: "oracle", REJECTED: "human"},
    INCONCLUSIVE: {VERIFIED: "oracle", HOLDING: "oracle", REJECTED: "human"},
    VERIFIED: {STILL_OPEN: "retest", FIXED: "retest"},
    STILL_OPEN: {FIXED: "retest"},
    REJECTED: {},
    FIXED: {},
}


@dataclass(frozen=True)
class FindingTransition:
    """One validated lifecycle step."""

    from_state: str
    to_state: str
    actor: str

    def to_dict(self) -> dict[str, Any]:
        return {"from": self.from_state, "to": self.to_state, "actor": self.actor}


def allowed_transitions(state: str) -> dict[str, str]:
    """Authorized {next_state: actor} for a finding state (unknown -> {})."""
    return dict(_TRANSITIONS.get(str(state or ""), {}))


def check_transition(from_state: str, to_state: str, actor: str) -> FindingTransition:
    """Validate one lifecycle step; raise ValueError on any violation.

    Covers: unknown states, illegal edges, and wrong actors — including an
    agent attempting to self-approve or self-verify.
    """
    options = _TRANSITIONS.get(str(from_state or ""))
    if options is None:
        raise ValueError(f"unknown finding state {from_state!r}")
    want = options.get(str(to_state or ""))
    if want is None:
        raise ValueError(f"illegal finding transition {from_state!r} -> {to_state!r}")
    if want != str(actor or ""):
        raise ValueError(f"finding transition {from_state!r} -> {to_state!r} requires actor {want!r}, got {actor!r}")
    return FindingTransition(from_state=str(from_state), to_state=str(to_state), actor=str(actor))
