"""Single three-state scope verdict for Flow A (P1 scope-approval-enum).

The frozen ``scope_gate.ScopeCheckResult`` expresses its decision as two bools
(``allowed`` + ``requires_human_approval``), which lets a caller check the
first value and drop the second — silently converting approval-gated work
into allowed work (this exact misuse existed in ``AttackModuleExecutor``).

Flow A callers route through :class:`ScopeVerdict` instead: :func:`verdict_for`
normalizes any gate result (frozen shape or test double) into exactly one of
DENY / ALLOW / REQUIRES_APPROVAL, so every call site must handle all three
outcomes. :class:`LabAutoApprovalPolicy` centralizes the lab posture mapping
(REQUIRES_APPROVAL → auditable auto-approval at one chokepoint).

The frozen ``scope_gate.py`` is untouched (CONTRIBUTING §5.2); this module
only *reads* its result shape.
"""

from __future__ import annotations

import enum
from typing import Any, Callable


class ScopeVerdict(str, enum.Enum):
    """The single scope decision every Flow A call site must handle."""

    DENY = "deny"
    ALLOW = "allow"
    REQUIRES_APPROVAL = "requires_approval"


def verdict_for(result: Any) -> ScopeVerdict:
    """Normalize a scope-check result to a single :class:`ScopeVerdict`.

    Accepts the frozen ``ScopeCheckResult`` (``allowed`` /
    ``requires_human_approval`` attrs) and duck-typed test doubles
    (``MagicMock(allowed=..., requires_human_approval=...)`` included).
    Order matters: denial always wins over the approval flag.

    Only an *explicitly configured* approval flag counts: ``unittest.mock``
    auto-attrs (a double that sets ``allowed`` but never mentions the flag)
    read as unset, preserving the prior allowed-only behavior for those
    doubles instead of newly blocking them.
    """
    allowed = bool(getattr(result, "allowed", False))
    if not allowed:
        return ScopeVerdict.DENY
    if _approval_requested(result):
        return ScopeVerdict.REQUIRES_APPROVAL
    return ScopeVerdict.ALLOW


def _approval_requested(result: Any) -> bool:
    """True iff the result explicitly requests human approval."""
    flag = getattr(result, "requires_human_approval", False)
    if isinstance(flag, bool):
        return flag
    if type(flag).__module__.split(".")[0] == "unittest":
        # Auto-created mock attr, never explicitly configured -> unset.
        return False
    return bool(flag)


class LabAutoApprovalPolicy:
    """Centralize the lab auto-approval mapping at one chokepoint.

    Under the ``high_authorized_testing`` risk profile, REQUIRES_APPROVAL is
    the lab's documented auto-approve posture — but it must be an *explicit,
    recorded* decision, never a silent fallthrough. Every auto-approval goes
    through :meth:`decide`, which invokes ``record`` (default: no-op) with a
    human-readable detail so the decision is auditable, then returns True.
    Under any other profile it returns False (caller must block / ask).
    """

    LAB_PROFILE = "high_authorized_testing"

    def __init__(
        self,
        risk_profile: str = "",
        record: Callable[[str], None] | None = None,
    ) -> None:
        self._risk_profile = str(risk_profile or "")
        self._record = record or (lambda _detail: None)

    @property
    def risk_profile(self) -> str:
        return self._risk_profile

    def decide(self, result: Any, *, context: str = "") -> bool:
        """Return True iff a REQUIRES_APPROVAL result may proceed.

        ALLOW → True (no record needed). DENY → False. REQUIRES_APPROVAL →
        True + auditable record, but only under the lab profile; False
        otherwise.
        """
        verdict = verdict_for(result)
        if verdict is ScopeVerdict.ALLOW:
            return True
        if verdict is ScopeVerdict.DENY:
            return False
        if self._risk_profile != self.LAB_PROFILE:
            return False
        reason = str(getattr(result, "reason", "") or "")
        detail = (
            f"lab auto-approval of REQUIRES_APPROVAL ({reason})" if reason else "lab auto-approval of REQUIRES_APPROVAL"
        )
        if context:
            detail = f"{context}: {detail}"
        self._record(detail)
        return True
