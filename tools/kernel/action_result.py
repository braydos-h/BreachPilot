"""Canonical ActionResult / finding / evidence contract (TODO 006).

One action contract, one outcome contract, one event vocabulary.

- Operational status (did the call complete?) is distinct from exploit
  outcome (did the action achieve compromise?) which is distinct from
  evidential status (is the finding independently proven?).
- ``tool exited 0 != exploit worked != finding evidenced`` (§3 separation).
- Exploit agent, SwarmOrchestrator, campaign executor, and Flow B adapters
  all emit :class:`CanonicalActionResult`. UI/telemetry consume one vocabulary.

Canonical re-export: :class:`ActionResult` from
``tools.exploit_agent.outcome_truth`` remains the exploit-agent normalized
record; this module wraps it with scope + evidential + provenance fields so
every layer maps success/failure identically.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from tools.exploit_agent.outcome_truth import ActionResult, ExploitOutcome, OperationalStatus
from tools.kernel.finding_lifecycle import HOLDING, INCONCLUSIVE, PROPOSED, VERIFIED
from tools.scope_verdict import ScopeVerdict

__all__ = [
    "ActionResult",
    "OperationalStatus",
    "ExploitOutcome",
    "EvidentialStatus",
    "CanonicalActionResult",
    "action_from_exploit_result",
    "action_from_swarm_result",
    "action_from_campaign_result",
    "action_from_flowb_finding",
]


class EvidentialStatus:
    """Independent verification verdict (oracle/probe), never inferred from chat."""

    VERIFIED = VERIFIED
    HOLDING = HOLDING
    INCONCLUSIVE = INCONCLUSIVE
    # REFUTED is a FlowB-mapping legacy ("hypothesis refuted"), NOT a canonical
    # lifecycle state — it never enters check_transition and must never be
    # stamped as a finding status. Swarm/campaign cap at HOLDING; only the
    # oracle path sets VERIFIED.
    REFUTED = "REFUTED"
    PROPOSED = PROPOSED


@dataclass
class CanonicalActionResult:
    """Single canonical outcome record for all orchestration layers."""

    action_id: str = ""
    tool_name: str = ""
    operational_status: str = OperationalStatus.COMPLETED
    exploit_outcome: str = ExploitOutcome.NONE
    evidential_status: str = EvidentialStatus.INCONCLUSIVE
    scope_verdict: str = ScopeVerdict.ALLOW.value
    evidence_refs: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    hypothesis_id: str = ""
    run_id: str = ""
    detail: str = ""
    retryable: bool = False

    @property
    def operational_success(self) -> bool:
        return self.operational_status == OperationalStatus.COMPLETED

    @property
    def verified_success(self) -> bool:
        return self.evidential_status == EvidentialStatus.VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def action_from_exploit_result(result: ActionResult, *, run_id: str = "", action_id: str = "") -> CanonicalActionResult:
    """Exploit-agent normalized result -> canonical (evidential stays INCONCLUSIVE until oracle)."""
    evidential = EvidentialStatus.INCONCLUSIVE
    # Strong machine proof promotes to HOLDING candidate; only oracle -> VERIFIED.
    if result.verified_success:
        evidential = EvidentialStatus.HOLDING
    return CanonicalActionResult(
        action_id=action_id,
        tool_name=result.tool_name,
        operational_status=result.operational_status,
        exploit_outcome=result.exploit_outcome,
        evidential_status=evidential,
        scope_verdict=ScopeVerdict.ALLOW.value,
        evidence_refs=list(result.evidence),
        run_id=run_id,
        detail=f"exit={result.exit_code} error={result.is_error}",
        retryable=result.retryable,
    )


def action_from_swarm_result(agent_result: Any, *, run_id: str = "") -> CanonicalActionResult:
    """Swarm AgentResult -> canonical. Swarm success without probe stays HOLDING at best."""
    status = str(getattr(agent_result, "status", "") or "")
    # AgentStatus.COMPLETE value is "complete".
    operational = OperationalStatus.COMPLETED if status == "complete" else OperationalStatus.FAILED
    output = getattr(agent_result, "output", {}) or {}
    findings = getattr(agent_result, "findings", []) or []
    evidence_refs = list(getattr(agent_result, "evidence_refs", []) or [])
    # Swarm never self-grades to VERIFIED; verified_success requires oracle.
    exploit_outcome = ExploitOutcome.NONE
    if isinstance(output, dict):
        if output.get("access_achieved") is True:
            exploit_outcome = ExploitOutcome.COMPROMISE
        elif output.get("verified") is True:
            exploit_outcome = ExploitOutcome.COMPROMISE
    evidential = (
        EvidentialStatus.HOLDING if exploit_outcome == ExploitOutcome.COMPROMISE else EvidentialStatus.INCONCLUSIVE
    )
    return CanonicalActionResult(
        action_id=str(getattr(agent_result, "task_id", "") or ""),
        tool_name=f"swarm:{getattr(agent_result, 'agent_type', '')}",
        operational_status=operational,
        exploit_outcome=exploit_outcome,
        evidential_status=evidential,
        scope_verdict=ScopeVerdict.ALLOW.value,
        evidence_refs=evidence_refs,
        finding_ids=[str(f.get("id", "")) for f in findings if isinstance(f, dict) and f.get("id")],
        run_id=run_id,
        detail=str(getattr(agent_result, "error", "") or ""),
    )


def action_from_campaign_result(task: dict[str, Any], *, run_id: str = "") -> CanonicalActionResult:
    """Campaign task dict (with result.status) -> canonical."""
    result = task.get("result", {}) if isinstance(task, dict) else {}
    status = str(result.get("status", "") if isinstance(result, dict) else "")
    operational = OperationalStatus.COMPLETED if status in ("success", "exploited") else OperationalStatus.FAILED
    if status in ("blocked", "denied", "scope_denied"):
        operational = OperationalStatus.BLOCKED
    exploit_outcome = ExploitOutcome.COMPROMISE if status == "exploited" else ExploitOutcome.NONE
    if status == "success" and isinstance(result, dict) and result.get("access_achieved"):
        exploit_outcome = ExploitOutcome.COMPROMISE
    evidential = (
        EvidentialStatus.HOLDING if exploit_outcome == ExploitOutcome.COMPROMISE else EvidentialStatus.INCONCLUSIVE
    )
    scope = ScopeVerdict.ALLOW.value
    if isinstance(result, dict) and result.get("scope_denied"):
        scope = ScopeVerdict.DENY.value
    elif isinstance(result, dict) and result.get("approval_required"):
        scope = ScopeVerdict.REQUIRES_APPROVAL.value
    return CanonicalActionResult(
        action_id=str(task.get("task_id", "") or task.get("id", "") or ""),
        tool_name=f"campaign:{task.get('phase', '')}",
        operational_status=operational,
        exploit_outcome=exploit_outcome,
        evidential_status=evidential,
        scope_verdict=scope,
        evidence_refs=list(result.get("evidence_refs", []) if isinstance(result, dict) else []),
        run_id=run_id,
        detail=status,
    )


def action_from_flowb_finding(row: dict[str, Any], *, run_id: str = "") -> CanonicalActionResult:
    """Flow B finding/outcome row -> canonical adapter (execution retired, model preserved)."""
    status = str(row.get("status", "") or row.get("verdict", "") or "").upper()
    mapping = {
        "CONFIRMED": EvidentialStatus.VERIFIED,
        "VERIFIED": EvidentialStatus.VERIFIED,
        "REFUTED": EvidentialStatus.REFUTED,
        "INCONCLUSIVE": EvidentialStatus.INCONCLUSIVE,
        "EXHAUSTED": EvidentialStatus.INCONCLUSIVE,
        "OPEN": EvidentialStatus.PROPOSED,
    }
    evidential = mapping.get(status, EvidentialStatus.INCONCLUSIVE)
    return CanonicalActionResult(
        action_id=str(row.get("id", "") or row.get("finding_id", "") or ""),
        tool_name="flowb:adapter",
        operational_status=OperationalStatus.COMPLETED,
        exploit_outcome=ExploitOutcome.NONE,
        evidential_status=evidential,
        scope_verdict=ScopeVerdict.ALLOW.value,
        evidence_refs=list(row.get("evidence_refs", []) or []),
        finding_ids=[str(row.get("id", ""))] if row.get("id") else [],
        hypothesis_id=str(row.get("hypothesis_id", "") or ""),
        run_id=run_id,
        detail=status,
    )
