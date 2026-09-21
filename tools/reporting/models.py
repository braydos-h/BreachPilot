"""Report data models + the HITL final-report filter (split out of ``tools.enhanced_reporting``).

The filter (:func:`approved_findings` / :func:`apply_hitl_filter`) gates on
the canonical lifecycle state
(:func:`tools.kernel.finding_lifecycle.current_state`), never on raw status
keys. Re-exported through :mod:`tools.enhanced_reporting` so existing
imports keep working.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from tools.reporting.cvss import CVSSScore

__all__ = [
    "AttackTimelineEntry",
    "ExploitationChain",
    "FailureAnalysis",
    "TechnicalFinding",
    "_confidence_from_verdict",
    "_resolve_verdict",
    "approved_findings",
    "apply_hitl_filter",
]


@dataclass
class AttackTimelineEntry:
    timestamp: str
    event_type: str
    description: str
    target: str = ""
    module: str = ""
    result: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "target": self.target,
            "module": self.module,
            "result": self.result,
            "metadata": self.metadata,
        }


@dataclass
class ExploitationChain:
    chain_id: str
    target: str
    entries: list[dict[str, Any]] = field(default_factory=list)
    successful: bool = False
    final_privilege: str = "none"
    total_duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "target": self.target,
            "entries": self.entries,
            "successful": self.successful,
            "final_privilege": self.final_privilege,
            "total_duration": self.total_duration,
        }


@dataclass
class FailureAnalysis:
    operation: str
    failure_count: int
    primary_error: str
    error_breakdown: dict[str, int] = field(default_factory=dict)
    mitigation_suggestion: str = ""
    recovery_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "failure_count": self.failure_count,
            "primary_error": self.primary_error,
            "error_breakdown": self.error_breakdown,
            "mitigation_suggestion": self.mitigation_suggestion,
            "recovery_actions": self.recovery_actions,
        }


@dataclass
class TechnicalFinding:
    finding_id: str
    title: str
    affected_asset: str
    vuln_class: str
    severity: str
    cvss: CVSSScore
    confidence: float
    summary: str
    reproduction_steps: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    exploitation_result: str = ""
    persistence_achieved: bool = False
    privilege_level_gained: str = ""
    attack_chain: ExploitationChain | None = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    # Closed-loop retest ("prove the fix"): the stored verification probe
    # re-executes ONLY the original PoC command; retest_status is one of
    # "" (never retested) | STILL_OPEN | FIXED | INCONCLUSIVE.
    verification_probe: dict[str, Any] = field(default_factory=dict)
    retest_status: str = ""
    retest_history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "affected_asset": self.affected_asset,
            "vuln_class": self.vuln_class,
            "severity": self.severity,
            "cvss": self.cvss.to_dict(),
            "confidence": self.confidence,
            "summary": self.summary,
            "reproduction_steps": self.reproduction_steps,
            "evidence_refs": self.evidence_refs,
            "exploitation_result": self.exploitation_result,
            "persistence_achieved": self.persistence_achieved,
            "privilege_level_gained": self.privilege_level_gained,
            "attack_chain": self.attack_chain.to_dict() if self.attack_chain else None,
            "remediation": self.remediation,
            "references": self.references,
            "verification_probe": self.verification_probe,
            "retest_status": self.retest_status,
            "retest_history": self.retest_history,
        }


def approved_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only reportable findings (the HITL final-report filter).

    Gated on the canonical lifecycle state (:func:`current_state`), not raw
    status keys: only ``APPROVED`` / ``VERIFIED`` / ``STILL_OPEN`` surface.
    ``PROPOSED`` / ``HOLDING`` / ``INCONCLUSIVE`` candidates stay hidden until
    decided/proved, and terminal ``REJECTED`` / ``FIXED`` never surface (a
    rejected candidate or a closed hole is not a finding). Never raises: a
    non-list input yields ``[]`` and non-dict rows are skipped.
    """
    from tools.kernel.finding_lifecycle import APPROVED as _L_APPROVED
    from tools.kernel.finding_lifecycle import STILL_OPEN as _L_STILL_OPEN
    from tools.kernel.finding_lifecycle import VERIFIED as _L_VERIFIED
    from tools.kernel.finding_lifecycle import current_state as _lifecycle_state

    if not isinstance(findings, list):
        return []
    return [
        item
        for item in findings
        if isinstance(item, dict) and _lifecycle_state(item) in (_L_APPROVED, _L_VERIFIED, _L_STILL_OPEN)
    ]


def apply_hitl_filter(report_data: dict[str, Any]) -> int:
    """Filter ``report_data["technical_findings"]`` to APPROVED-only, in place.

    The single chokepoint every render path funnels through: ``generate_full_report``
    (JSON write), ``_generate_markdown`` / ``_generate_html`` (md/html writes AND
    the hitl/verify/retest sibling-refresh path, which calls the renderers
    directly). Returns the pending count (filtered-out items) and stashes it as
    ``report_metadata["hitl_pending_count"]`` for JSON consumers. Content-wise
    idempotent (re-filtering keeps the same list); the RETURNED count is only
    fresh on the first pass over unfiltered data — callers that filter and then
    render the same dict must thread the count explicitly (see the
    ``pending_count`` params) instead of relying on a second call.
    Fail-open: non-dict input or missing/non-list findings yield 0, never raise.
    """
    try:
        if not isinstance(report_data, dict):
            return 0
        findings = report_data.get("technical_findings", [])
        if not isinstance(findings, list):
            report_data["technical_findings"] = []
            return 0
        kept = approved_findings(findings)
        pending = len(findings) - len(kept)
        report_data["technical_findings"] = kept
        meta = report_data.get("report_metadata")
        if isinstance(meta, dict):
            meta["hitl_pending_count"] = pending
        return pending
    except Exception:  # noqa: BLE001 -- report filter must never break rendering
        return 0


def _confidence_from_verdict(verdict: str | None) -> float:
    """Map an OutcomeJudge verdict to a finding confidence value."""
    if verdict == "confirmed":
        return 0.95
    if verdict == "refuted":
        return 0.2
    if verdict in ("inconclusive", "exhausted", "open"):
        return 0.5
    return 0.5


def _resolve_verdict(
    assessments: Mapping[str, Any] | None,
    target: str,
) -> str | None:
    """Resolve a hypothesis verdict for a target from an assessments mapping.

    Accepts either an ``OutcomeAssessment`` (duck-typed via
    ``hypothesis_status``) or a dict carrying ``hypothesis_status`` (enum or
    string). Returns the lowercased status string (e.g. ``"confirmed"``) or
    ``None`` when no assessment is present for the target.
    """
    if not assessments:
        return None
    entry = assessments.get(target)
    if entry is None:
        return None
    status = getattr(entry, "hypothesis_status", None)
    if status is None and isinstance(entry, Mapping):
        status = entry.get("hypothesis_status")
    if status is None:
        return None
    # Enum members expose ``.value``; bare strings do not.
    value = getattr(status, "value", status)
    return str(value).strip().lower() if value else None
