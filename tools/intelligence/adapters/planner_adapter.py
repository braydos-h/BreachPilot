"""PlannerAdapter — task confidence plumbing and the AttackPhase bridge.

Defect C3: ``PlannerAgent._create_task`` never set ``confidence``, so
``TaskQueue.reprioritize`` (``task.get("confidence", 0.0)``) always scored
planner tasks 0. This module maps the planner's 0-100 ``planning_score`` to a
0-1 task confidence and exposes the bidirectional phase bridge between
``tools.attack_planner.AttackPhase`` and
``tools.autonomous_orchestrator.AttackPhase``.
"""

from __future__ import annotations

from typing import Any

from tools.attack_planner import AttackPhase as AttackPlannerPhase
from tools.autonomous_orchestrator import AttackPhase as OrchestratorPhase

_UNSUPPORTED_CONFIDENCE_THRESHOLD = 0.75


def planning_score_to_confidence(score: float) -> float:
    """Map a 0-100 planning score to a clamped 0-1 confidence (round 3)."""
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, min(numeric / 100.0, 1.0)), 3)


class PlannerAdapter:
    """Task-dict confidence helpers and the v2 planning-input seam."""

    @staticmethod
    def task_confidence(task: dict[str, Any]) -> float:
        """Return ``task["confidence"]`` (clamped), or derive it from priority."""
        confidence = task.get("confidence")
        if isinstance(confidence, (int, float)):
            return max(0.0, min(float(confidence), 1.0))
        priority = task.get("priority")
        if isinstance(priority, (int, float)):
            return max(0.0, min(float(priority) / 100.0, 1.0))
        return 0.5

    @staticmethod
    def attach_planning_metadata(
        task: dict[str, Any],
        planning_score: float,
        information_value: float,
    ) -> dict[str, Any]:
        """Stamp confidence + expected_information_value onto a task dict."""
        task["confidence"] = planning_score_to_confidence(planning_score)
        task["expected_information_value"] = information_value
        return task

    @staticmethod
    def unsupported_confidence(
        task: dict[str, Any],
        hypothesis_state: Any,
    ) -> bool:
        """True when a task claims high confidence with zero evidence behind it.

        High confidence (>= 0.75) with no evidence refs and no attempts yet is
        unsupported: the score came from speculation, not investigation.
        """
        if PlannerAdapter.task_confidence(task) < _UNSUPPORTED_CONFIDENCE_THRESHOLD:
            return False
        state: dict[str, Any] = {}
        if isinstance(hypothesis_state, dict):
            state = hypothesis_state
        elif hypothesis_state is not None:
            to_dict = getattr(hypothesis_state, "to_dict", None)
            if callable(to_dict):
                state = to_dict()
        evidence = task.get("evidence_refs") or state.get("evidence_refs") or []
        attempts = task.get(
            "hypothesis_attempt_count",
            task.get("attempt_count", state.get("attempt_count", 0)),
        )
        return not evidence and int(attempts or 0) == 0

    @staticmethod
    def plan_inputs(
        graph_summary: str,
        memory_summary: str,
        open_hypotheses: list[Any],
    ) -> dict[str, Any]:
        """Structured context bundle for the v2 planner seam (future use)."""
        return {
            "graph_summary": graph_summary,
            "memory_summary": memory_summary,
            "open_hypotheses": [
                dict(h) if isinstance(h, dict) else getattr(h, "to_dict", lambda: h)()
                for h in open_hypotheses
            ],
        }


class AttackPhaseBridge:
    """Map between the two incompatible ``AttackPhase`` enums.

    ``tools.attack_planner.AttackPhase`` (attack-plan phases)
        RECON ENUMERATE EXPLOIT ESCALATE LOOT PIVOT DONE
    ``tools.autonomous_orchestrator.AttackPhase`` (campaign phases)
        RECONNAISSANCE ENUMERATION EXPLOITATION PRIVILEGE_ESCALATION
        LATERAL_MOVEMENT PERSISTENCE VALIDATION REPORTING

    Mapping table:
        RECON     -> RECONNAISSANCE
        ENUMERATE -> ENUMERATION
        EXPLOIT   -> EXPLOITATION
        ESCALATE  -> PRIVILEGE_ESCALATION
        LOOT      -> VALIDATION   (no POST_EXPLOIT member exists; looted
                                   credential/data harvesting is closest to
                                   the post-exploitation validation phase)
        PIVOT     -> LATERAL_MOVEMENT
        DONE      -> REPORTING
        PERSISTENCE -> ESCALATE   (orchestrator-only; no persistence member in
                                   the planner — mapped to the post-exploit
                                   escalate phase, so round-trips for
                                   PERSISTENCE are not identity)

    Unknown inputs never raise: both directions return None.
    """

    _TO_ORCHESTRATOR: dict[AttackPlannerPhase, OrchestratorPhase] = {
        AttackPlannerPhase.RECON: OrchestratorPhase.RECONNAISSANCE,
        AttackPlannerPhase.ENUMERATE: OrchestratorPhase.ENUMERATION,
        AttackPlannerPhase.EXPLOIT: OrchestratorPhase.EXPLOITATION,
        AttackPlannerPhase.ESCALATE: OrchestratorPhase.PRIVILEGE_ESCALATION,
        AttackPlannerPhase.LOOT: OrchestratorPhase.VALIDATION,
        AttackPlannerPhase.PIVOT: OrchestratorPhase.LATERAL_MOVEMENT,
        AttackPlannerPhase.DONE: OrchestratorPhase.REPORTING,
    }

    _TO_ATTACK_PLANNER: dict[OrchestratorPhase, AttackPlannerPhase] = {
        OrchestratorPhase.RECONNAISSANCE: AttackPlannerPhase.RECON,
        OrchestratorPhase.ENUMERATION: AttackPlannerPhase.ENUMERATE,
        OrchestratorPhase.EXPLOITATION: AttackPlannerPhase.EXPLOIT,
        OrchestratorPhase.PRIVILEGE_ESCALATION: AttackPlannerPhase.ESCALATE,
        OrchestratorPhase.LATERAL_MOVEMENT: AttackPlannerPhase.PIVOT,
        OrchestratorPhase.PERSISTENCE: AttackPlannerPhase.ESCALATE,
        OrchestratorPhase.VALIDATION: AttackPlannerPhase.LOOT,
        OrchestratorPhase.REPORTING: AttackPlannerPhase.DONE,
    }

    @staticmethod
    def to_orchestrator(phase: Any) -> OrchestratorPhase | None:
        """Map an attack-planner phase (or its value string) to the orchestrator enum."""
        candidate = _coerce(phase, AttackPlannerPhase)
        return AttackPhaseBridge._TO_ORCHESTRATOR.get(candidate) if candidate else None

    @staticmethod
    def to_attack_planner(phase: Any) -> AttackPlannerPhase | None:
        """Map an orchestrator phase (or its value string) to the attack-planner enum."""
        candidate = _coerce(phase, OrchestratorPhase)
        return AttackPhaseBridge._TO_ATTACK_PLANNER.get(candidate) if candidate else None


def _coerce(phase: Any, enum_cls: type) -> Any:
    """Return ``phase`` if it is already a member, its coerced member, or None."""
    if isinstance(phase, enum_cls):
        return phase
    try:
        return enum_cls(str(phase))
    except (ValueError, TypeError):
        return None
