"""Tests for ``PlannerAdapter`` + the planner confidence fix (defect C3).

Covers confidence defaults/derivation, metadata attachment, score mapping,
``_create_task`` confidence wiring, and the bidirectional ``AttackPhaseBridge``.
"""

from __future__ import annotations

from planner import PlannerAgent
from tools.attack_planner import AttackPhase as AttackPlannerPhase
from tools.autonomous_orchestrator import AttackPhase as OrchestratorPhase
from tools.intelligence.adapters import (
    AttackPhaseBridge,
    PlannerAdapter,
    planning_score_to_confidence,
)

# ── PlannerAdapter ────────────────────────────────────────────────────────────


def test_task_confidence_returns_0_5_default_when_absent():
    assert PlannerAdapter.task_confidence({}) == 0.5
    assert PlannerAdapter.task_confidence({"priority": 50}) == 0.5


def test_task_confidence_uses_explicit_confidence():
    assert PlannerAdapter.task_confidence({"confidence": 0.9}) == 0.9
    assert PlannerAdapter.task_confidence({"confidence": 1.5}) == 1.0


def test_task_confidence_derives_from_priority():
    assert PlannerAdapter.task_confidence({"priority": 30}) == 0.3


def test_attach_planning_metadata_sets_confidence_and_information_value():
    task = {"objective": "check"}
    result = PlannerAdapter.attach_planning_metadata(task, 82, 0.7)
    assert result is task
    assert task["confidence"] == 0.82
    assert task["expected_information_value"] == 0.7


def test_planning_score_to_confidence_mapping():
    assert planning_score_to_confidence(100) == 1.0
    assert planning_score_to_confidence(50) == 0.5
    assert planning_score_to_confidence(0) == 0.0
    assert planning_score_to_confidence(150) == 1.0
    assert planning_score_to_confidence(-5) == 0.0
    assert planning_score_to_confidence("nope") == 0.0


def test_create_task_with_planning_score_sets_confidence():
    planner = PlannerAgent(risk_profile="low_noise_non_destructive")
    task = planner._create_task(
        phase="analysis",
        target="10.0.0.1",
        asset_type="finding",
        objective="Run an independent check",
        hypothesis="Host exposes ssh",
        allowed_tools=["nmap_service_scan"],
        planning_score=73,
    )
    assert task["confidence"] == 0.73


def test_create_task_without_planning_score_omits_confidence():
    planner = PlannerAgent(risk_profile="low_noise_non_destructive")
    task = planner._create_task(
        phase="recon",
        target="10.0.0.1",
        asset_type="host",
        objective="Confirm scope",
        hypothesis="Scope is correct",
        allowed_tools=["check_scope"],
    )
    assert "confidence" not in task
    assert "expected_information_value" not in task


# ── AttackPhaseBridge ─────────────────────────────────────────────────────────


def test_bridge_maps_every_attack_planner_member():
    for phase in AttackPlannerPhase:
        mapped = AttackPhaseBridge.to_orchestrator(phase)
        assert mapped is not None and isinstance(mapped, OrchestratorPhase)


def test_bridge_maps_every_orchestrator_member():
    for phase in OrchestratorPhase:
        mapped = AttackPhaseBridge.to_attack_planner(phase)
        assert mapped is not None and isinstance(mapped, AttackPlannerPhase)


def test_bridge_accepts_value_strings():
    assert AttackPhaseBridge.to_orchestrator("recon") == OrchestratorPhase.RECONNAISSANCE
    assert AttackPhaseBridge.to_attack_planner("lateral") == AttackPlannerPhase.PIVOT


def test_bridge_round_trip_identity_for_attack_planner_members():
    for phase in AttackPlannerPhase:
        assert AttackPhaseBridge.to_attack_planner(AttackPhaseBridge.to_orchestrator(phase)) == phase


def test_bridge_specific_mappings():
    assert AttackPhaseBridge.to_orchestrator(AttackPlannerPhase.RECON) == OrchestratorPhase.RECONNAISSANCE
    assert AttackPhaseBridge.to_orchestrator(AttackPlannerPhase.ENUMERATE) == OrchestratorPhase.ENUMERATION
    assert AttackPhaseBridge.to_orchestrator(AttackPlannerPhase.EXPLOIT) == OrchestratorPhase.EXPLOITATION
    assert AttackPhaseBridge.to_orchestrator(AttackPlannerPhase.ESCALATE) == OrchestratorPhase.PRIVILEGE_ESCALATION
    assert AttackPhaseBridge.to_orchestrator(AttackPlannerPhase.PIVOT) == OrchestratorPhase.LATERAL_MOVEMENT
    assert AttackPhaseBridge.to_orchestrator(AttackPlannerPhase.DONE) == OrchestratorPhase.REPORTING
    assert AttackPhaseBridge.to_attack_planner(OrchestratorPhase.PERSISTENCE) == AttackPlannerPhase.ESCALATE
