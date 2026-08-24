"""Adversarial tests for the intelligence adapters.

(a) ``unsupported_confidence`` flags high confidence with zero evidence;
(b) ``AttackPhaseBridge`` never raises on unknown input (returns None);
(c) whitespace-only values raise ValueError;
(d) repeated ``add_edge_by_value`` wiring is idempotent (one edge row).
"""

from __future__ import annotations

import pytest

from db import DatabaseManager, _new_id
from outcome_judge import HypothesisState, HypothesisStatus
from target_graph import TargetGraph
from tools.intelligence.adapters import AttackPhaseBridge, PlannerAdapter, TargetGraphV2Adapter


@pytest.fixture
def graph(tmp_path):
    path = tmp_path / "test_adapter_adversarial.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Adapter Adversarial Test", "Map surface", "standard_authorized"),
        )
    return db, mid, TargetGraph(db, mid)


# (a) unsupported_confidence ───────────────────────────────────────────────────


def test_unsupported_confidence_high_confidence_zero_evidence():
    task = {"confidence": 0.9, "hypothesis_attempt_count": 0}
    state = {"evidence_refs": [], "attempt_count": 0}
    assert PlannerAdapter.unsupported_confidence(task, state) is True


def test_unsupported_confidence_accepts_hypothesis_state_dataclass():
    task = {"confidence": 0.9, "hypothesis_attempt_count": 0}
    state = HypothesisState(
        hypothesis_id="H-1",
        mission_id="M-1",
        statement="Host exposes ssh",
        target="10.0.0.1",
        status=HypothesisStatus.OPEN,
    )
    assert PlannerAdapter.unsupported_confidence(task, state) is True


def test_unsupported_confidence_requires_threshold_and_evidence():
    state = {"evidence_refs": [], "attempt_count": 0}
    assert PlannerAdapter.unsupported_confidence({"confidence": 0.7}, state) is False
    assert PlannerAdapter.unsupported_confidence({"confidence": 0.9, "evidence_refs": ["ev:nmap:x"]}, state) is False
    assert PlannerAdapter.unsupported_confidence({"confidence": 0.9, "hypothesis_attempt_count": 2}, state) is False


# (b) AttackPhaseBridge never raises ───────────────────────────────────────────


def test_bridge_never_raises_on_unknown_string_input():
    assert AttackPhaseBridge.to_orchestrator("bogus_phase") is None
    assert AttackPhaseBridge.to_attack_planner("bogus_phase") is None
    assert AttackPhaseBridge.to_orchestrator("") is None
    assert AttackPhaseBridge.to_attack_planner("") is None


def test_bridge_never_raises_on_non_string_input():
    assert AttackPhaseBridge.to_orchestrator(None) is None
    assert AttackPhaseBridge.to_attack_planner(12345) is None
    assert AttackPhaseBridge.to_orchestrator(object()) is None


# (c) whitespace validation ─────────────────────────────────────────────────────


def test_add_edge_by_value_whitespace_value_raises(graph):
    _, _, g = graph
    with pytest.raises(ValueError, match="whitespace"):
        TargetGraphV2Adapter.add_edge_by_value(g, "host", "   ", "service", "ssh", "exposes")
    with pytest.raises(ValueError, match="whitespace"):
        TargetGraphV2Adapter.add_edge_by_value(g, "host", "10.0.0.1", "service", "\t\n", "exposes")


# (d) idempotent wiring ─────────────────────────────────────────────────────────


def test_add_edge_by_value_is_idempotent(graph):
    db, mid, g = graph
    first = TargetGraphV2Adapter.add_edge_by_value(g, "host", "10.0.0.1", "service", "ssh", "exposes")
    second = TargetGraphV2Adapter.add_edge_by_value(g, "host", "10.0.0.1", "service", "ssh", "exposes")
    assert first == second
    with db.connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM graph_edges WHERE mission_id=?", (mid,)).fetchone()[0]
    assert count == 1
