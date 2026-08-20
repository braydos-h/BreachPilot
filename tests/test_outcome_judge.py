"""Evidence-grounded hypothesis judgment and persistence tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from db import DatabaseManager, _new_id, _SCHEMA_VERSION
from executor import ExecutionResult
from observer import Observation
from outcome_judge import (
    DuplicateInvestigationError,
    HypothesisRepository,
    HypothesisStatus,
    OutcomeJudge,
)
from planner import PlannerAgent
from task_queue import TaskQueue
from tools.experience_store import ExperienceStore


def _database(path: Path) -> tuple[DatabaseManager, str]:
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mission_id = _new_id("M")
        conn.execute(
            """INSERT INTO missions(
                id, program_name, objective, risk_profile, created_at, updated_at)
               VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mission_id, "Outcome Test", "Test judgments.", "standard_authorized"),
        )
    return db, mission_id


def _task(tool: str = "check_a") -> dict:
    return {
        "task_id": _new_id("T"),
        "phase": "analysis",
        "target": "example.test",
        "objective": "Determine whether port 443 is open.",
        "hypothesis": "Port 443 is open on example.test.",
        "allowed_tools": [tool],
        "success_criteria": [
            {"field": "facts", "operator": "contains", "value": "Port 443/tcp open"}
        ],
        "stop_conditions": [
            {"field": "facts", "operator": "contains", "value": "Host unreachable"}
        ],
    }


def _execution(*, success: bool, evidence: list[str] | None = None, error: str = ""):
    return ExecutionResult(
        task_id="T",
        success=success,
        output_summary="tool output",
        evidence_refs=evidence or [],
        tool_name="check",
        target="example.test",
        error=error,
        scope_gate_passed=True,
        risk_gate_passed=True,
    )


def test_command_success_without_criteria_is_inconclusive_and_not_learned(tmp_path):
    judge = OutcomeJudge()
    assessment = judge.judge(
        _task(),
        _execution(success=True, evidence=["E-1"]),
        Observation(facts=["Port 80/tcp open"], evidence_refs=["E-1"]),
    )

    assert assessment.execution_outcome.value == "succeeded"
    assert assessment.hypothesis_status is HypothesisStatus.INCONCLUSIVE
    assert assessment.evidential_outcome is None
    assert assessment.another_investigation_justified is True

    db, _ = _database(tmp_path / "learning.db")
    store = ExperienceStore(db, min_samples=1, time_decay_days=0)
    recorded = store.record_evidential_outcome(
        "example.test",
        "analysis:check",
        assessment.hypothesis_status.value,
        confidence=assessment.confidence,
        evidence_refs=assessment.evidence_refs,
    )
    assert recorded is None
    with db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM lessons").fetchone()[0] == 0


def test_command_failure_does_not_refute_hypothesis():
    assessment = OutcomeJudge().judge(
        _task(),
        _execution(success=False, evidence=["E-ERR"], error="connection timeout"),
        Observation(dead_ends=["check timed out"], evidence_refs=["E-ERR"]),
    )

    assert assessment.execution_outcome.value == "failed"
    assert assessment.hypothesis_status is HypothesisStatus.INCONCLUSIVE
    assert "does not refute" in assessment.reasoning


def test_agent_loop_keeps_execution_and_hypothesis_status_separate(tmp_path):
    from agent_loop import AgentLoop

    config = {
        "program_name": "Loop Outcome",
        "risk_profile": "low_noise_non_destructive",
        "allowed_assets": ["127.0.0.1"],
        "testing_modes": ["recon"],
        "use_swarm": False,
        "memory": {
            "semantic_enabled": False,
            "experience_min_samples": 1,
            "experience_time_decay_days": 0,
        },
    }
    loop = AgentLoop(
        config,
        tmp_path / "loop",
        lambda _tool, _args: "80/tcp open  http nginx 1.24",
    )
    events = []
    loop._event_callback = lambda event_type, data: events.append((event_type, data))
    task = _task("nmap_basic")
    task["task_id"] = "T-LOOP"
    task["target"] = "127.0.0.1"
    loop._queue.create_task(task)

    loop.run(max_cycles=1)

    persisted_task = loop._queue.get_task("T-LOOP")
    assessment = loop._hypotheses.get_assessment_for_task("T-LOOP")
    assert persisted_task["status"] == "complete"
    assert assessment is not None
    assert assessment.hypothesis_status is HypothesisStatus.INCONCLUSIVE
    assert any(event_type == "outcome_judgment" for event_type, _ in events)
    with loop._db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM lessons").fetchone()[0] == 0
    loop._db.close()


def test_strong_matching_evidence_confirms_hypothesis():
    assessment = OutcomeJudge().judge(
        _task(),
        _execution(success=True, evidence=["E-443"]),
        Observation(
            facts=["Port 443/tcp open"],
            new_endpoints=["example.test:443/tcp"],
            evidence_refs=["E-443"],
            usefulness=40,
        ),
    )

    assert assessment.hypothesis_status is HypothesisStatus.CONFIRMED
    assert assessment.confidence >= 0.9
    assert assessment.satisfied_criteria
    assert assessment.evidence_refs == ["E-443"]
    assert assessment.another_investigation_justified is False


def test_contradictory_structured_evidence_refutes_hypothesis():
    assessment = OutcomeJudge().judge(
        _task(),
        _execution(success=True, evidence=["E-CLOSED"]),
        Observation(facts=["Port 443/tcp closed"], evidence_refs=["E-CLOSED"]),
    )

    assert assessment.hypothesis_status is HypothesisStatus.REFUTED
    assert assessment.confidence >= 0.9
    assert assessment.evidential_outcome == "failure"


def test_repeated_independent_inconclusive_checks_exhaust_hypothesis(tmp_path):
    db, mission_id = _database(tmp_path / "attempts.db")
    queue = TaskQueue(db, mission_id)
    repository = HypothesisRepository(db, mission_id)
    judge = OutcomeJudge(max_inconclusive_attempts=3)
    statuses = []

    for index, tool in enumerate(("check_a", "check_b", "check_c"), start=1):
        task = _task(tool)
        task["task_id"] = f"T-{index}"
        queue.create_task(task)
        persisted_task = queue.get_task(task["task_id"])
        prior = repository.get_for_task(persisted_task)
        assessment = judge.judge(
            persisted_task,
            _execution(success=True, evidence=[f"E-{index}"]),
            Observation(facts=[f"Unrelated fact {index}"], evidence_refs=[f"E-{index}"]),
            prior_hypothesis=prior,
        )
        assessment, state = repository.persist_assessment(persisted_task, assessment)
        statuses.append(assessment.hypothesis_status)
        queue.complete_task(task["task_id"])

    assert statuses[0] is HypothesisStatus.INCONCLUSIVE
    assert statuses[1] is HypothesisStatus.INCONCLUSIVE
    assert statuses[2] is HypothesisStatus.EXHAUSTED
    assert state is not None
    assert state.attempt_count == 3
    assert state.independent_check_count == 3


def test_single_inconclusive_attempt_does_not_exhaust():
    assessment = OutcomeJudge(max_inconclusive_attempts=3).judge(
        _task(),
        _execution(success=True, evidence=["E-1"]),
        Observation(facts=["Unrelated fact"], evidence_refs=["E-1"]),
    )
    assert assessment.hypothesis_status is HypothesisStatus.INCONCLUSIVE
    assert assessment.attempt_count == 1


@pytest.mark.parametrize("status", ["confirmed", "refuted", "exhausted"])
def test_terminal_hypotheses_are_not_replanned(status):
    state = {
        "hypothesis_id": "HYP-1",
        "statement": "Port 443 is open on example.test.",
        "target": "example.test",
        "status": status,
        "confidence": 0.9,
        "attempt_count": 1,
    }
    tasks = PlannerAgent().plan(
        mission={"program_name": "test", "allowed_assets": ["example.test"]},
        open_hypotheses=[state],
        hypothesis_states=[state],
        existing_task_count=1,
        phase_filter="hypothesis_only",
    )
    assert tasks == []


def test_repeated_identical_check_is_rejected(tmp_path):
    db, mission_id = _database(tmp_path / "duplicate.db")
    queue = TaskQueue(db, mission_id)
    first = _task("check_a")
    first["task_id"] = "T-FIRST"
    second = _task("check_a")
    second["task_id"] = "T-SECOND"
    second["objective"] = "[RETRY 2] Reworded but materially identical check"
    second["phase"] = "recon"
    second["success_criteria"] = ["Cosmetically different evaluation wording"]

    queue.create_task(first)
    with pytest.raises(DuplicateInvestigationError):
        queue.create_task(second)


def test_planner_ranks_information_value_over_costly_repetition():
    ranked = PlannerAgent.rank_unresolved_hypotheses(
        [
            {
                "hypothesis_id": "H-REPEATED",
                "statement": "Repeated path",
                "status": "inconclusive",
                "confidence": 0.8,
                "expected_information_value": 0.2,
                "attempt_count": 2,
                "risk_level": "high",
                "estimated_cost": 0.9,
            },
            {
                "hypothesis_id": "H-DISCRIMINATING",
                "statement": "Low-risk distinguishing check",
                "status": "open",
                "confidence": 0.5,
                "expected_information_value": 0.9,
                "attempt_count": 0,
                "risk_level": "low",
                "estimated_cost": 0.1,
            },
        ]
    )
    assert ranked[0]["hypothesis_id"] == "H-DISCRIMINATING"


def test_evidence_and_confidence_persist_across_restart(tmp_path):
    path = tmp_path / "restart.db"
    db, mission_id = _database(path)
    queue = TaskQueue(db, mission_id)
    repository = HypothesisRepository(db, mission_id)
    task = _task()
    task["task_id"] = "T-RESTART"
    queue.create_task(task)
    persisted_task = queue.get_task("T-RESTART")
    assessment = OutcomeJudge().judge(
        persisted_task,
        _execution(success=True, evidence=["E-PERSIST"]),
        Observation(facts=["Port 443/tcp open"], evidence_refs=["E-PERSIST"]),
        prior_hypothesis=repository.get_for_task(persisted_task),
    )
    assessment, state = repository.persist_assessment(persisted_task, assessment)
    hypothesis_id = state.hypothesis_id
    db.close()

    resumed_db = DatabaseManager(path)
    with resumed_db.connection(write=True) as conn:
        resumed_db.ensure_schema(conn)
    resumed = HypothesisRepository(resumed_db, mission_id)
    loaded = resumed.get(hypothesis_id)
    loaded_assessment = resumed.get_assessment_for_task("T-RESTART")

    assert loaded is not None
    assert loaded.status is HypothesisStatus.CONFIRMED
    assert loaded.confidence == assessment.confidence
    assert loaded.evidence_refs == ["E-PERSIST"]
    assert loaded_assessment is not None
    assert loaded_assessment.evidence_refs == ["E-PERSIST"]
    assert loaded_assessment.attempt_count == 1


def test_version_three_database_migrates_without_inferred_success(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE _migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
        INSERT INTO _migrations VALUES(1, 'old'), (2, 'old'), (3, 'old');
        CREATE TABLE missions (
            id TEXT PRIMARY KEY,
            program_name TEXT NOT NULL DEFAULT '',
            objective TEXT NOT NULL DEFAULT '',
            risk_profile TEXT NOT NULL DEFAULT 'low_noise_non_destructive',
            testing_modes_json TEXT NOT NULL DEFAULT '[]',
            target_assets_json TEXT NOT NULL DEFAULT '[]',
            allowed_assets_json TEXT NOT NULL DEFAULT '[]',
            disallowed_assets_json TEXT NOT NULL DEFAULT '[]',
            forbidden_actions_json TEXT NOT NULL DEFAULT '[]',
            rate_limits_json TEXT NOT NULL DEFAULT '{}',
            accounts_json TEXT NOT NULL DEFAULT '[]',
            notes TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE tasks (
            id TEXT PRIMARY KEY,
            mission_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            asset_type TEXT NOT NULL DEFAULT '',
            objective TEXT NOT NULL DEFAULT '',
            hypothesis TEXT NOT NULL DEFAULT '',
            preconditions_json TEXT NOT NULL DEFAULT '[]',
            allowed_tools_json TEXT NOT NULL DEFAULT '[]',
            risk_level TEXT NOT NULL DEFAULT 'low',
            priority INTEGER NOT NULL DEFAULT 0,
            required_human_approval INTEGER NOT NULL DEFAULT 0,
            success_criteria_json TEXT NOT NULL DEFAULT '[]',
            stop_conditions_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'pending',
            result_summary TEXT NOT NULL DEFAULT '',
            block_reason TEXT NOT NULL DEFAULT '',
            evidence_refs_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        INSERT INTO missions(id, program_name, created_at, updated_at)
            VALUES('M-OLD', 'legacy', 'old', 'old');
        INSERT INTO tasks(
            id, mission_id, phase, target, objective, hypothesis,
            allowed_tools_json, status, created_at, updated_at)
            VALUES(
                'T-OLD', 'M-OLD', 'analysis', 'example.test', 'legacy check',
                'Port 443 is open', '["check_a"]', 'complete', 'old', 'old'
            );
        """
    )
    conn.commit()
    conn.close()

    db = DatabaseManager(path)
    with db.connection(write=True) as migrated:
        db.ensure_schema(migrated)
        assert migrated.execute("SELECT MAX(version) FROM _migrations").fetchone()[0] == _SCHEMA_VERSION
        task_columns = {
            row["name"] for row in migrated.execute("PRAGMA table_info(tasks)").fetchall()
        }
        assert {"hypothesis_id", "check_fingerprint"} <= task_columns
        hypothesis = migrated.execute("SELECT * FROM hypotheses").fetchone()
        assert hypothesis is not None
        assert hypothesis["status"] == "open"
        assert hypothesis["attempt_count"] == 0
