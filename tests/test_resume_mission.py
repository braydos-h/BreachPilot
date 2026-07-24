"""Regression tests for Tier 1.3 — real ``--resume`` / mission reattach (Flow B).

Flow B's DB already holds the entire resumable state (mission row, scope_rules,
tasks w/ status, observations, findings, evidence, graph, memory, audit). The
gap was that ``AgentLoop.__init__`` ALWAYS called ``create_from_config`` (a new
mission row) and never accepted a ``mission_id`` to resume. Tier 1.3 adds:

* ``AgentLoop(..., mission_id=<id>)`` -> loads the existing mission row from the
  DB (instead of creating one), re-points every manager at it, and re-queues any
  tasks left 'running' by a crashed prior run back to 'pending'.
* ``TaskQueue.reset_stale_running()`` -- the safety-critical primitive that
  re-queues in-flight tasks so a botched resume neither silently drops them nor
  leaves them as in-flight (where ``get_next_task`` would never pick them up).

These tests would have caught the original gap: a resumed loop must load the
SAME mission (not mint a new id), must not create a second mission row, must
use the DB's scope (not the passed config), and must re-queue stale 'running'
tasks.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent_loop import AgentLoop


def _config(allowed_assets: list[str] | None = None) -> dict:
    return {
        "program_name": "Resume Test",
        "objective": "verify resume",
        "risk_profile": "high_authorized_testing",
        "allowed_assets": allowed_assets or ["10.0.0.50"],
        "disallowed_assets": [],
        "forbidden_actions": ["denial_of_service"],
        "testing_modes": ["recon", "analysis", "test", "exploit"],
        "use_swarm": False,           # avoid needing a model client
        "critic_enabled": False,
        "reflection_enabled": False,
    }


def _new_loop(workspace: Path, *, mission_id: str | None = None,
               allowed_assets: list[str] | None = None) -> AgentLoop:
    return AgentLoop(
        _config(allowed_assets=allowed_assets),
        workspace,
        MagicMock(return_value="ok"),
        mission_id=mission_id,
    )


# ── Basic resume ────────────────────────────────────────────────────────────


def test_resume_loads_existing_mission_by_id(tmp_path):
    ws = tmp_path / "ws"
    loop1 = _new_loop(ws)
    mid = loop1._mission_id
    assert loop1._resumed is False

    loop2 = _new_loop(ws, mission_id=mid)
    assert loop2._resumed is True
    assert loop2._mission_id == mid, "resumed loop must keep the SAME mission id"
    assert loop2._mission.allowed_assets == ["10.0.0.50"]


def test_resume_nonexistent_mission_raises(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="Cannot resume"):
        _new_loop(ws, mission_id="M-NONEXISTENT-XYZ")


def test_resume_does_not_create_new_mission_row(tmp_path):
    ws = tmp_path / "ws"
    loop1 = _new_loop(ws)
    mid = loop1._mission_id

    with loop1._db.connection() as conn:
        n_before = conn.execute("SELECT COUNT(*) FROM missions").fetchone()[0]
    assert n_before == 1

    loop2 = _new_loop(ws, mission_id=mid)  # resume -- must NOT add a row
    with loop2._db.connection() as conn:
        n_after = conn.execute("SELECT COUNT(*) FROM missions").fetchone()[0]
    assert n_after == 1, "resume created a duplicate mission row"


def test_resume_uses_db_scope_not_config(tmp_path):
    """A resumed campaign must continue the scope it was STARTED with (from the
    DB), not re-parse the passed config's allowed_assets. Pre-1.3 there was no
    resume; this locks in that the DB is the source of truth on resume."""
    ws = tmp_path / "ws"
    loop1 = _new_loop(ws, allowed_assets=["10.0.0.50"])
    mid = loop1._mission_id

    # Resume with a DIFFERENT allowed_assets in config -- must be ignored.
    loop2 = _new_loop(ws, mission_id=mid, allowed_assets=["10.0.0.99"])
    assert loop2._mission.allowed_assets == ["10.0.0.50"], (
        "resume used config scope instead of the saved DB scope"
    )
    # ScopeGate is constructed from the loaded mission, so its allow rules
    # reflect the DB assets ("10.0.0.50"), NOT the passed config ("10.0.0.99").
    allow_patterns = {r["pattern"] for r in loop2._scope_gate._allow_rules}
    assert "10.0.0.50" in allow_patterns
    assert "10.0.0.99" not in allow_patterns


# ── Stale-running re-queue (the safety-critical piece) ─────────────────────


def test_reset_stale_running_requeues_inflight_tasks(tmp_path):
    """A crashed run leaves tasks in 'running'. reset_stale_running must move
    them to 'pending' (re-queued) and return the count."""
    ws = tmp_path / "ws"
    loop = _new_loop(ws)
    q = loop._queue

    q.create_task({"task_id": "T-RUN-1", "phase": "recon", "target": "10.0.0.50",
                   "objective": "in-flight when crash", "status": "running"})
    q.create_task({"task_id": "T-PEND-1", "phase": "recon", "target": "10.0.0.50",
                   "objective": "never started", "status": "pending"})
    q.create_task({"task_id": "T-DONE-1", "phase": "recon", "target": "10.0.0.50",
                   "objective": "already done", "status": "complete"})

    n = q.reset_stale_running()
    assert n == 1
    assert q.get_next_task()["task_id"] in ("T-RUN-1", "T-PEND-1")  # both now pending
    # The completed task is untouched.
    statuses = q.count_by_status()
    assert statuses.get("pending", 0) == 2
    assert statuses.get("complete", 0) == 1
    assert statuses.get("running", 0) == 0


def test_resume_requeues_stale_running_tasks_end_to_end(tmp_path):
    """Full resume cycle: run 1 creates a mission + leaves a task 'running'
    (simulating a crash mid-task); a fresh AgentLoop resumed on that mission_id
    re-queues the stale 'running' task to 'pending' so it is re-attempted, while
    a 'pending' and a 'complete' task are untouched."""
    ws = tmp_path / "ws"
    loop1 = _new_loop(ws)
    mid = loop1._mission_id
    loop1._queue.create_task(
        {"task_id": "T-CRASH", "phase": "recon", "target": "10.0.0.50",
         "objective": "crashed mid-flight", "status": "running"})
    loop1._queue.create_task(
        {"task_id": "T-WAIT", "phase": "recon", "target": "10.0.0.50",
         "objective": "still queued", "status": "pending"})
    loop1._queue.create_task(
        {"task_id": "T-FINI", "phase": "recon", "target": "10.0.0.50",
         "objective": "done before crash", "status": "complete"})
    # Drop loop1 (simulate process exit).

    loop2 = _new_loop(ws, mission_id=mid)
    # The stale 'running' task was re-queued to 'pending' on resume.
    statuses = loop2._queue.count_by_status()
    assert statuses.get("running", 0) == 0, "stale running task not re-queued"
    assert statuses.get("pending", 0) == 2, "T-CRASH + T-WAIT should be pending"
    assert statuses.get("complete", 0) == 1, "completed task must be untouched"
    # T-CRASH is now pickable by get_next_task (it was 'running' before -- would
    # have been invisible to get_next_task, which only selects 'pending').
    pending_ids = {t["task_id"] for t in loop2._queue.list_open_tasks()}
    assert "T-CRASH" in pending_ids


def test_resume_carries_over_findings_and_evidence(tmp_path):
    """Findings + evidence are mission-scoped DB rows, so a resumed loop sees
    the prior run's findings via its (mission_id-bound) FindingVerifier."""
    ws = tmp_path / "ws"
    loop1 = _new_loop(ws)
    mid = loop1._mission_id
    # Insert a finding directly into the DB for this mission.
    with loop1._db.connection(write=True) as conn:
        loop1._db.ensure_schema(conn)
        conn.execute(
            """INSERT INTO findings(id, mission_id, title, vuln_class,
               affected_asset, summary, impact, confidence, status, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            ("F-1", mid, "test finding", "exploitation", "10.0.0.50",
             "summary", "high", 0.9, "validated", "2026-06-18T00:00:00Z",
             "2026-06-18T00:00:00Z"),
        )

    loop2 = _new_loop(ws, mission_id=mid)
    rows = loop2._verifier.list_all()
    titles = {r.get("title") for r in rows}
    assert "test finding" in titles, "resumed loop lost the prior run's finding"


def test_fresh_loop_marks_not_resumed_and_creates_row(tmp_path):
    ws = tmp_path / "ws"
    loop = _new_loop(ws)
    assert loop._resumed is False
    assert loop._mission_id.startswith("M-")
    with loop._db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM missions").fetchone()[0] == 1