"""Tests for the task queue module.

Covers:
- Task creation and retrieval
- Priority ordering
- Status transitions
- Deduplication
- Reprioritization
"""

from __future__ import annotations

import pytest

from db import DatabaseManager, _new_id
from task_queue import TaskQueue

# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test_queue.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Queue Test", "Find vulns.", "standard_authorized"),
        )
    db._mid = mid
    return db


@pytest.fixture
def queue(temp_db):
    return TaskQueue(temp_db, getattr(temp_db, "_mid", "M-TEST"))


# ── Basic CRUD ────────────────────────────────────────────────────────────


def test_create_task(queue):
    tid = queue.create_task({
        "phase": "recon",
        "target": "example.com",
        "objective": "Scan ports",
        "hypothesis": "Ports expose services",
        "allowed_tools": ["nmap_basic"],
        "risk_level": "low",
    })
    assert tid.startswith("T-")

    task = queue.get_task(tid)
    assert task is not None
    assert task["phase"] == "recon"
    assert task["target"] == "example.com"
    assert task["status"] == "pending"


def test_create_multiple_priorities(queue):
    t1 = queue.create_task({
        "phase": "recon", "target": "a.com", "objective": "low prio",
        "priority": 10, "allowed_tools": ["nmap"], "risk_level": "low",
    })
    t2 = queue.create_task({
        "phase": "test", "target": "b.com", "objective": "high prio IDOR test",
        "hypothesis": "IDOR exists", "priority": 90,
        "allowed_tools": ["http_request"], "risk_level": "medium",
    })
    t3 = queue.create_task({
        "phase": "recon", "target": "c.com", "objective": "mid prio",
        "priority": 50, "allowed_tools": ["nmap"], "risk_level": "low",
    })

    # Get next should return highest priority
    next_task = queue.get_next_task()
    assert next_task["task_id"] == t2
    assert next_task["priority"] >= 90


# ── Status transitions ────────────────────────────────────────────────────


def test_status_transition(queue):
    tid = queue.create_task({
        "phase": "recon", "target": "test.com", "objective": "Test",
        "allowed_tools": ["nmap"], "risk_level": "low",
    })

    queue.update_task_status(tid, "running")
    t = queue.get_task(tid)
    assert t["status"] == "running"

    queue.complete_task(tid, "Done!")
    t = queue.get_task(tid)
    assert t["status"] == "complete"
    assert t["result_summary"] == "Done!"


def test_block_task(queue):
    tid = queue.create_task({
        "phase": "recon", "target": "blocked.com", "objective": "Will be blocked",
        "allowed_tools": ["nmap"], "risk_level": "low",
    })
    queue.block_task(tid, "Out of scope")
    t = queue.get_task(tid)
    assert t["status"] == "blocked"
    assert "Out of scope" in t["block_reason"]


# ── List operations ──────────────────────────────────────────────────────


def test_list_open(queue):
    queue.create_task({"phase": "recon", "target": "a.com", "objective": "A",
                        "allowed_tools": ["nmap"], "risk_level": "low"})
    queue.create_task({"phase": "recon", "target": "a.com", "objective": "B",
                        "allowed_tools": ["nmap"], "risk_level": "low"})

    open_tasks = queue.list_open_tasks(target="a.com")
    assert len(open_tasks) == 2


def test_list_open_filters_completed(queue):
    t1 = queue.create_task({"phase": "recon", "target": "test.com", "objective": "Pending",
                             "allowed_tools": ["nmap"], "risk_level": "low"})
    t2 = queue.create_task({"phase": "recon", "target": "test.com", "objective": "Done",
                             "allowed_tools": ["nmap"], "risk_level": "low"})
    queue.complete_task(t2, "Done")

    open_tasks = queue.list_open_tasks(target="test.com")
    assert len(open_tasks) == 1
    assert open_tasks[0]["task_id"] == t1


def test_list_blocked(queue):
    t1 = queue.create_task({"phase": "recon", "target": "blocked.com", "objective": "Blocked",
                             "allowed_tools": ["nmap"], "risk_level": "low"})
    queue.block_task(t1, "Test block")

    blocked = queue.list_blocked_tasks()
    assert len(blocked) == 1


# ── Dedup ────────────────────────────────────────────────────────────────


def test_deduplicate_pending(queue):
    queue.create_task({"phase": "recon", "target": "dup.com", "objective": "Scan ports",
                        "allowed_tools": ["nmap"], "risk_level": "low"})
    queue.create_task({"phase": "recon", "target": "dup.com", "objective": "Scan ports",
                        "allowed_tools": ["nmap"], "risk_level": "low"})

    removed = queue.deduplicate()
    assert removed >= 1

    remaining = queue.list_open_tasks(target="dup.com")
    assert len(remaining) == 1


# ── Counts ────────────────────────────────────────────────────────────────


def test_count_by_status(queue):
    queue.create_task({"phase": "recon", "target": "a.com", "objective": "A",
                        "allowed_tools": ["nmap"], "risk_level": "low"})
    queue.create_task({"phase": "recon", "target": "b.com", "objective": "B",
                        "allowed_tools": ["nmap"], "risk_level": "low"})

    counts = queue.count_by_status()
    assert counts.get("pending", 0) == 2
    assert counts.get("complete", 0) == 0


# ── Priority scoring ──────────────────────────────────────────────────────


def test_priority_scoring_auth():
    score = TaskQueue._score_priority({
        "phase": "test", "objective": "Test authorization bypass",
        "hypothesis": "Access control broken",
    })
    assert score >= 20  # test phase + auth kw


def test_priority_scoring_vague():
    score = TaskQueue._score_priority({
        "phase": "recon", "objective": "Scan all ports and discover services",
        "hypothesis": "",
    })
    assert score <= 20  # recon + vague + no hypothesis


# ── Custom task_id ───────────────────────────────────────────────────────


def test_create_with_explicit_id(queue):
    tid = queue.create_task({
        "task_id": "T-CUSTOM-001", "phase": "recon", "target": "custom.com",
        "objective": "Custom", "allowed_tools": ["nmap"], "risk_level": "low",
    })
    assert tid == "T-CUSTOM-001"
