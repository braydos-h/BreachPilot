"""Tests for the evidence store module.

Covers:
- Save evidence of different types
- Retrieve evidence by ID
- List evidence for tasks and findings
- Compare evidence items
"""

from __future__ import annotations

import hashlib

import pytest

from db import DatabaseManager, _new_id
from evidence import EvidenceStore

# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test_evidence.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Evidence Test", "Find vulns.", "standard_authorized"),
        )
        # Create a test task
        tid = _new_id("T")
        conn.execute(
            """INSERT INTO tasks(id, mission_id, phase, target, objective, status, created_at, updated_at)
            VALUES(?,?,?,?,?,?,datetime('now'),datetime('now'))""",
            (tid, mid, "recon", "example.com", "Test task", "pending"),
        )
        db._mid = mid
        db._tid = tid
    return db


@pytest.fixture
def evidence_store(temp_db, tmp_path):
    ws = tmp_path / "evidence_ws"
    ws.mkdir(parents=True, exist_ok=True)
    return EvidenceStore(
        temp_db,
        getattr(temp_db, "_mid", "M-TEST"),
        ws,
    )


# ── Save & Get ────────────────────────────────────────────────────────────


def test_save_and_get_raw_output(evidence_store):
    eid = evidence_store.save(
        evidence_type="raw_output",
        content="Nmap scan results: port 22 open\nPort 80 open",
        metadata={"tool": "nmap", "target": "example.com"},
    )
    assert eid.startswith("E-")

    ev = evidence_store.get(eid)
    assert ev is not None
    assert "Nmap scan" in ev.get("content", "")
    assert ev["type"] == "raw_output"


def test_save_http_response(evidence_store):
    eid = evidence_store.save(
        evidence_type="http_response",
        content="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html>...</html>",
    )
    ev = evidence_store.get(eid)
    assert ev is not None
    assert "nginx" in ev.get("content", "") or "nginx" in ev.get("summary", "")


def test_save_with_task_id(evidence_store, temp_db):
    tid = getattr(temp_db, "_tid", "T-TEST")
    eid = evidence_store.save(
        evidence_type="raw_output",
        content="Port scan result",
        task_id=tid,
    )
    assert eid.startswith("E-")

    # List for task
    items = evidence_store.list_for_task(tid)
    assert len(items) == 1
    assert items[0]["evidence_id"] == eid


# ── Hash ──────────────────────────────────────────────────────────────────


def test_evidence_hash(evidence_store):
    content = "Test content with unique data: abc123"
    eid = evidence_store.save(evidence_type="note", content=content)

    ev = evidence_store.get(eid)
    assert ev is not None

    expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert ev["hash"] == expected_hash


# ── List by finding ──────────────────────────────────────────────────────


def test_list_for_finding(evidence_store):
    eid1 = evidence_store.save(evidence_type="raw_output", content="Ev1", finding_id="F-TEST")
    eid2 = evidence_store.save(evidence_type="note", content="Ev2", finding_id="F-TEST")

    items = evidence_store.list_for_finding("F-TEST")
    assert len(items) == 2
    ids = {i["evidence_id"] for i in items}
    assert eid1 in ids
    assert eid2 in ids


# ── Compare ───────────────────────────────────────────────────────────────


def test_compare_same(evidence_store):
    content = "Same content"
    a = evidence_store.save(evidence_type="note", content=content)
    b = evidence_store.save(evidence_type="note", content=content)

    compare = evidence_store.compare(a, b)
    assert compare["comparable"] is True
    assert compare["same_hash"] is True


def test_compare_different(evidence_store):
    a = evidence_store.save(evidence_type="note", content="Content A: " + _new_id(""))
    b = evidence_store.save(evidence_type="note", content="Content B: " + _new_id(""))

    compare = evidence_store.compare(a, b)
    assert compare["comparable"] is True
    assert compare["same_hash"] is False


def test_compare_missing(evidence_store):
    a = evidence_store.save(evidence_type="note", content="test")
    compare = evidence_store.compare(a, "E-MISSING")
    assert compare["comparable"] is False


# ── List for mission ─────────────────────────────────────────────────────


def test_list_for_mission(evidence_store):
    evidence_store.save(evidence_type="raw_output", content="A")
    evidence_store.save(evidence_type="raw_output", content="B")
    evidence_store.save(evidence_type="http_response", content="C")

    items = evidence_store.list_for_mission()
    assert len(items) == 3


# ── Multiple evidence types ──────────────────────────────────────────────


def test_all_evidence_types(evidence_store):
    types = ["raw_output", "http_response", "note", "structured_json"]
    count = 0
    for t in types:
        eid = evidence_store.save(evidence_type=t, content=f"Test {t}")
        ev = evidence_store.get(eid)
        assert ev is not None
        count += 1
    assert count == 4
