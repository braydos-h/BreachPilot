"""C6: MemoryAdapter wiring tests — graded confidence, dedup, confidence ranking."""

from __future__ import annotations

import pytest

from db import DatabaseManager, _new_id
from memory import MemoryManager
from tools.intelligence.adapters.memory_adapter import MemoryAdapter


@pytest.fixture
def mem(tmp_path):
    db = DatabaseManager(tmp_path / "adapter.db")
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Adapter Test", "Find vulns.", "standard_authorized"),
        )
        db._mid = mid
    return MemoryManager(db, db._mid)


def test_find_existing_matches_stored_fact(mem):
    mid = mem.remember(target="10.0.0.5", fact="Port 80 open", memory_type="target")
    found = MemoryAdapter().find_existing(mem, "10.0.0.5", "Port 80 open", "target")
    assert found is not None and found["id"] == mid
    assert MemoryAdapter().find_existing(mem, "10.0.0.5", "Port 443 open", "target") is None
    assert MemoryAdapter().find_existing(mem, "10.0.0.6", "Port 80 open", "target") is None


def test_dedup_remember_stores_once(mem):
    adapter = MemoryAdapter()
    first = adapter.dedup_remember(mem, "10.0.0.5", "Port 80 open", "target", 0.5)
    second = adapter.dedup_remember(mem, "10.0.0.5", "Port 80 open", "target", 0.9)
    assert first == second
    memories = mem.retrieve(target="10.0.0.5", memory_type="target")
    identical = [m for m in memories if m["fact"] == "Port 80 open"]
    assert len(identical) == 1


def test_remember_graded_stores_passed_confidence(mem):
    mid = MemoryAdapter().remember_graded(
        mem, "10.0.0.5", "nginx detected", confidence=0.4, source="test"
    )
    match = [m for m in mem.retrieve(target="10.0.0.5") if m["id"] == mid]
    assert match and match[0]["confidence"] == 0.4
    assert match[0]["metadata"].get("source") == "test"


def test_confidence_rank_sorts_desc_without_mutating():
    retrieved = [
        {"fact": "low", "confidence": 0.3},
        {"fact": "high", "confidence": 0.9},
        {"fact": "mid", "confidence": 0.5},
    ]
    original = list(retrieved)
    ranked = MemoryAdapter.confidence_rank(retrieved)
    assert [m["fact"] for m in ranked] == ["high", "mid", "low"]
    assert retrieved == original


def test_confidence_rank_is_stable():
    retrieved = [
        {"fact": "first", "confidence": 0.5},
        {"fact": "second", "confidence": 0.5},
    ]
    ranked = MemoryAdapter.confidence_rank(retrieved)
    assert [m["fact"] for m in ranked] == ["first", "second"]
