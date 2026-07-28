"""Tests for the Flow A <-> Flow B evidence bridge (Phase 1.3)."""

from __future__ import annotations

import json

import pytest

from db import DatabaseManager, _new_id
from evidence import EvidenceStore, promote_exploit_audit, record_run_output


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def temp_db(tmp_path):
    path = tmp_path / "test_evidence_bridge.db"
    db = DatabaseManager(path)
    with db.connection(write=True) as conn:
        db.ensure_schema(conn)
        mid = _new_id("M")
        conn.execute(
            """INSERT INTO missions(id, program_name, objective, risk_profile, created_at, updated_at)
            VALUES(?,?,?,?,datetime('now'),datetime('now'))""",
            (mid, "Bridge Test", "Find vulns.", "standard_authorized"),
        )
        db._mid = mid
    return db


@pytest.fixture
def evidence_store(temp_db, tmp_path):
    ws = tmp_path / "evidence_ws"
    ws.mkdir(parents=True, exist_ok=True)
    return EvidenceStore(temp_db, getattr(temp_db, "_mid", "M-TEST"), ws)


def _write_audit_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, default=str) + "\n")
    return path


# ── promote_exploit_audit ─────────────────────────────────────────────────


def test_promote_empty_path_returns_empty(evidence_store, tmp_path):
    audit = tmp_path / "missing.jsonl"
    assert promote_exploit_audit(evidence_store, audit, "M-1", "10.0.0.5") == []


def test_promote_none_store_returns_empty():
    assert promote_exploit_audit(None, "anywhere.jsonl", "M-1", "10.0.0.5") == []


def test_promote_mixes_flow_a_and_mcp_rows(evidence_store, tmp_path):
    audit = tmp_path / "exploit_audit.jsonl"
    rows = [
        # Flow A ExploitRecord row.
        {
            "timestamp": "2026-07-28T00:00:00+00:00",
            "target_ip": "10.0.0.5",
            "action": "run_exploit_terminal",
            "approved": True,
            "status": "completed",
            "exit_code": 0,
            "command": "nmap -sV 10.0.0.5",
            "detail": "scan ok",
            "attempt_id": "ATT-1",
            "full_args": {"command": "nmap -sV 10.0.0.5"},
            "code_sha256": "abc123",
            "prev_hash": "prev0",
            "hash": "hash_flow_a_1",
        },
        # MCP-tool row.
        {
            "timestamp": "2026-07-28T00:00:01+00:00",
            "target_ip": "10.0.0.5",
            "tool_name": "run_exploit_terminal",
            "approved": True,
            "status": "completed",
            "command": "whoami",
            "args": {"command": "whoami"},
            "attempt_id": "",
            "code_sha256": "def456",
            "duration_seconds": 0.4,
        },
        # Malformed line (skipped).
        "not-json{",
        # Unknown row kind (skipped).
        {"foo": "bar"},
    ]
    _write_audit_jsonl(audit, rows)

    ids = promote_exploit_audit(evidence_store, audit, "M-1", "10.0.0.5")
    assert len(ids) == 2
    for eid in ids:
        assert eid.startswith("E-")

    # The promoted rows land as structured_json evidence for the mission.
    items = evidence_store.list_for_mission(limit=50, evidence_type="structured_json")
    assert len(items) == 2
    # Each carries the audit hash + join keys in metadata.
    hashes = {item["metadata"].get("audit_hash", "") for item in items}
    assert "hash_flow_a_1" in hashes
    assert "def456" in hashes  # MCP row falls back to code_sha256
    for item in items:
        assert item["metadata"]["source"] == "exploit_audit"
        assert item["metadata"]["target_ip"] == "10.0.0.5"
        assert item["metadata"]["mission_id"] == "M-1"
        # Action label is Flow A action OR MCP tool_name.
        assert item["metadata"]["action"] in {"run_exploit_terminal"}


def test_promote_skips_unknown_rows(evidence_store, tmp_path):
    audit = tmp_path / "exploit_audit.jsonl"
    _write_audit_jsonl(audit, [{"weird": "shape"}])
    assert promote_exploit_audit(evidence_store, audit, "M-1", "10.0.0.5") == []


def test_promote_skips_malformed_json(evidence_store, tmp_path):
    audit = tmp_path / "exploit_audit.jsonl"
    audit.parent.mkdir(parents=True, exist_ok=True)
    audit.write_text("not-json\n\n  \n", encoding="utf-8")
    assert promote_exploit_audit(evidence_store, audit, "M-1", "10.0.0.5") == []


def test_promote_empty_file(evidence_store, tmp_path):
    audit = tmp_path / "exploit_audit.jsonl"
    audit.write_text("", encoding="utf-8")
    assert promote_exploit_audit(evidence_store, audit, "M-1", "10.0.0.5") == []


# ── record_run_output ────────────────────────────────────────────────────


def test_record_run_output_writes_raw_output(evidence_store):
    eid = record_run_output(
        evidence_store,
        mission_id="M-1",
        target_ip="10.0.0.5",
        action="verify_compromise",
        output_text="uid=0(root)\nroot\ntarget-host\n",
        audit_hash="hash123",
    )
    assert eid.startswith("E-")
    ev = evidence_store.get(eid)
    assert ev is not None
    assert ev["type"] == "raw_output"
    assert "uid=0(root)" in ev["content"]
    assert ev["metadata"]["action"] == "verify_compromise"
    assert ev["metadata"]["audit_hash"] == "hash123"
    assert ev["metadata"]["source"] == "run_output"


def test_record_run_output_empty_text_returns_empty(evidence_store):
    assert record_run_output(evidence_store, "M-1", "10.0.0.5", "act", "") == ""


def test_record_run_output_none_store_returns_empty():
    assert record_run_output(None, "M-1", "10.0.0.5", "act", "text") == ""


def test_record_run_output_default_audit_hash(evidence_store):
    eid = record_run_output(
        evidence_store,
        mission_id="M-1",
        target_ip="10.0.0.5",
        action="probe",
        output_text="hello",
    )
    ev = evidence_store.get(eid)
    assert ev is not None
    assert ev["metadata"]["audit_hash"] == ""


# ── Existing Flow B usage stays intact ───────────────────────────────────


def test_existing_save_path_still_works(evidence_store):
    eid = evidence_store.save(
        evidence_type="raw_output",
        content="legacy flow-b output",
        metadata={"tool": "nmap"},
    )
    assert eid.startswith("E-")
    ev = evidence_store.get(eid)
    assert ev is not None
    assert "legacy flow-b output" in ev["content"]