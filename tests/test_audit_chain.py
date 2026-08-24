"""Tier 3 regression tests: exploit_audit.jsonl tamper-evidence hash chain.

``ExploitPolicy.record()`` now links each record to the previous one via
``prev_hash``/``hash`` (sha256 of the canonical JSON minus the ``hash`` field),
and ``verify_audit_chain`` recomputes the chain end-to-end at startup. The
shared audit file is also appended to by the MCP tool layer
(``tools.mcp_shared.make_audit_tool``) with a different, *unchained* schema;
those rows have no ``hash`` field and must be skipped by the verifier (not
flagged as tampered), and by ``_load_last_hash`` when seeding the chain tail.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.exploit_agent import (
    ExploitPermission,
    ExploitPolicy,
    ExploitRecord,
    ExploitSettings,
    _record_chain_hash,
    verify_audit_chain,
)


def _settings(tmp_path: Path) -> ExploitSettings:
    return ExploitSettings(
        enabled=True,
        mode="standalone",
        target_ip="10.0.0.50",
        workspace_root=tmp_path,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
    )


@pytest.mark.asyncio
async def test_record_chains_prev_hash(tmp_path: Path):
    policy = ExploitPolicy(_settings(tmp_path), tmp_path)
    r1 = await policy.record(action="run_exploit_terminal", command="echo a", status="completed")
    r2 = await policy.record(action="run_exploit_terminal", command="echo b", status="completed")
    assert r1.prev_hash == ""
    assert r1.hash != ""
    assert r2.prev_hash == r1.hash
    assert r2.hash != r1.hash
    # _last_hash advanced to the tail.
    assert policy._last_hash == r2.hash


@pytest.mark.asyncio
async def test_chain_verifies_across_records(tmp_path: Path):
    policy = ExploitPolicy(_settings(tmp_path), tmp_path)
    for i in range(4):
        await policy.record(action="run_exploit_terminal", command=f"echo {i}", status="completed")
    ok, why = verify_audit_chain(tmp_path / "exploit_audit.jsonl")
    assert ok, why
    assert "4 chained" in why


@pytest.mark.asyncio
async def test_chain_continues_across_policy_instances(tmp_path: Path):
    """A second ExploitPolicy in the same workspace must continue the chain
    (prev_hash links to the prior instance's last record)."""
    p1 = ExploitPolicy(_settings(tmp_path), tmp_path)
    await p1.record(action="run_exploit_terminal", command="echo first", status="completed")
    last = p1._last_hash
    p2 = ExploitPolicy(_settings(tmp_path), tmp_path)
    assert p2._last_hash == last, "new instance must seed _last_hash from the file tail"
    r = await p2.record(action="run_exploit_terminal", command="echo second", status="completed")
    assert r.prev_hash == last
    ok, _ = verify_audit_chain(tmp_path / "exploit_audit.jsonl")
    assert ok


@pytest.mark.asyncio
async def test_tampered_record_breaks_chain(tmp_path: Path):
    policy = ExploitPolicy(_settings(tmp_path), tmp_path)
    await policy.record(action="run_exploit_terminal", command="echo a", status="completed")
    await policy.record(action="run_exploit_terminal", command="echo b", status="completed")

    audit = tmp_path / "exploit_audit.jsonl"
    lines = audit.read_text(encoding="utf-8").splitlines()
    # Rewrite the second record's status in place (tampering).
    obj = json.loads(lines[1])
    obj["status"] = "completed"  # unchanged value but break the hash by re-dumping w/o hash
    obj.pop("hash", None)
    obj.pop("prev_hash", None)
    lines[1] = json.dumps(obj)
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, why = verify_audit_chain(audit)
    assert not ok
    assert "hash mismatch" in why or "prev_hash mismatch" in why


@pytest.mark.asyncio
async def test_unchained_mcp_tool_rows_skipped_by_verifier(tmp_path: Path):
    """The MCP tool layer (make_audit_tool) writes rows with no ``hash`` field
    interleaved with ExploitPolicy rows. The verifier must skip them, not flag
    them as a broken chain."""
    audit = tmp_path / "exploit_audit.jsonl"
    # An unchained MCP-tool-style row FIRST (no hash/prev_hash).
    audit.write_text(
        json.dumps(
            {
                "timestamp": "t",
                "target_ip": "10.0.0.50",
                "tool_name": "msfconsole_command",
                "approved": True,
                "status": "completed",
                "command": "set RHOSTS 10.0.0.50",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    policy = ExploitPolicy(_settings(tmp_path), tmp_path)
    # _load_last_hash must skip the unchained row -> chain starts fresh.
    assert policy._last_hash == ""
    await policy.record(action="run_exploit_terminal", command="echo a", status="completed")
    # Append a trailing unchained row AFTER the chained one.
    with audit.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"tool_name": "msf_list_sessions", "status": "completed"}) + "\n")
    ok, why = verify_audit_chain(audit)
    assert ok, why
    assert "1 chained" in why


def test_record_chain_hash_excludes_hash_field():
    rec = ExploitRecord(
        timestamp="t",
        target_ip="10.0.0.50",
        action="x",
        approved=True,
        status="completed",
        command="c",
        detail="",
        attempt_id="",
    )
    rec.prev_hash = "abc"
    h1 = _record_chain_hash(rec)
    # Mutating the hash field must NOT change the computed chain hash.
    rec.hash = "deadbeef"
    h2 = _record_chain_hash(rec)
    assert h1 == h2
    # Mutating any real field DOES change it.
    rec.status = "blocked"
    assert _record_chain_hash(rec) != h1
