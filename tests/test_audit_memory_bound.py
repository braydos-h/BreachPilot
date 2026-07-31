"""Regression: ExploitPolicy._records is a bounded ring buffer.

The on-disk JSONL (exploit_audit.jsonl) is the complete, append-only audit
chain. The in-memory ``_records`` list is only a convenience cache for the
approval-block message (reads ``[-1]``) and the final report. Left unbounded
it leaked memory across long autonomous campaigns — every tool call appended
a full ExploitRecord that was never trimmed. This test pins the cap.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tools.exploit_agent.policy import (
    MAX_INMEMORY_AUDIT_RECORDS,
    ExploitPermission,
    ExploitPolicy,
    ExploitSettings,
)


def _make_policy(tmp_path: Path) -> ExploitPolicy:
    settings = ExploitSettings(
        enabled=True,
        permission=ExploitPermission.FULL_ACCESS,
        attack_mode=True,
        target_ip="10.0.0.5",
    )
    return ExploitPolicy(settings=settings, workspace=tmp_path)


@pytest.mark.asyncio
async def test_inmemory_records_capped(tmp_path: Path) -> None:
    policy = _make_policy(tmp_path)
    # Record far more than the cap; each record() mirrors a tool call.
    over = MAX_INMEMORY_AUDIT_RECORDS + 250
    for i in range(over):
        await policy.record(action="run_exploit_terminal", command=f"cmd {i}", status="completed")

    # In-memory list must stay bounded at the cap.
    assert len(policy._records) == MAX_INMEMORY_AUDIT_RECORDS
    # The most recent record is retained (approval-block path reads [-1]).
    assert policy._records[-1].command == f"cmd {over - 1}"

    # The on-disk JSONL still holds the complete chain.
    full = policy.read_audit_records()
    assert len(full) == over
    assert full[0].command == "cmd 0"
    assert full[-1].command == f"cmd {over - 1}"


@pytest.mark.asyncio
async def test_read_audit_records_round_trips_chain(tmp_path: Path) -> None:
    policy = _make_policy(tmp_path)
    for i in range(5):
        await policy.record(action="run_exploit_terminal", command=f"cmd {i}", status="completed")

    full = policy.read_audit_records()
    assert len(full) == 5
    # Hash chain survives the round-trip.
    for prev, cur in zip(full, full[1:]):
        assert cur.prev_hash == prev.hash


@pytest.mark.asyncio
async def test_read_audit_records_missing_file_returns_empty(tmp_path: Path) -> None:
    policy = _make_policy(tmp_path / "never_created")
    assert policy.read_audit_records() == []