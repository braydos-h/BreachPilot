"""Tests for honest adaptive retries.

The audit flagged that ``_run_adaptive_rounds`` could spin empty rounds after
all applicable modules were dropped by ``skip_failed``: ``should_continue()``
stayed true on ``not access_achieved`` even when no candidate tasks remained,
so the loop burned the full ``max_cycles`` budget doing nothing. These tests
pin the no-novel-candidate stop.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.autonomous_orchestrator import (
    AttackState,
    AutonomousOrchestrator,
)
from tools.recon_pipeline import HostReconResult, ServiceInfo


def _recon_with_http() -> HostReconResult:
    return HostReconResult(
        target_ip="10.0.0.5",
        os_family="linux",
        services=[ServiceInfo(port=80, protocol="tcp", service="http")],
        open_ports=[80],
    )


def _orchestrator(tmp_path: Path) -> AutonomousOrchestrator:
    return AutonomousOrchestrator(
        mission_config={
            "program_name": "test",
            "objective": "test",
            "adaptive_replan": True,
            "max_cycles": 10,
        },
        workspace_root=tmp_path,
        tool_executor=lambda name, args: "exit_code=0",
    )


async def _noop_privesc(state):
    return None


async def _noop_lateral(state, depth):
    return None


@pytest.mark.asyncio
async def test_adaptive_rounds_stop_when_no_novel_candidates_remain(tmp_path):
    """When an exploitation round creates no new tasks (all modules already
    failed) and no access is achieved, the adaptive loop must stop -- not spin
    ``max_cycles`` empty rounds (audit: it burned the full budget doing
    nothing)."""
    orch = _orchestrator(tmp_path)

    # Simulate: round 1 creates tasks (module runs, fails); round 2 (skip_failed)
    # creates NO new tasks -> the no-novel-candidate stop must fire.
    call_count = {"n": 0}

    async def _fake_exploit(state, *, skip_failed=False):
        call_count["n"] += 1
        # Round 1: create one task so the round did work. Mark the module as
        # failed so the next round's skip_failed would drop it.
        if call_count["n"] == 1:
            from tools.autonomous_orchestrator import AttackPhase, AttackTask
            t = AttackTask(
                task_id="ATK-1",
                phase=AttackPhase.EXPLOITATION,
                module_name="FakeModule",
                target=state.target,
            )
            orch._tasks[t.task_id] = t
            state.record_failure("FakeModule", "exploit failed")
        # Round 2: no tasks created (empty -- simulates all-dropped).
        return None

    orch._phase_exploitation = _fake_exploit  # type: ignore

    orch._phase_privilege_escalation = _noop_privesc  # type: ignore
    orch._phase_lateral_movement = _noop_lateral  # type: ignore
    orch._schedule_vuln_chain = lambda state: None  # type: ignore

    state = AttackState(target="10.0.0.5")
    state.recon_result = _recon_with_http()

    await orch._run_adaptive_rounds(state, 0)

    # Round 1 ran (created + failed a task). Round 2 ran (skip_found, no new
    # tasks) -> no-novel-candidate stop fired. Must NOT run 10 rounds.
    assert call_count["n"] == 2, f"expected 2 rounds, got {call_count['n']}"
    stop_events = [e for e in state.timeline if e["event_type"] == "adaptive_stop"]
    assert stop_events, "expected an adaptive_stop timeline event"


@pytest.mark.asyncio
async def test_adaptive_rounds_continue_when_access_achieved(tmp_path):
    """When access IS achieved, the no-novel-candidate stop must NOT fire even
    if a round creates no new tasks -- privesc/lateral may still have work."""
    orch = _orchestrator(tmp_path)

    async def _fake_exploit(state, *, skip_failed=False):
        # No tasks created, but access was achieved on a prior round.
        return None

    orch._phase_exploitation = _fake_exploit  # type: ignore

    privesc_called = {"n": 0}

    async def _fake_privesc(state):
        privesc_called["n"] += 1

    orch._phase_privilege_escalation = _fake_privesc  # type: ignore
    orch._phase_lateral_movement = _noop_lateral  # type: ignore
    orch._schedule_vuln_chain = lambda state: None  # type: ignore

    state = AttackState(target="10.0.0.5")
    state.recon_result = _recon_with_http()
    state.access_achieved = True
    state.privilege_level = "www-data"  # not root -> should_continue True

    await orch._run_adaptive_rounds(state, 0)

    # The no-novel-candidate stop must NOT fire when access is achieved.
    stop_events = [e for e in state.timeline if e["event_type"] == "adaptive_stop"]
    assert not stop_events, "adaptive_stop must not fire when access is achieved"
    # Privesc was called (access achieved, privilege not yet root).
    assert privesc_called["n"] >= 1
