"""Phase 6.2 — OPSEC pacing wiring into AttackModuleExecutor / AutonomousOrchestrator.

Locks in that:
- AttackModuleExecutor.execute() awaits opsec_manager.acquire_pacing(aggression)
  before each module run (so AggressionLevel.STEALTH becomes load-bearing).
- A missing opsec_manager is a no-op (legacy behavior).
- An opsec pacing exception is swallowed (never blocks an authorized step).
- AutonomousOrchestrator builds an OpsecManager from the ``opsec`` config block
  and forwards it to the executor (disabled profile when the block is absent).
"""

from __future__ import annotations

from pathlib import Path
import tempfile

import pytest

from tools.autonomous_orchestrator import (
    AggressionLevel,
    AttackModuleExecutor,
    AttackPhase,
    AttackState,
    AttackTask,
    AutonomousOrchestrator,
)


class FakeOpsec:
    """Records acquire_pacing calls; configurable raise-on-call."""

    def __init__(self, *, raise_on_call: bool = False) -> None:
        self.calls: list[str] = []
        self._raise = raise_on_call

    async def acquire_pacing(self, aggression: str) -> None:
        self.calls.append(aggression)
        if self._raise:
            raise RuntimeError("pacing explosion")


def _info_task(aggression: AggressionLevel = AggressionLevel.STEALTH) -> AttackTask:
    # detection_coverage_probe is a registered info module (no dispatch, no
    # shell_type/privilege_level) -- ideal for exercising the pacing chokepoint
    # without triggering real exploit dispatch.
    return AttackTask(
        task_id="T-OPSEC-1",
        phase=AttackPhase.EXPLOITATION,
        module_name="detection_coverage_probe",
        target="10.0.0.50",
        aggression=aggression,
    )


@pytest.mark.asyncio
async def test_execute_awaits_opsec_pacing_with_aggression() -> None:
    opsec = FakeOpsec()
    executor = AttackModuleExecutor(opsec_manager=opsec)
    state = AttackState(target="10.0.0.50")
    result = await executor.execute(_info_task(AggressionLevel.STEALTH), state)
    assert opsec.calls == ["stealth"]
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_execute_pacing_aggression_tracks_task() -> None:
    opsec = FakeOpsec()
    executor = AttackModuleExecutor(opsec_manager=opsec)
    state = AttackState(target="10.0.0.50")
    await executor.execute(_info_task(AggressionLevel.AGGRESSIVE), state)
    assert opsec.calls == ["aggressive"]


@pytest.mark.asyncio
async def test_execute_no_opsec_manager_is_noop() -> None:
    executor = AttackModuleExecutor(opsec_manager=None)
    state = AttackState(target="10.0.0.50")
    # Must not raise; pacing path is skipped entirely when manager is None.
    result = await executor.execute(_info_task(), state)
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_execute_opsec_pacing_exception_does_not_block() -> None:
    opsec = FakeOpsec(raise_on_call=True)
    executor = AttackModuleExecutor(opsec_manager=opsec)
    state = AttackState(target="10.0.0.50")
    # A pacing failure must be swallowed -- the authorized step still runs.
    result = await executor.execute(_info_task(), state)
    assert isinstance(result, dict)
    assert opsec.calls == ["stealth"]  # the call was attempted


def test_orchestrator_builds_opsec_from_config() -> None:
    ws = Path(tempfile.mkdtemp())
    mc = {"opsec": {"enabled": True, "ua_rotation": True, "min_gap_seconds": 0.5, "jitter_seconds": 0.2}}
    o = AutonomousOrchestrator(mc, ws)
    assert o._opsec is not None
    assert o._executor._opsec is o._opsec
    assert o._opsec.profile.enabled is True
    assert o._opsec.profile.ua_rotation is True
    assert o._opsec.profile.min_gap_seconds == 0.5


def test_orchestrator_opsec_disabled_when_block_absent() -> None:
    ws = Path(tempfile.mkdtemp())
    o = AutonomousOrchestrator({}, ws)
    # Manager is still built (so process_user_agent global is set) but the
    # profile is disabled -> pacing is a no-op (legacy behavior).
    assert o._opsec is not None
    assert o._opsec.profile.enabled is False
    assert o._executor._opsec is o._opsec