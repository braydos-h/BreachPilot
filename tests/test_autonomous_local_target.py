"""Regression tests for the autonomous-orchestrator local-target gate (Gap 2).

The LOCAL TARGET PLAYBOOK in ``tools/exploit_agent/prompt.py`` only influences
the LLM ``exploit_agent`` path. The autonomous orchestrator had ZERO
``is_local_target`` checks, so running it (or the swarm) against ``127.0.0.1``
led with network brute-force of the box's own listeners. The fix short-circuits
``_attack_target`` to a local-takeover phase (filesystem reads + privesc) for
local targets and adds a lateral-movement guard. The scope gate is preserved
(privesc still routes through ``AttackModuleExecutor.execute`` ->
``scope_gate.check_scope``).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tools.autonomous_orchestrator import (
    AttackState,
    AutonomousOrchestrator,
)


@dataclass
class _ScopeResult:
    allowed: bool
    reason: str


class _BlockingScopeGate:
    """A scope gate whose check_scope always denies -- proves the local-takeover
    shortcut does NOT bypass the scope gate (privesc tasks get BLOCKED)."""

    def check_scope(self, *, asset, action_type=None, tool_name=None, risk_level=None):
        return _ScopeResult(allowed=False, reason="blocked by test scope gate")


def _timeline_types(state: AttackState) -> list[str]:
    return [e["event_type"] for e in state.timeline]


def _orch(
    tmp_path: Path,
    *,
    tool_executor=None,
    scope_gate=None,
    mission_config: dict[str, Any] | None = None,
) -> AutonomousOrchestrator:
    return AutonomousOrchestrator(
        mission_config=mission_config or {"max_cycles": 5},
        workspace_root=tmp_path,
        tool_executor=tool_executor,
        scope_gate=scope_gate,
    )


# ── _attack_target short-circuit ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_attack_target_local_short_circuits_recon(tmp_path: Path) -> None:
    """127.0.0.1 -> local-takeover runs, reconnaissance does NOT."""
    recorded_cmds: list[str] = []

    def _exec(cmd: str, ctx: dict[str, Any]) -> str:
        recorded_cmds.append(cmd)
        return "stub-output"

    # Stub out the heavy phases so we observe the routing, not real execution.
    orch = _orch(tmp_path, tool_executor=_exec)
    recon_called = {"v": False}
    privesc_called = {"v": False}
    validation_called = {"v": False}

    async def _fake_recon(state):
        recon_called["v"] = True
    async def _fake_privesc(state):
        privesc_called["v"] = True
    async def _fake_validation(state):
        validation_called["v"] = True

    orch._phase_reconnaissance = _fake_recon  # type: ignore[assignment]
    orch._phase_privilege_escalation = _fake_privesc  # type: ignore[assignment]
    orch._phase_validation = _fake_validation  # type: ignore[assignment]

    result = await orch._attack_target("127.0.0.1")  # type: ignore[attr-defined]

    assert result["status"] == "complete"
    assert recon_called["v"] is False, "recon must NOT run for a local target"
    assert privesc_called["v"] is True, "privesc must run in local-takeover"
    assert validation_called["v"] is True
    state = orch.get_state("127.0.0.1")
    assert "local_takeover" in _timeline_types(state)
    # The local-read commands were dispatched through the tool_executor.
    assert "cat /etc/passwd" in recorded_cmds
    assert any("/etc/shadow" in c for c in recorded_cmds)
    assert any(".ssh" in c for c in recorded_cmds)


@pytest.mark.asyncio
async def test_attack_target_remote_runs_recon(tmp_path: Path) -> None:
    """A remote target takes the normal recon-first path (no local shortcut)."""
    orch = _orch(tmp_path)
    recon_called = {"v": False}
    privesc_called = {"v": False}

    async def _fake_recon(state):
        recon_called["v"] = True
        # No open ports -> _attack_target returns "no_attack_surface" before privesc.
    async def _fake_privesc(state):
        privesc_called["v"] = True

    orch._phase_reconnaissance = _fake_recon  # type: ignore[assignment]
    orch._phase_privilege_escalation = _fake_privesc  # type: ignore[assignment]

    result = await orch._attack_target("10.0.0.99")  # type: ignore[attr-defined]

    assert recon_called["v"] is True
    assert privesc_called["v"] is False  # no open ports -> early return before privesc
    state = orch.get_state("10.0.0.99")
    assert "local_takeover" not in _timeline_types(state)


@pytest.mark.asyncio
async def test_attack_target_local_without_tool_executor(tmp_path: Path) -> None:
    """A standalone orchestrator (no tool_executor) still runs privesc and
    records that the local reads were skipped -- it does not crash."""
    orch = _orch(tmp_path, tool_executor=None)
    privesc_called = {"v": False}

    async def _fake_privesc(state):
        privesc_called["v"] = True
    async def _fake_validation(state):
        pass

    orch._phase_privilege_escalation = _fake_privesc  # type: ignore[assignment]
    orch._phase_validation = _fake_validation  # type: ignore[assignment]

    result = await orch._attack_target("127.0.0.1")  # type: ignore[attr-defined]
    assert result["status"] == "complete"
    assert privesc_called["v"] is True
    state = orch.get_state("127.0.0.1")
    assert "local_read_skipped" in _timeline_types(state)


# ── lateral movement guard ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lateral_movement_skipped_for_local(tmp_path: Path) -> None:
    """Even with pivot_targets populated, a local target never pivots."""
    orch = _orch(tmp_path)
    state = AttackState(target="127.0.0.1", pivot_targets=["10.0.0.99"])

    recursed: list[str] = []
    async def _fake_attack(target, *, _depth=0):
        recursed.append(target)
        return {"status": "complete", "state": {}}
    orch._attack_target = _fake_attack  # type: ignore[assignment]

    await orch._phase_lateral_movement(state, _depth=0)  # type: ignore[arg-type]

    assert recursed == [], "must not recurse into pivots from a local target"
    assert "lateral_skip_local" in _timeline_types(state)


@pytest.mark.asyncio
async def test_lateral_movement_proceeds_for_remote(tmp_path: Path) -> None:
    """A remote target with pivots is NOT short-circuited: the local guard does
    not fire and a LateralMovement task is created for the pivot. (Full recursion
    into ``_attack_target`` only happens after a successful lateral move, which
    is exercised in ``test_phase4_bugfixes.py`` with a stub executor.)"""
    orch = _orch(tmp_path, mission_config={"max_cycles": 5, "max_pivot_depth": 2})
    state = AttackState(target="10.0.0.5", pivot_targets=["10.0.0.99"])

    # Stub _attack_target so the LateralMovement info-stub module's success=True
    # (which triggers recursion) does NOT run a real recon pass against the
    # pivot over the network. Full recursion is covered by test_phase4_bugfixes.
    async def _fake_attack(target: str, *, _depth: int = 0) -> dict[str, Any]:
        return {"status": "complete", "state": {}}

    orch._attack_target = _fake_attack  # type: ignore[assignment]

    await orch._phase_lateral_movement(state, _depth=0)  # type: ignore[arg-type]
    # The local guard must not have fired.
    assert "lateral_skip_local" not in _timeline_types(state)
    # A lateral-movement task targeting the pivot was created and attempted.
    lateral_tasks = [
        t for t in orch._tasks.values()
        if t.phase.value == "lateral" and t.target == "10.0.0.99"
    ]
    assert lateral_tasks, "remote lateral movement must create a pivot task"


# ── scope gate still enforced on the local path ────────────────────────────


@pytest.mark.asyncio
async def test_scope_gate_still_enforced_on_local_path(tmp_path: Path) -> None:
    """The local shortcut does not bypass the scope gate: privesc tasks routed
    through AttackModuleExecutor.execute -> scope_gate.check_scope are BLOCKED
    when the gate denies. The target-IP lock is the one attack-mode safety
    kept (CLAUDE.md) and must survive the locality branch."""
    gate = _BlockingScopeGate()
    orch = _orch(tmp_path, scope_gate=gate, mission_config={"max_cycles": 5})
    state = AttackState(target="127.0.0.1")

    # _phase_privilege_escalation builds privesc tasks and runs them through
    # _execute_task_batch -> self._executor.execute -> scope_gate.check_scope.
    await orch._phase_privilege_escalation(state)  # type: ignore[arg-type]

    # Every privesc task must have been blocked by the scope gate (not silently
    # allowed by the local shortcut).
    blocked_tasks = [t for t in orch._tasks.values() if t.status.value == "blocked"]
    assert blocked_tasks, "scope gate must block privesc tasks on the local path"
    assert any("blocked by test scope gate" in (t.error or "") for t in blocked_tasks)
    assert "blocked" in _timeline_types(state)
