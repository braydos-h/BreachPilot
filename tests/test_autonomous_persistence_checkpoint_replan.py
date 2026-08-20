"""Phase 2.2 / 2.3 / 2.4 — persistence phase, periodic checkpoint, adaptive replan.

These pin the three opt-in autonomous-orchestrator capabilities added in Phase 2.
All three default OFF (``persistence_phase``/``checkpoint_every``/``adaptive_replan``
in the ``autonomous`` config block), so the default single-pass ``_attack_target``
behavior is unchanged -- the existing ``test_autonomous_phase_machine.py`` suite
guards that default path; this file guards the opt-in paths.

2.2 PERSISTENCE: ``_phase_persistence`` dispatches OS-appropriate persistence
modules through ``tool_executor`` and records confirmed methods in
``state.persistence_established`` by scanning the dispatch output for the
``PERSISTENCE_INSTALLED:`` marker. Skipped when access is not achieved and
when no ``tool_executor`` is wired; the call site in ``_attack_target`` is
gated by ``persistence_phase`` so it is inert when the flag is off.

2.3 CHECKPOINT: ``run_autonomous_campaign`` saves ``attack_states.json`` every
``checkpoint_every`` completed targets (best-effort) and bounds a single
target's crash so one failure does not abort the campaign.

2.4 ADAPTIVE REPLAN: ``_run_adaptive_rounds`` runs a bounded multi-round loop
(max_cycles) that stops when ``should_continue`` is False; ``_phase_exploitation``
drops already-failed modules when ``skip_failed`` is set; ``_schedule_vuln_chain``
records exploit->creds/pivot chain metadata.

The persistence-handler tests use FAKE persistence modules (defined below) that
print the canonical marker, so handler logic is tested independently of the real
module implementations in tools/attack_modules/modules/persistence.py (those are
covered by test_persistence_modules.py).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools.attack_modules import AttackModule, ModuleContext
import tools.autonomous_orchestrator as orch_mod
from tools.autonomous_orchestrator import (
    AttackPhase,
    AttackState,
    AttackTask,
    AutonomousOrchestrator,
)
from tools.recon_pipeline import HostReconResult, ServiceInfo


# ── Fake persistence modules (handler-logic tests) ──────────────────────────


class _FakeLinuxPersist(AttackModule):
    name = "LinuxPersistence"
    description = "fake linux persistence"
    target_services = ["ssh"]
    target_ports = [22]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "script_generated",
            "module": self.name,
            "script": "print('PERSISTENCE_INSTALLED: cron')",
        }


class _FakeWebPersist(AttackModule):
    name = "WebShellPersistence"
    description = "fake webshell persistence"
    target_services = ["http", "https"]
    target_ports = [80, 443]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "script_generated",
            "module": self.name,
            "script": "print('PERSISTENCE_INSTALLED: webshell')",
        }


class _FakeWinPersist(AttackModule):
    name = "WindowsPersistence"
    description = "fake windows persistence"
    target_services = ["smb", "rdp"]
    target_ports = [445, 3389]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        return {
            "status": "script_generated",
            "module": self.name,
            "script": "print('PERSISTENCE_INSTALLED: schtask')",
        }


_FAKE_PERSIST: dict[str, AttackModule] = {
    "LinuxPersistence": _FakeLinuxPersist(),
    "WebShellPersistence": _FakeWebPersist(),
    "WindowsPersistence": _FakeWinPersist(),
}


def _fake_persist_get_module(name: str) -> AttackModule | None:
    return _FAKE_PERSIST.get(name)


# ── Fakes ───────────────────────────────────────────────────────────────────


class _ScopeResult:
    allowed: bool = True
    reason: str = "test-allow"


class _AllowScopeGate:
    def check_scope(self, *, asset, action_type=None, tool_name=None, risk_level=None):
        return _ScopeResult()


def _recon_linux_http() -> HostReconResult:
    return HostReconResult(
        target_ip="10.0.0.5",
        os_family="linux",
        services=[ServiceInfo(port=80, protocol="tcp", service="http"),
                  ServiceInfo(port=22, protocol="tcp", service="ssh")],
        open_ports=[80, 22],
    )


def _recon_windows() -> HostReconResult:
    return HostReconResult(
        target_ip="10.0.0.5",
        os_family="windows",
        services=[ServiceInfo(port=445, protocol="tcp", service="microsoft-ds")],
        open_ports=[445],
    )


def _persist_exec(script: str, ctx: dict[str, Any]) -> str:
    """Fake tool_executor: returns the canonical marker for the module name."""
    mod = (ctx or {}).get("module", "")
    return {
        "LinuxPersistence": "PERSISTENCE_INSTALLED: cron",
        "WebShellPersistence": "PERSISTENCE_INSTALLED: webshell",
        "WindowsPersistence": "PERSISTENCE_INSTALLED: schtask",
    }.get(mod, "")


def _timeline_types(state: AttackState) -> list[str]:
    return [e["event_type"] for e in state.timeline]


def _orch(
    tmp_path: Path,
    *,
    mission_config: dict[str, Any] | None = None,
    tool_executor=None,
) -> AutonomousOrchestrator:
    return AutonomousOrchestrator(
        mission_config=mission_config or {},
        workspace_root=tmp_path,
        tool_executor=tool_executor,
        scope_gate=_AllowScopeGate(),
    )


# ── 2.2 PERSISTENCE ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_persistence_records_methods_on_access(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With persistence_phase on + access achieved, _phase_persistence dispatches
    each OS/web module and records the confirmed method per the dispatch marker."""
    monkeypatch.setattr(orch_mod, "get_module", _fake_persist_get_module)
    orch = _orch(tmp_path, mission_config={"persistence_phase": True, "max_cycles": 5},
                 tool_executor=_persist_exec)
    state = orch.get_state("10.0.0.5")
    state.access_achieved = True
    state.recon_result = _recon_linux_http()  # linux + http -> Linux + WebShell

    await orch._phase_persistence(state)

    assert state.persistence_established == ["cron", "webshell"], \
        "linux+http must install cron (Linux) then webshell (WebShell)"
    assert "persistence_established" in _timeline_types(state)


@pytest.mark.asyncio
async def test_persistence_skipped_without_access(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No access -> _phase_persistence is a no-op: nothing dispatched, nothing recorded."""
    monkeypatch.setattr(orch_mod, "get_module", _fake_persist_get_module)
    captured: list[str] = []

    def _exec(script: str, ctx: dict[str, Any]) -> str:
        captured.append(script)
        return "PERSISTENCE_INSTALLED: cron"

    orch = _orch(tmp_path, mission_config={"persistence_phase": True}, tool_executor=_exec)
    state = orch.get_state("10.0.0.5")
    state.access_achieved = False
    state.recon_result = _recon_linux_http()

    await orch._phase_persistence(state)

    assert state.persistence_established == []
    assert captured == [], "no dispatch without access"


@pytest.mark.asyncio
async def test_persistence_skipped_without_tool_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No tool_executor -> the phase logs a skip and records nothing (best-effort)."""
    monkeypatch.setattr(orch_mod, "get_module", _fake_persist_get_module)
    orch = _orch(tmp_path, mission_config={"persistence_phase": True}, tool_executor=None)
    state = orch.get_state("10.0.0.5")
    state.access_achieved = True
    state.recon_result = _recon_linux_http()

    await orch._phase_persistence(state)

    assert state.persistence_established == []
    assert "persistence_skipped" in _timeline_types(state)


@pytest.mark.asyncio
async def test_persistence_off_by_default_in_attack_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """persistence_phase OFF (default) -> _attack_target must NOT run persistence
    even when access is achieved (the call-site gate, not the method, enforces it)."""
    # Real get_module would fail for exploitation modules; stub phases instead so
    # _attack_target exercises only the persistence call-site gate.
    orch = _orch(tmp_path, mission_config={"max_cycles": 5}, tool_executor=_persist_exec)

    async def _fake_recon(state: AttackState) -> None:
        state.recon_result = _recon_linux_http()

    async def _fake_exploit(state: AttackState) -> None:
        state.access_achieved = True  # would trigger persistence if the flag were on

    async def _noop(state: AttackState) -> None:
        return None

    orch._phase_reconnaissance = _fake_recon  # type: ignore[assignment]
    orch._phase_exploitation = _fake_exploit  # type: ignore[assignment]
    orch._phase_privilege_escalation = _noop  # type: ignore[assignment]
    orch._phase_lateral_movement = _noop  # type: ignore[assignment]
    orch._phase_validation = _noop  # type: ignore[assignment]
    state = orch.get_state("10.0.0.5")

    await orch._attack_target("10.0.0.5")

    assert state.access_achieved is True
    assert state.persistence_established == [], "persistence must NOT run when the flag is off"
    assert "persistence_established" not in _timeline_types(state)


@pytest.mark.asyncio
async def test_persistence_on_runs_in_attack_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """persistence_phase ON + access achieved -> _attack_target runs persistence."""
    monkeypatch.setattr(orch_mod, "get_module", _fake_persist_get_module)
    orch = _orch(tmp_path, mission_config={"persistence_phase": True, "max_cycles": 5},
                 tool_executor=_persist_exec)

    async def _fake_recon(state: AttackState) -> None:
        state.recon_result = _recon_linux_http()

    async def _fake_exploit(state: AttackState) -> None:
        state.access_achieved = True

    async def _noop(state: AttackState) -> None:
        return None

    orch._phase_reconnaissance = _fake_recon  # type: ignore[assignment]
    orch._phase_exploitation = _fake_exploit  # type: ignore[assignment]
    orch._phase_privilege_escalation = _noop  # type: ignore[assignment]
    orch._phase_lateral_movement = _noop  # type: ignore[assignment]
    orch._phase_validation = _noop  # type: ignore[assignment]
    state = orch.get_state("10.0.0.5")

    await orch._attack_target("10.0.0.5")

    assert state.persistence_established == ["cron", "webshell"]
    assert "persistence_established" in _timeline_types(state)


def test_extract_persistence_marker(tmp_path: Path) -> None:
    orch = _orch(tmp_path)
    assert orch._extract_persistence_marker("... PERSISTENCE_INSTALLED: cron ...") == "cron"
    assert orch._extract_persistence_marker("PERSISTENCE_INSTALLED: schtask") == "schtask"
    assert orch._extract_persistence_marker("no marker here") is None
    assert orch._extract_persistence_marker("") is None


# ── 2.3 CHECKPOINT ──────────────────────────────────────────────────────────


def _stub_all_phases_to_noop(orch: AutonomousOrchestrator, *, recon: Any = None) -> None:
    async def _default_recon(state: AttackState) -> None:
        state.recon_result = _recon_linux_http()

    async def _noop(state: AttackState) -> None:
        return None

    orch._phase_reconnaissance = recon or _default_recon  # type: ignore[assignment]
    orch._phase_exploitation = _noop  # type: ignore[assignment]
    orch._phase_privilege_escalation = _noop  # type: ignore[assignment]
    orch._phase_lateral_movement = _noop  # type: ignore[assignment]
    orch._phase_validation = _noop  # type: ignore[assignment]


@pytest.mark.asyncio
async def test_checkpoint_every_n_writes_state_file(tmp_path: Path) -> None:
    """checkpoint_every=2 -> attack_states.json is written during the campaign."""
    orch = _orch(tmp_path, mission_config={"checkpoint_every": 2, "max_cycles": 5})
    _stub_all_phases_to_noop(orch)

    state_path = tmp_path / "attack_states.json"
    assert not state_path.exists()

    await orch.run_autonomous_campaign(["10.0.0.5", "10.0.0.6", "10.0.0.7"])

    assert state_path.exists(), "checkpoint must have written attack_states.json"
    # The file must be valid JSON with the states payload. The checkpoint fires
    # at completed==2 (a multiple of checkpoint_every=2), so it captures the two
    # targets that had run by then; target 3 runs after and 3 is not a multiple
    # of 2, so no further checkpoint rewrites the file.
    import json
    data = json.loads(state_path.read_text(encoding="utf-8"))
    assert "states" in data and len(data["states"]) == 2


@pytest.mark.asyncio
async def test_checkpoint_off_writes_no_file_mid_campaign(tmp_path: Path) -> None:
    """checkpoint_every=0 (default) -> no periodic checkpoint file is written."""
    orch = _orch(tmp_path, mission_config={"max_cycles": 5})
    _stub_all_phases_to_noop(orch)

    state_path = tmp_path / "attack_states.json"
    await orch.run_autonomous_campaign(["10.0.0.5", "10.0.0.6"])
    assert not state_path.exists(), "no checkpoint when checkpoint_every is 0"


@pytest.mark.asyncio
async def test_crash_bounded_campaign_continues(tmp_path: Path) -> None:
    """A target whose _attack_target raises must not abort the campaign: the
    crashed target is recorded, the remaining targets still complete."""
    orch = _orch(tmp_path, mission_config={"max_cycles": 5})

    async def _recon(state: AttackState) -> None:
        if state.target == "10.0.0.6":
            raise RuntimeError("simulated target crash")
        state.recon_result = _recon_linux_http()

    _stub_all_phases_to_noop(orch, recon=_recon)

    result = await orch.run_autonomous_campaign(["10.0.0.5", "10.0.0.6", "10.0.0.7"])

    assert result["results"]["10.0.0.5"]["status"] == "complete"
    assert result["results"]["10.0.0.6"]["status"] == "crashed", \
        "the crashing target must be recorded as crashed, not abort the run"
    assert result["results"]["10.0.0.7"]["status"] == "complete"


# ── 2.4 ADAPTIVE REPLAN + VULN-CHAINING ─────────────────────────────────────


@pytest.mark.asyncio
async def test_adaptive_rounds_stop_when_should_continue_false(tmp_path: Path) -> None:
    """adaptive_replan on: one round sets access+root -> should_continue False
    -> exactly one adaptive_round event (loop terminates, no runaway)."""
    orch = _orch(tmp_path, mission_config={"adaptive_replan": True, "max_cycles": 5})

    async def _fake_recon(state: AttackState) -> None:
        state.recon_result = _recon_linux_http()

    async def _fake_exploit(state: AttackState, *, skip_failed: bool = False) -> None:
        state.access_achieved = True
        state.privilege_level = "root"
        state.successful_exploits.append("FakeExploit")

    async def _noop(state: AttackState) -> None:
        return None

    orch._phase_reconnaissance = _fake_recon  # type: ignore[assignment]
    orch._phase_exploitation = _fake_exploit  # type: ignore[assignment]
    orch._phase_privilege_escalation = _noop  # type: ignore[assignment]
    orch._phase_lateral_movement = _noop  # type: ignore[assignment]
    orch._phase_validation = _noop  # type: ignore[assignment]
    state = orch.get_state("10.0.0.5")

    await orch._attack_target("10.0.0.5")

    rounds = [e for e in state.timeline if e["event_type"] == "adaptive_round"]
    assert len(rounds) == 1, "should_continue False after round 1 -> exactly one round"
    # Vuln-chain scheduled from the successful exploit (no creds/pivots here -> 0 chains)
    assert "vuln_chain_scheduled" not in _timeline_types(state)


@pytest.mark.asyncio
async def test_adaptive_rounds_bounded_by_max_cycles(tmp_path: Path) -> None:
    """When should_continue stays True (never achieve access), the loop runs
    exactly max_cycles rounds and no more (the bound holds)."""
    orch = _orch(tmp_path, mission_config={"adaptive_replan": True, "max_cycles": 3})

    call_count = {"n": 0}

    async def _fake_recon(state: AttackState) -> None:
        state.recon_result = _recon_linux_http()

    async def _fake_exploit(state: AttackState, *, skip_failed: bool = False) -> None:
        call_count["n"] += 1
        # Add a novel task each round so the no-novel-candidate stop does not
        # fire; never achieve access so should_continue stays True and the loop
        # runs exactly max_cycles rounds (the bound under test).
        orch._tasks[f"fake-{call_count['n']}"] = AttackTask(
            task_id=f"fake-{call_count['n']}",
            phase=AttackPhase.EXPLOITATION,
            module_name="FakeExploit",
            target="10.0.0.5",
        )

    async def _noop(state: AttackState) -> None:
        return None

    orch._phase_reconnaissance = _fake_recon  # type: ignore[assignment]
    orch._phase_exploitation = _fake_exploit  # type: ignore[assignment]
    orch._phase_privilege_escalation = _noop  # type: ignore[assignment]
    orch._phase_lateral_movement = _noop  # type: ignore[assignment]
    orch._phase_validation = _noop  # type: ignore[assignment]
    state = orch.get_state("10.0.0.5")

    await orch._attack_target("10.0.0.5")

    rounds = [e for e in state.timeline if e["event_type"] == "adaptive_round"]
    assert len(rounds) == 3, "loop must be bounded by max_cycles"
    assert call_count["n"] == 3


def test_schedule_vuln_chain_records_chains(tmp_path: Path) -> None:
    """_schedule_vuln_chain links the last exploit -> creds/pivots into attack_paths."""
    orch = _orch(tmp_path)
    state = AttackState(target="10.0.0.5")
    state.successful_exploits = ["EternalBlue"]
    state.credentials_found = [{"user": "admin", "password": "pw"}]
    state.pivot_targets = ["10.0.0.99"]

    orch._schedule_vuln_chain(state)

    assert state.attack_paths, "attack_paths must be populated"
    # Chains anchor on the last successful exploit.
    assert all(path[0] == "exploit:EternalBlue" for path in state.attack_paths)
    flat = [step for path in state.attack_paths for step in path]
    assert any(s.startswith("pivot:10.0.0.99") for s in flat)
    assert "vuln_chain_scheduled" in _timeline_types(state)


def test_schedule_vuln_chain_noop_without_success(tmp_path: Path) -> None:
    """No successful exploits -> no chains, no timeline event."""
    orch = _orch(tmp_path)
    state = AttackState(target="10.0.0.5")
    state.pivot_targets = ["10.0.0.99"]  # pivots alone, no exploit to chain from

    orch._schedule_vuln_chain(state)

    assert state.attack_paths == []
    assert "vuln_chain_scheduled" not in _timeline_types(state)


# ── constructor flag wiring ─────────────────────────────────────────────────


def test_opt_in_flags_default_off(tmp_path: Path) -> None:
    """Bare mission_config -> all Phase 2 opt-in flags default OFF/0."""
    orch = _orch(tmp_path)
    assert orch._persistence_enabled is False
    assert orch._checkpoint_every == 0
    assert orch._adaptive_replan is False


def test_opt_in_flags_wired_from_mission_config(tmp_path: Path) -> None:
    """mission_config keys flow through to the orchestrator flags."""
    orch = _orch(tmp_path, mission_config={
        "persistence_phase": True, "checkpoint_every": 3, "adaptive_replan": True,
    })
    assert orch._persistence_enabled is True
    assert orch._checkpoint_every == 3
    assert orch._adaptive_replan is True