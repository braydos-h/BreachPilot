"""Tests for the four orchestrator phase-level AttackModules.

Before this fix ``tools/autonomous_orchestrator.py`` referenced
``TokenImpersonation``/``ServiceMisconfiguration`` (privesc phase),
``LateralMovement`` (lateral phase), and ``ValidateFinding`` (validation
phase) -- none were in ``registry._MODULE_CLASSES``, so ``get_module(name)``
returned ``None`` and every privesc/lateral/validation task FAILED. These
tests prove the four modules are registered, instantiable, and return the
expected shape, and that ``get_module`` resolves them (the regression).
"""
from __future__ import annotations

import pytest

from tools.attack_modules.base import ModuleContext
from tools.attack_modules import registry
from tools.attack_modules.modules.orchestrator_phases import (
    TokenImpersonation,
    ServiceMisconfiguration,
    LateralMovement,
    ValidateFinding,
)


def test_four_phase_modules_registered() -> None:
    """All four previously-phantom names resolve via get_module (the bug fix)."""
    for name in ("TokenImpersonation", "ServiceMisconfiguration", "LateralMovement", "ValidateFinding"):
        mod = registry.get_module(name)
        assert mod is not None, f"{name} not in registry (phantom module regression)"
        assert mod.name == name


def test_four_phase_modules_in_module_classes() -> None:
    names = {cls.name for cls in registry._MODULE_CLASSES}
    assert {"TokenImpersonation", "ServiceMisconfiguration", "LateralMovement", "ValidateFinding"} <= names


def _ctx(target_ip: str = "10.0.0.50", services=None) -> ModuleContext:
    return ModuleContext(
        target_ip=target_ip,
        target_os="windows",
        services=services or [{"service": "microsoft-ds", "port": "445/tcp"}, {"service": "ms-wbt-server", "port": "3389/tcp"}],
    )


def test_token_impersonation_shape() -> None:
    mod = TokenImpersonation()
    res = mod.run(_ctx())
    assert res["status"] == "script_generated"
    assert res["module"] == "TokenImpersonation"
    assert "mimikatz" in res["script"]
    # Applicability: smb + ms-wbt-server present + ports 445/3389 -> high
    assert mod.applicability(_ctx()) >= 50


def test_service_misconfiguration_shape() -> None:
    mod = ServiceMisconfiguration()
    res = mod.run(_ctx())
    assert res["status"] == "script_generated"
    assert res["module"] == "ServiceMisconfiguration"
    assert "sc" in res["script"] and "qc" in res["script"]
    assert mod.applicability(_ctx()) >= 30


def test_lateral_movement_is_phase_only_and_target_locked() -> None:
    mod = LateralMovement()
    ctx = _ctx(target_ip="10.0.0.99")
    res = mod.run(ctx)
    assert res["status"] == "info"
    assert res["extra"].get("phase_only") is True
    # The suggested command must reference only the module's own target_ip.
    assert "10.0.0.99" in res["suggested_command"]
    # Phase-only modules declare no target_services -> service-match scoring is 0,
    # so they are never auto-selected by find_modules (orchestrator instantiates by name).
    assert mod.target_services == []


def test_validate_finding_is_phase_only_and_target_locked() -> None:
    mod = ValidateFinding()
    ctx = _ctx(target_ip="10.0.0.77")
    res = mod.run(ctx)
    assert res["status"] == "info"
    assert res["extra"].get("phase_only") is True
    assert "10.0.0.77" in res["suggested_command"]
    assert "whoami" in res["suggested_command"]
    assert mod.target_services == []


def test_phase_only_modules_not_auto_selected() -> None:
    """find_modules must NOT surface phase-only modules (no target_services) --
    they are instantiated by name by the orchestrator, not by service match."""
    ctx = _ctx()
    scored = registry.find_modules(ctx)
    names = {m.name for _, m in scored}
    assert "LateralMovement" not in names
    assert "ValidateFinding" not in names

# ── Phase 3: LocalExploitSuggester advisory module + orchestrator wiring ──────

from tools.attack_modules.modules.orchestrator_phases import LocalExploitSuggester


def test_local_exploit_suggester_registered() -> None:
    assert registry.get_module("LocalExploitSuggester") is not None
    assert "LocalExploitSuggester" in {cls.name for cls in registry._MODULE_CLASSES}


def test_local_exploit_suggester_is_advisory_info() -> None:
    mod = LocalExploitSuggester()
    res = mod.run(_ctx())
    assert res["status"] == "info"
    assert res["extra"].get("phase_only") is True
    assert res["extra"].get("requires_session") is True
    # It SUGGESTS the MSF recipe but must NOT fabricate a session id.
    assert "local_exploit_suggester" in res["suggested_command"]
    assert "<id" in res["suggested_command"]  # placeholder, not a real session id
    assert mod.target_services == []


def test_local_exploit_suggester_not_auto_selected() -> None:
    scored = registry.find_modules(_ctx())
    assert "LocalExploitSuggester" not in {m.name for _, m in scored}


def _orchestrator(mission_config, tmp_path):
    from tools.autonomous_orchestrator import AutonomousOrchestrator
    return AutonomousOrchestrator(mission_config, tmp_path)


def test_orchestrator_auto_les_flag_default_off(tmp_path) -> None:
    o = _orchestrator({"target": "10.0.0.1"}, tmp_path)
    assert o._auto_local_exploit_suggester is False


def test_orchestrator_auto_les_flag_from_msf_auto_les(tmp_path) -> None:
    o = _orchestrator({"target": "10.0.0.1", "msf_auto_les": True}, tmp_path)
    assert o._auto_local_exploit_suggester is True


def test_orchestrator_auto_les_flag_from_nested_msf_dict(tmp_path) -> None:
    o = _orchestrator({"target": "10.0.0.1", "msf": {"auto_local_exploit_suggester": True}}, tmp_path)
    assert o._auto_local_exploit_suggester is True


@pytest.mark.asyncio
async def test_privesc_phase_appends_les_when_access_achieved(tmp_path, monkeypatch) -> None:
    """When auto_les is on AND access_achieved, the privesc phase dispatches a
    LocalExploitSuggester info-task after the privesc batch. When access is NOT
    achieved, no LES task is dispatched."""
    from tools.autonomous_orchestrator import AttackState, AggressionLevel

    o = _orchestrator({"target": "10.0.0.1", "msf_auto_les": True}, tmp_path)
    state = AttackState(target="10.0.0.1", aggression=AggressionLevel.NORMAL)
    state.recon_result = None  # triggers the else-branch privesc module list

    executed: list[str] = []

    async def fake_execute(self, task, state):
        executed.append(task.module_name)
        task.status = __import__("tools.autonomous_orchestrator", fromlist=["TaskStatus"]).TaskStatus.COMPLETED
        return {"success": True}

    monkeypatch.setattr(
        "tools.autonomous_orchestrator.AttackModuleExecutor.execute", fake_execute
    )

    # Access NOT achieved -> no LES task.
    state.access_achieved = False
    executed.clear()
    await o._phase_privilege_escalation(state)
    assert "LocalExploitSuggester" not in executed

    # Access achieved -> LES task dispatched after the privesc batch.
    state.access_achieved = True
    executed.clear()
    await o._phase_privilege_escalation(state)
    assert "LocalExploitSuggester" in executed


@pytest.mark.asyncio
async def test_privesc_phase_no_les_when_flag_off(tmp_path, monkeypatch) -> None:
    from tools.autonomous_orchestrator import AttackState, AggressionLevel
    from tools.autonomous_orchestrator import TaskStatus

    o = _orchestrator({"target": "10.0.0.1"}, tmp_path)  # auto_les off
    assert o._auto_local_exploit_suggester is False
    state = AttackState(target="10.0.0.1", aggression=AggressionLevel.NORMAL)
    state.access_achieved = True
    state.recon_result = None

    executed: list[str] = []
    async def fake_execute(self, task, state):
        executed.append(task.module_name)
        task.status = TaskStatus.COMPLETED
        return {"success": True}
    monkeypatch.setattr("tools.autonomous_orchestrator.AttackModuleExecutor.execute", fake_execute)

    await o._phase_privilege_escalation(state)
    assert "LocalExploitSuggester" not in executed
