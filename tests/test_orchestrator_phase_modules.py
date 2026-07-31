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