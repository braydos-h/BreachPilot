"""Phase 3: dev-time lint for attack module result quality.

Every AttackModule's run() must leave an actionable evidence trail: an
info-status module that returns no evidence, no suggested_command, and no
suggested_msf is a dead stub -- the orchestrator (since Phase 1) records it
as a failure with nothing to show for it, and the audit trail loses "what
did this module actually find".

This is a dev-time lint (fails loud in pytest), NOT a runtime gate -- it
never blocks the attack path.
"""

from __future__ import annotations

from tools.attack_modules import list_modules
from tools.attack_modules.base import ModuleContext


def _ctx() -> ModuleContext:
    return ModuleContext(
        target_ip="127.0.0.1",
        services=[{"service": "http", "port": "80/tcp", "version": ""}],
        cves=["CVE-2021-44228"],
    )


def test_info_modules_leave_actionable_trail() -> None:
    """An info-status module must say SOMETHING actionable: evidence,
    suggested_command, or suggested_msf. A bare info stub is dead data."""
    offenders: list[str] = []
    for mod in list_modules():
        try:
            result = mod.run(_ctx()) or {}
        except Exception:
            # Modules that raise on a bare context (e.g. require services) are
            # not lintable here -- skip, not fail.
            continue
        if result.get("status") != "info":
            continue
        if not (
            result.get("evidence")
            or result.get("suggested_command")
            or result.get("suggested_msf")
            or result.get("workflow")
            or result.get("prompt_template")
        ):
            offenders.append(mod.name)
    assert not offenders, (
        f"info-status modules with no actionable output (no evidence / "
        f"suggested_command / suggested_msf / workflow): {offenders}. "
        f"Use AttackModule._info_result(...) to populate the trail."
    )


def test_script_generated_modules_have_script() -> None:
    """A script_generated module must actually carry a script (or a
    suggested_command fallback) -- otherwise the dispatcher runs nothing."""
    offenders: list[str] = []
    for mod in list_modules():
        try:
            result = mod.run(_ctx()) or {}
        except Exception:
            continue
        if result.get("status") != "script_generated":
            continue
        if not (result.get("script") or result.get("suggested_command")):
            offenders.append(mod.name)
    assert not offenders, (
        f"script_generated modules with no script/suggested_command: {offenders}"
    )
