"""Tests for the boot-time sandbox native fallback (tools/sandbox/manager.py).

The single sanctioned fallback: with ``sandbox.fallback_native`` true (the
default), a server whose Docker stack is unusable at boot degrades WHOLLY to
the documented legacy host-execution mode -- ``(None, notice)`` -- instead of
failing every execution closed. ``false`` restores the strict fail-closed
contract (a manager is returned either way and blocks at execution time).

Covered invariants:
- ``fallback_native`` defaults to true; explicit false parses.
- resolve_manager_with_fallback: docker ok + image ok => manager, no notice.
- docker ok + image missing => (None, notice) with fallback_native, manager
  (that fail-closes later) without it.
- docker down => same split.
- probe exceptions never crash resolution (both the docker and image probes).
- disabled sandbox stays (None, "") regardless of fallback_native.
- The boot decision is recorded to the shared boot-state file, and
  status_report reports THAT decision even when a live Docker probe would
  say something else (the session posture never flips mid-session).
- status_report live fallback modes (no boot state): disabled / contained /
  native_fallback / blocked; probe exceptions never throw.
- The notice is actionable (names the config key + remediation).
- Tool-layer ``sandbox_fallback_notice`` renders the SANDBOX_FALLBACK line
  from ctx.sandbox_notice and stays empty for configured host mode.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.sandbox import docker_backend as _db
from tools.sandbox import manager as _mgr
from tools.sandbox.manager import (
    native_fallback_notice,
    read_boot_state,
    resolve_manager_with_fallback,
    status_report,
)
from tools.sandbox.models import SandboxConfig


def _cfg(**overrides: Any) -> dict[str, Any]:
    sec: dict[str, Any] = {"enabled": True, "image": "breachpilot-sandbox:latest"}
    sec.update(overrides)
    return {"sandbox": sec}


def _probe(ok: bool, reason: str = "docker down") -> Any:
    return lambda: (ok, reason)


@pytest.fixture(autouse=True)
def _hermetic_boot_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Route boot-state writes/reads into tmp_path: tests must never read a
    real session's boot file or write one into the repo (both processes
    resolve boot_state_path(config) the same way in production; pinning it
    here keeps the suite hermetic on any box)."""
    boot_path = tmp_path / "sandbox_boot_state.json"
    monkeypatch.setattr(_mgr, "boot_state_path", lambda config=None: boot_path)
    return boot_path


# --------------------------------------------------------------- SandboxConfig


def test_fallback_native_defaults_true() -> None:
    assert SandboxConfig.from_config(_cfg()).fallback_native is True


def test_fallback_native_explicit_false() -> None:
    cfg = SandboxConfig.from_config(_cfg(fallback_native=False))
    assert cfg.fallback_native is False


def test_missing_sandbox_section_is_disabled_untouched() -> None:
    cfg = SandboxConfig.from_config({})
    assert cfg.enabled is False


# --------------------------------------------- resolve_manager_with_fallback


def test_docker_ok_image_ok_returns_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(True, ""))
    assert manager is not None
    assert notice == ""
    state = read_boot_state(_cfg())
    assert state is not None
    assert state["mode"] == "contained"
    assert state["reason"] == ""


def test_docker_ok_image_missing_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False)
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(True, ""))
    assert manager is None
    assert "SANDBOX" in notice or "sandbox" in notice
    assert "not built" in notice
    assert read_boot_state(_cfg())["mode"] == "native_fallback"


def test_docker_ok_image_missing_strict_returns_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # fallback_native=false: manager is returned; it fail-closes at execution.
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False)
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(fallback_native=False), probe=_probe(True, ""))
    assert manager is not None
    assert notice == ""
    assert read_boot_state(_cfg())["mode"] == "blocked"


def test_docker_down_falls_back(tmp_path: Path) -> None:
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(False, "docker daemon down"))
    assert manager is None
    assert "docker daemon down" in notice
    assert read_boot_state(_cfg())["mode"] == "native_fallback"


def test_docker_down_strict_returns_manager(tmp_path: Path) -> None:
    manager, notice = resolve_manager_with_fallback(
        tmp_path, _cfg(fallback_native=False), probe=_probe(False, "docker daemon down")
    )
    assert manager is not None
    assert notice == ""
    # Strict + unusable: recorded as blocked (the manager fail-closes later).
    assert read_boot_state(_cfg())["mode"] == "blocked"


def test_probe_exception_never_crashes(tmp_path: Path) -> None:
    def boom() -> tuple[bool, str]:
        raise RuntimeError("cli exploded")

    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=boom)
    assert manager is None
    assert "probe failed" in notice


def test_image_probe_generic_exception_degrades_not_crashes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The image seam may raise ANYTHING (it is a documented monkeypatch seam);
    # boot must still resolve to a loud native fallback, never crash and never
    # a silent empty-notice degrade.
    def boom(image: str) -> bool:
        raise OSError("probe seam exploded")

    monkeypatch.setattr(_db, "docker_image_exists", boom)
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(True, ""))
    assert manager is None
    assert "image probe failed" in notice
    assert read_boot_state(_cfg())["mode"] == "native_fallback"


def test_disabled_returns_none_no_notice(tmp_path: Path) -> None:
    manager, notice = resolve_manager_with_fallback(tmp_path, {"sandbox": {"enabled": False}}, probe=_probe(False, "x"))
    assert manager is None
    assert notice == ""
    assert read_boot_state({"sandbox": {"enabled": False}}) is None


def test_notice_is_actionable() -> None:
    notice = native_fallback_notice("docker daemon down")
    assert "fallback_native" in notice
    assert "sandbox.fallback_native: false" in notice
    assert "NATIVE" in notice or "native" in notice


# ---------------------------------------------------------------- status_report


def test_status_report_disabled_mode() -> None:
    report = status_report({"sandbox": {"enabled": False}})
    assert report["mode"] == "disabled"
    assert report["fallback_native"] is True


def test_status_report_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", lambda: (True, ""))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    report = status_report(_cfg())
    assert report["mode"] == "contained"
    assert report["docker_available"] is True
    assert report["image_present"] is True
    assert report["fallback_reason"] == ""


def test_status_report_native_fallback_when_docker_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", lambda: (False, "daemon unreachable"))
    report = status_report(_cfg())
    assert report["mode"] == "native_fallback"
    assert report["fallback_reason"] == "daemon unreachable"
    assert report["fallback_native"] is True


def test_status_report_blocked_when_strict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", lambda: (False, "daemon unreachable"))
    report = status_report(_cfg(fallback_native=False))
    assert report["mode"] == "blocked"
    assert report["fallback_native"] is False


def test_status_report_native_fallback_when_image_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", lambda: (True, ""))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False)
    report = status_report(_cfg())
    assert report["mode"] == "native_fallback"
    assert report["image_present"] is False
    assert "not built" in report["fallback_reason"]


def test_status_report_probe_exception_never_throws(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> tuple[bool, str]:
        raise OSError("status seam exploded")

    monkeypatch.setattr(_db, "docker_version", boom)
    report = status_report(_cfg())
    assert report["docker_available"] is False
    assert report["mode"] == "native_fallback"
    assert "status seam exploded" in report["fallback_reason"]


# --------------------------------------- status_report: boot decision is truth


def test_status_report_prefers_boot_decision_over_live_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _hermetic_boot_state: Path
) -> None:
    # Session booted native_fallback; the operator started Docker after.
    # The banner must NOT flip green for the running session.
    _hermetic_boot_state.write_text(
        json.dumps({"mode": "native_fallback", "reason": "boot-time daemon down", "recorded_at": 1.0}), encoding="utf-8"
    )
    monkeypatch.setattr(_db, "docker_version", lambda: (True, ""))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    report = status_report(_cfg())
    assert report["mode"] == "native_fallback"
    assert report["fallback_reason"] == "boot-time daemon down"
    # Live probe still fills the remediation fields.
    assert report["docker_available"] is True


def test_status_report_boot_contained_survives_later_docker_death(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _hermetic_boot_state: Path
) -> None:
    # Session booted contained; Docker dies mid-session => in-session commands
    # fail closed, they do NOT silently degrade. The banner must not claim
    # native execution.
    _hermetic_boot_state.write_text(
        json.dumps({"mode": "contained", "reason": "", "recorded_at": 1.0}), encoding="utf-8"
    )
    monkeypatch.setattr(_db, "docker_version", lambda: (False, "daemon died"))
    report = status_report(_cfg())
    assert report["mode"] == "contained"
    assert report["docker_error"] == "daemon died"


def test_status_report_ignores_invalid_boot_state(monkeypatch: pytest.MonkeyPatch, _hermetic_boot_state: Path) -> None:
    _hermetic_boot_state.write_text(json.dumps({"mode": "garbage", "reason": "", "recorded_at": 1.0}), encoding="utf-8")
    monkeypatch.setattr(_db, "docker_version", lambda: (True, ""))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    report = status_report(_cfg())
    assert report["mode"] == "contained"


def test_boot_state_round_trip_via_resolver(tmp_path: Path) -> None:
    resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(False, "no daemon"))
    state = read_boot_state(_cfg())
    assert state is not None
    assert state["mode"] == "native_fallback"
    assert "no daemon" in state["reason"]


# --------------------------------------------- tool-layer SANDBOX_FALLBACK line


def test_sandbox_fallback_notice_line_from_ctx() -> None:
    from tools.mcp_tools.sandbox_exec import sandbox_fallback_notice

    class Ctx:
        sandbox = None
        sandbox_notice = "Docker sandbox unavailable (docker daemon down) -- ..."

    line = sandbox_fallback_notice(Ctx())
    assert line.startswith("SANDBOX_FALLBACK: ")
    assert line.endswith("\n")
    assert "docker daemon down" in line


def test_read_boot_state_never_raises_on_corrupt_file(_hermetic_boot_state: Path) -> None:
    # Regression for the narrowed catches in read_boot_state: garbage,
    # wrong-shaped JSON, and unreadable files all mean "no state" (None),
    # never an exception on the attack path.
    _hermetic_boot_state.write_text("{not json", encoding="utf-8")
    assert read_boot_state(_cfg()) is None
    _hermetic_boot_state.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    assert read_boot_state(_cfg()) is None
    _hermetic_boot_state.write_text(json.dumps({"mode": "bogus"}), encoding="utf-8")
    assert read_boot_state(_cfg()) is None
    _hermetic_boot_state.unlink()
    assert read_boot_state(_cfg()) is None


def test_sandbox_fallback_notice_empty_for_configured_host_mode() -> None:
    from tools.mcp_tools.sandbox_exec import sandbox_fallback_notice

    class Ctx:
        sandbox = None
        sandbox_notice = ""  # sandbox disabled as configured, not degraded

    class CtxNoAttr:
        sandbox = None  # legacy FakeCtx duck-typing: no sandbox_notice at all

    assert sandbox_fallback_notice(Ctx()) == ""
    assert sandbox_fallback_notice(CtxNoAttr()) == ""
