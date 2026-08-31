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
- probe exceptions never crash resolution.
- disabled sandbox stays (None, "") regardless of fallback_native.
- status_report modes: disabled / contained / native_fallback / blocked.
- The notice is actionable (names the config key + remediation).
- Tool-layer ``sandbox_fallback_notice`` renders the SANDBOX_FALLBACK line
  from ctx.sandbox_notice and stays empty for configured host mode.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools.sandbox import docker_backend as _db
from tools.sandbox.manager import native_fallback_notice, resolve_manager_with_fallback, status_report
from tools.sandbox.models import SandboxConfig


def _cfg(**overrides: Any) -> dict[str, Any]:
    sec: dict[str, Any] = {"enabled": True, "image": "breachpilot-sandbox:latest"}
    sec.update(overrides)
    return {"sandbox": sec}


def _probe(ok: bool, reason: str = "docker down") -> Any:
    return lambda: (ok, reason)


# --------------------------------------------------------------- SandboxConfig


def test_fallback_native_defaults_true(monkeypatch: pytest.MonkeyPatch) -> None:
    assert SandboxConfig.from_config(_cfg()).fallback_native is True


def test_fallback_native_explicit_false(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = SandboxConfig.from_config(_cfg(fallback_native=False))
    assert cfg.fallback_native is False


def test_missing_sandbox_section_is_disabled_untouched() -> None:
    cfg = SandboxConfig.from_config({})
    assert cfg.enabled is False


# --------------------------------------------- resolve_manager_with_fallback


def test_docker_ok_image_ok_returns_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True, raising=False)
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(True, ""))
    assert manager is not None
    assert notice == ""


def test_docker_ok_image_missing_falls_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False, raising=False)
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(True, ""))
    assert manager is None
    assert "SANDBOX" in notice or "sandbox" in notice
    assert "not built" in notice


def test_docker_ok_image_missing_strict_returns_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # fallback_native=false: manager is returned; it fail-closes at execution.
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False, raising=False)
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(fallback_native=False), probe=_probe(True, ""))
    assert manager is not None
    assert notice == ""


def test_docker_down_falls_back(tmp_path: Path) -> None:
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(False, "docker daemon down"))
    assert manager is None
    assert "docker daemon down" in notice


def test_docker_down_strict_returns_manager(tmp_path: Path) -> None:
    manager, notice = resolve_manager_with_fallback(
        tmp_path, _cfg(fallback_native=False), probe=_probe(False, "docker daemon down")
    )
    assert manager is not None
    assert notice == ""


def test_probe_exception_never_crashes(tmp_path: Path) -> None:
    def boom() -> tuple[bool, str]:
        raise RuntimeError("cli exploded")

    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=boom)
    assert manager is None
    assert "probe failed" in notice


def test_disabled_returns_none_no_notice(tmp_path: Path) -> None:
    manager, notice = resolve_manager_with_fallback(tmp_path, {"sandbox": {"enabled": False}}, probe=_probe(False, "x"))
    assert manager is None
    assert notice == ""


def test_notice_is_actionable() -> None:
    notice = native_fallback_notice("docker daemon down")
    assert "fallback_native" in notice
    assert "sandbox.fallback_native: false" in notice
    assert "NATIVE" in notice or "native" in notice


# ---------------------------------------------------------------- status_report


def test_status_report_disabled_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    report = status_report({"sandbox": {"enabled": False}})
    assert report["mode"] == "disabled"
    assert report["fallback_native"] is True


def test_status_report_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", lambda: (True, ""), raising=False)
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True, raising=False)
    report = status_report(_cfg())
    assert report["mode"] == "contained"
    assert report["docker_available"] is True
    assert report["image_present"] is True
    assert report["fallback_reason"] == ""


def test_status_report_native_fallback_when_docker_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", lambda: (False, "daemon unreachable"), raising=False)
    report = status_report(_cfg())
    assert report["mode"] == "native_fallback"
    assert report["fallback_reason"] == "daemon unreachable"
    assert report["fallback_native"] is True


def test_status_report_blocked_when_strict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", lambda: (False, "daemon unreachable"), raising=False)
    report = status_report(_cfg(fallback_native=False))
    assert report["mode"] == "blocked"
    assert report["fallback_native"] is False


def test_status_report_native_fallback_when_image_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", lambda: (True, ""), raising=False)
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False, raising=False)
    report = status_report(_cfg())
    assert report["mode"] == "native_fallback"
    assert report["image_present"] is False
    assert "not built" in report["fallback_reason"]


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


def test_sandbox_fallback_notice_empty_for_configured_host_mode() -> None:
    from tools.mcp_tools.sandbox_exec import sandbox_fallback_notice

    class Ctx:
        sandbox = None
        sandbox_notice = ""  # sandbox disabled as configured, not degraded

    class CtxNoAttr:
        sandbox = None  # legacy FakeCtx duck-typing: no sandbox_notice at all

    assert sandbox_fallback_notice(Ctx()) == ""
    assert sandbox_fallback_notice(CtxNoAttr()) == ""
