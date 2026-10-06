"""Regression coverage for the sandbox's fail-closed boot contract.

The historical test filename is retained so existing test selection remains
stable. Native fallback is unsupported: disabling containment or requesting a
host-execution fallback is rejected, and an unavailable worker is recorded as
blocked.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.sandbox import docker_backend as _db
from tools.sandbox import manager as _mgr
from tools.sandbox.manager import read_boot_state, resolve_manager_with_fallback, status_report
from tools.sandbox.models import SandboxConfig


def _cfg(**overrides: Any) -> dict[str, Any]:
    section: dict[str, Any] = {"enabled": True, "image": "breachpilot-sandbox:latest"}
    section.update(overrides)
    return {"sandbox": section}


def _probe(ok: bool, reason: str = "docker down"):
    return lambda: (ok, reason)


@pytest.fixture(autouse=True)
def _hermetic_boot_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    boot_path = tmp_path / "sandbox_boot_state.json"
    monkeypatch.setattr(_mgr, "boot_state_path", lambda config=None: boot_path)
    return boot_path


def test_fallback_native_defaults_false() -> None:
    assert SandboxConfig.from_config(_cfg()).fallback_native is False


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"sandbox": {"enabled": False}}, "sandbox.enabled=false is unsafe"),
        (_cfg(fallback_native=True), "sandbox.fallback_native is unsupported"),
    ],
)
def test_unsafe_legacy_modes_are_rejected(config: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        SandboxConfig.from_config(config)


def test_missing_sandbox_section_uses_contained_defaults() -> None:
    assert SandboxConfig.from_config({}).enabled is True


def test_unsafe_legacy_modes_are_rejected_by_direct_construction() -> None:
    with pytest.raises(ValueError, match="sandbox.enabled=false is unsafe"):
        SandboxConfig(enabled=False, backend="docker", image="worker", user="sandbox", read_only_rootfs=True)
    with pytest.raises(ValueError, match="fallback_native is unsupported"):
        SandboxConfig(
            enabled=True,
            backend="docker",
            image="worker",
            user="sandbox",
            read_only_rootfs=True,
            fallback_native=True,
        )


def test_healthy_worker_resolves_contained_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)

    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(True, ""))

    assert manager is not None
    assert notice == ""
    state = read_boot_state(_cfg())
    assert state is not None
    assert state["mode"] == "contained"
    assert state["reason"] == ""


def test_missing_docker_resolves_manager_but_records_blocked(tmp_path: Path) -> None:
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(False, "daemon unavailable"))

    assert manager is not None
    assert notice == ""
    state = read_boot_state(_cfg())
    assert state is not None
    assert state["mode"] == "blocked"
    assert state["reason"] == "daemon unavailable"


def test_missing_worker_image_records_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False)

    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(True, ""))

    assert manager is not None
    assert notice == ""
    state = read_boot_state(_cfg())
    assert state is not None
    assert state["mode"] == "blocked"
    assert "not built" in state["reason"]


def test_image_probe_exception_resolves_to_blocked_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_image_probe(_image: str) -> bool:
        raise OSError("image probe failed")

    monkeypatch.setattr(_db, "docker_image_exists", broken_image_probe)
    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=_probe(True, ""))

    assert manager is not None
    assert notice == ""
    state = read_boot_state(_cfg())
    assert state is not None
    assert state["mode"] == "blocked"
    assert "image probe failed" in state["reason"]


def test_probe_exceptions_resolve_to_blocked_without_crashing(tmp_path: Path) -> None:
    def broken_probe() -> tuple[bool, str]:
        raise OSError("daemon probe failed")

    manager, notice = resolve_manager_with_fallback(tmp_path, _cfg(), probe=broken_probe)

    assert manager is not None
    assert notice == ""
    state = read_boot_state(_cfg())
    assert state is not None
    assert state["mode"] == "blocked"
    assert "daemon probe failed" in state["reason"]


@pytest.mark.parametrize(
    ("config", "reason"),
    [
        ({"sandbox": {"enabled": False}}, "sandbox.enabled=false is unsafe"),
        (_cfg(fallback_native=True), "sandbox.fallback_native is unsupported"),
    ],
)
def test_status_report_invalid_legacy_config_is_blocked(
    config: dict[str, Any], reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_db, "docker_version", _probe(True, ""))

    report = status_report(config)

    assert report["mode"] == "blocked"
    assert report["fallback_native"] is False
    assert reason in report["fallback_reason"]


def test_status_report_reports_contained_or_blocked_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", _probe(False, "daemon unreachable"))

    report = status_report(_cfg())

    assert report["mode"] == "blocked"
    assert report["fallback_native"] is False
    assert report["fallback_reason"] == "daemon unreachable"


def test_status_report_live_probe_can_report_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", _probe(True, ""))
    monkeypatch.setattr(_db, "docker_image_exists", lambda _image: True)

    report = status_report(_cfg())

    assert report["mode"] == "contained"
    assert report["docker_available"] is True
    assert report["image_present"] is True


def test_status_report_live_probe_reports_missing_image_as_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_db, "docker_version", _probe(True, ""))
    monkeypatch.setattr(_db, "docker_image_exists", lambda _image: False)

    report = status_report(_cfg())

    assert report["mode"] == "blocked"
    assert report["image_present"] is False
    assert "not built" in report["fallback_reason"]


def test_status_report_probe_exception_never_throws(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_probe() -> tuple[bool, str]:
        raise OSError("status probe failed")

    monkeypatch.setattr(_db, "docker_version", broken_probe)

    report = status_report(_cfg())

    assert report["mode"] == "blocked"
    assert report["docker_available"] is False
    assert "status probe failed" in report["docker_error"]


def test_status_report_preserves_boot_decision_after_live_probe_changes(
    _hermetic_boot_state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _hermetic_boot_state.write_text(
        json.dumps({"mode": "contained", "reason": "", "recorded_at": 1.0}), encoding="utf-8"
    )
    monkeypatch.setattr(_db, "docker_version", _probe(False, "daemon died"))

    report = status_report(_cfg())

    assert report["mode"] == "contained"
    assert report["docker_error"] == "daemon died"


def test_status_report_does_not_green_a_blocked_boot_after_docker_recovers(
    _hermetic_boot_state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _hermetic_boot_state.write_text(
        json.dumps({"mode": "blocked", "reason": "worker was absent at boot", "recorded_at": 1.0}),
        encoding="utf-8",
    )
    monkeypatch.setattr(_db, "docker_version", _probe(True, ""))
    monkeypatch.setattr(_db, "docker_image_exists", lambda _image: True)

    report = status_report(_cfg())

    assert report["mode"] == "blocked"
    assert report["fallback_reason"] == "worker was absent at boot"


def test_corrupt_boot_state_is_ignored(_hermetic_boot_state: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hermetic_boot_state.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(_db, "docker_version", _probe(False, "daemon unavailable"))

    assert read_boot_state(_cfg()) is None
    assert status_report(_cfg())["mode"] == "blocked"


@pytest.mark.parametrize("raw_state", ["[1, 2, 3]", "null", '{"mode": "unknown"}'])
def test_wrong_shape_or_unknown_boot_state_is_ignored(
    _hermetic_boot_state: Path, monkeypatch: pytest.MonkeyPatch, raw_state: str
) -> None:
    _hermetic_boot_state.write_text(raw_state, encoding="utf-8")
    monkeypatch.setattr(_db, "docker_version", _probe(True, ""))
    monkeypatch.setattr(_db, "docker_image_exists", lambda _image: True)

    assert read_boot_state(_cfg()) is None
    assert status_report(_cfg())["mode"] == "contained"
