"""Tests for the persistence attack modules."""

from __future__ import annotations

from tools.attack_modules import ModuleContext
from tools.attack_modules.modules.persistence import (
    LinuxPersistence,
    WindowsPersistence,
    WebShellPersistence,
)
from tools.attack_modules.registry import list_modules


def _ctx() -> ModuleContext:
    return ModuleContext(target_ip="10.0.0.5", target_os="linux", services=[], cves=[])


def test_linux_persistence_script_has_marker() -> None:
    mod = LinuxPersistence()
    result = mod.run(_ctx())
    assert result["status"] == "script_generated"
    assert result["module"] == "LinuxPersistence"
    assert "PERSISTENCE_INSTALLED: cron" in result["script"]


def test_windows_persistence_script_has_marker() -> None:
    mod = WindowsPersistence()
    result = mod.run(_ctx())
    assert result["status"] == "script_generated"
    assert result["module"] == "WindowsPersistence"
    assert "PERSISTENCE_INSTALLED: schtask" in result["script"]


def test_webshell_persistence_script_has_marker() -> None:
    mod = WebShellPersistence()
    result = mod.run(_ctx())
    assert result["status"] == "script_generated"
    assert result["module"] == "WebShellPersistence"
    assert "PERSISTENCE_INSTALLED: webshell" in result["script"]


def test_persistence_modules_registered() -> None:
    names = [m.name for m in list_modules()]
    assert "LinuxPersistence" in names
    assert "WindowsPersistence" in names
    assert "WebShellPersistence" in names


def test_persistence_modules_have_target_metadata() -> None:
    for mod in (LinuxPersistence(), WindowsPersistence(), WebShellPersistence()):
        assert mod.target_services, f"{mod.name} has no target_services"
        assert mod.target_ports, f"{mod.name} has no target_ports"