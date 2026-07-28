"""Tests for wiring the plugin singleton into core registries.

Verifies the additive plugin consult in:
- tools/attack_modules/registry.py (list_modules / get_module / find_modules)
- tools/config_manager.py (ConfigValidator unknown-key handling + plugins schema)
- tools/skill_registry.py (load_skill_registry root merging)
- mcp_exploit_server.py (create_mcp_server plugin MCP tool factories)
- main.py (--list-plugins argparse flag)

All tests are hermetic: no real network, no real filesystem entry points, no
real MCP server over a socket. A fresh ``PluginRegistry`` is used and the
module-level ``PLUGIN_REGISTRY`` singleton is monkeypatched where the wired
code reads it.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from tools.attack_modules.base import AttackModule, ModuleContext
from tools.attack_modules.registry import find_modules, get_module, list_modules
from tools.plugins import (
    PLUGIN_REGISTRY,
    PluginRegistry,
    list_discovered_plugins,
)


# ─── helpers ──────────────────────────────────────────────────────────────────

class _DummyMod(AttackModule):
    name = "plugin-dummy-mod"
    description = "plugin-registered test module"
    target_services = ["plugin-svc"]
    target_ports = [9999]

    def run(self, ctx: ModuleContext) -> dict[str, Any]:  # noqa: ARG002
        return {"status": "info", "module": self.name}


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Isolate every test from the module-level singleton."""
    PLUGIN_REGISTRY.reset()
    from tools import plugins as plugins_mod
    plugins_mod._reset_discovered()
    yield
    PLUGIN_REGISTRY.reset()
    plugins_mod._reset_discovered()


def _set_singleton(reg: PluginRegistry, monkeypatch) -> None:
    """Point tools.plugins.PLUGIN_REGISTRY at ``reg`` so wired code sees it."""
    monkeypatch.setattr("tools.plugins.PLUGIN_REGISTRY", reg)
    # attack_modules/registry + config_manager + skill_registry import
    # PLUGIN_REGISTRY lazily from tools.plugins, so patching the attribute is
    # enough; they re-read it each call.


# ─── attack_modules registry ──────────────────────────────────────────────────

def test_list_modules_includes_plugin_module(monkeypatch):
    reg = PluginRegistry()
    reg.register_attack_module(_DummyMod)
    _set_singleton(reg, monkeypatch)

    names = {m.name for m in list_modules()}
    assert "plugin-dummy-mod" in names
    # built-ins still present (additive consult did not drop them)
    assert "Log4jRCE" in names or any(n.lower() == "log4jrce" for n in names)


def test_list_modules_reset_removes_plugin_module(monkeypatch):
    reg = PluginRegistry()
    reg.register_attack_module(_DummyMod)
    _set_singleton(reg, monkeypatch)
    assert "plugin-dummy-mod" in {m.name for m in list_modules()}

    reg.reset()
    _set_singleton(reg, monkeypatch)
    assert "plugin-dummy-mod" not in {m.name for m in list_modules()}


def test_get_module_finds_plugin_module(monkeypatch):
    reg = PluginRegistry()
    reg.register_attack_module(_DummyMod)
    _set_singleton(reg, monkeypatch)

    found = get_module("plugin-dummy-mod")
    assert found is not None
    assert found.name == "plugin-dummy-mod"
    # case-insensitive
    assert get_module("PLUGIN-DUMMY-MOD") is not None


def test_get_module_returns_none_for_unknown(monkeypatch):
    reg = PluginRegistry()
    _set_singleton(reg, monkeypatch)
    assert get_module("does-not-exist-plugin") is None


def test_find_modules_returns_plugin_when_applicable(monkeypatch):
    reg = PluginRegistry()
    reg.register_attack_module(_DummyMod)
    _set_singleton(reg, monkeypatch)

    ctx = ModuleContext(
        target_ip="10.0.0.5",
        services=[{"service": "plugin-svc", "port": "9999/tcp", "version": "1.0"}],
    )
    scored = find_modules(ctx)
    names = [m.name for _, m in scored]
    assert "plugin-dummy-mod" in names
    # the plugin module has a positive score
    score = [s for s, m in scored if m.name == "plugin-dummy-mod"][0]
    assert score > 0


def test_plugin_consult_noop_when_empty(monkeypatch):
    """list_modules baseline unchanged when no plugins registered."""
    reg = PluginRegistry()
    _set_singleton(reg, monkeypatch)
    baseline = {m.name for m in list_modules()}
    # registering nothing -> same set
    assert {m.name for m in list_modules()} == baseline


def test_plugin_import_failure_does_not_break_list_modules(monkeypatch):
    """If tools.plugins cannot be imported, list_modules still returns built-ins."""
    import builtins

    real_import = builtins.__import__

    def _boom(name, *args, **kwargs):
        if name == "tools.plugins":
            raise ImportError("simulated plugins import failure")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _boom)
    modules = list_modules()
    assert modules  # built-ins still present
    assert all(m.name != "plugin-dummy-mod" for m in modules)


# ─── config_manager ───────────────────────────────────────────────────────────

def _validator_with(config: dict[str, Any]):
    from tools.config_manager import ConfigValidator
    v = ConfigValidator("config.yaml")
    v._config = config
    return v


def test_config_validator_flags_unknown_plugin_key_before_registration():
    # Ensure the singleton has no "myplug" section registered.
    v = _validator_with({"ollama": {"host": "http://localhost:11434"}, "myplug": {"x": 1}})
    result = v.validate()
    assert "myplug" in result.unknown_keys


def test_config_validator_accepts_plugin_section_after_registration(monkeypatch):
    reg = PluginRegistry()
    reg.register_config_section("myplug", {"x": {"type": "int"}})
    _set_singleton(reg, monkeypatch)

    v = _validator_with({"ollama": {"host": "http://localhost:11434"}, "myplug": {"x": 1}})
    result = v.validate()
    assert "myplug" not in result.unknown_keys


def test_config_schema_has_plugins_block():
    from tools.config_manager import CONFIG_SCHEMA, KNOWN_TOP_KEYS
    assert "plugins" in CONFIG_SCHEMA
    plugins = CONFIG_SCHEMA["plugins"]
    assert plugins["enabled"] == []
    assert plugins["disabled"] == []
    assert plugins["search_paths"] == ["plugins"]
    assert plugins["entry_points"] is True
    assert "plugins" in KNOWN_TOP_KEYS


def test_config_validator_plugins_block_not_unknown():
    """The built-in 'plugins' top-level key is known and never warned."""
    v = _validator_with({"plugins": {"enabled": ["foo"]}})
    result = v.validate()
    assert "plugins" not in result.unknown_keys


# ─── skill_registry ───────────────────────────────────────────────────────────

def _write_skill(root: Path, name: str) -> Path:
    sdir = root / name
    sdir.mkdir(parents=True, exist_ok=True)
    path = sdir / "SKILL.md"
    path.write_text(
        "---\n"
        f"name: {name}\n"
        "description: plugin skill\n"
        "domain: cybersecurity\n"
        "---\n# Skill\n\nbody\n",
        encoding="utf-8",
    )
    return path


def test_load_skill_registry_walks_plugin_skill_dir(monkeypatch, tmp_path):
    plugin_skills = tmp_path / "plugin_skills"
    _write_skill(plugin_skills, "plugin-skill")

    reg = PluginRegistry()
    reg.register_skill_dir(plugin_skills)
    _set_singleton(reg, monkeypatch)

    from tools.skill_registry import load_skill_registry
    # An empty (non-existent) baseline root so only the plugin dir contributes.
    registry = load_skill_registry([tmp_path / "empty_baseline"], base_dir=tmp_path)
    assert registry.get("plugin-skill") is not None
    assert plugin_skills.resolve() in {Path(p) for p in registry.roots}


def test_load_skill_registry_dedups_plugin_dir_already_in_roots(monkeypatch, tmp_path):
    plugin_skills = tmp_path / "plugin_skills"
    _write_skill(plugin_skills, "plugin-skill")

    reg = PluginRegistry()
    reg.register_skill_dir(plugin_skills)
    _set_singleton(reg, monkeypatch)

    from tools.skill_registry import load_skill_registry
    registry = load_skill_registry([plugin_skills], base_dir=tmp_path)
    # the plugin skill is discovered exactly once
    assert registry.get("plugin-skill") is not None
    # roots contains the dir exactly once (no duplicate walk)
    roots = [Path(p) for p in registry.roots]
    assert roots.count(plugin_skills.resolve()) == 1


# ─── list_discovered_plugins ─────────────────────────────────────────────────

def test_list_discovered_plugins_shape_and_loaded_flag(tmp_path):
    from tools.plugins import load_plugins

    # write two plugins: one enabled, one not
    def _mk(name: str, enabled: bool) -> None:
        pdir = tmp_path / name
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "plugin.yaml").write_text(
            f"name: {name}\nversion: '1.0.0'\ndescription: desc-{name}\n"
            "capabilities:\n  - attack_module\n"
            f"enabled: {'true' if enabled else 'false'}\n",
            encoding="utf-8",
        )

    _mk("alpha", enabled=True)
    _mk("beta", enabled=False)

    load_plugins(
        {"plugins": {"enabled": ["alpha"], "search_paths": [str(tmp_path)], "entry_points": False}},
        entry_point_loader=lambda group: [],
    )
    listed = list_discovered_plugins()
    by_name = {d["name"]: d for d in listed}
    assert set(by_name) == {"alpha", "beta"}
    alpha = by_name["alpha"]
    assert set(alpha.keys()) == {"name", "version", "description", "capabilities", "loaded"}
    assert alpha["loaded"] is True
    assert by_name["beta"]["loaded"] is False
    assert alpha["capabilities"] == ["attack_module"]


def test_list_discovered_plugins_empty():
    assert list_discovered_plugins() == []


# ─── main.py --list-plugins ───────────────────────────────────────────────────

def test_list_plugins_argparse_flag_accepted():
    """parse_args accepts --list-plugins and sets list_plugins=True."""
    from main import parse_args
    args = parse_args(["--list-plugins", "--target", "10.0.0.1"])
    assert getattr(args, "list_plugins", False) is True


def test_list_plugins_flag_absent_defaults_false():
    from main import parse_args
    args = parse_args(["--target", "10.0.0.1"])
    assert getattr(args, "list_plugins", False) is False


def test_list_plugins_source_string_present():
    """Smoke guard: the --list-plugins flag is wired in main.py source."""
    src = Path(__file__).resolve().parent.parent / "main.py"
    text = src.read_text(encoding="utf-8")
    assert "--list-plugins" in text
    assert "list_discovered_plugins" in text


# ─── mcp_exploit_server plugin MCP tool factories ────────────────────────────

def test_create_mcp_server_invokes_plugin_mcp_factories(monkeypatch, tmp_path):
    """create_mcp_server calls plugin-registered mcp tool factories."""
    # Neutralize every built-in register_*_tools so the only thing exercised is
    # the plugin consult block. They all accept (mcp, *, ctx) or (mcp, ctx=...).
    import mcp_exploit_server as srv

    for fn_name in [
        "register_runtime_skill_tools", "register_peer_model_tools",
        "register_terminal_tools", "register_workspace_tools",
        "register_research_tools", "register_metasploit_tools",
        "register_credential_tools", "register_recon_tools",
        "register_payload_tools", "register_attack_module_tools",
        "register_session_tools",
    ]:
        monkeypatch.setattr(srv, fn_name, lambda mcp, *, ctx=None: None)

    # Stub the workspace helpers that create_mcp_server calls.
    monkeypatch.setattr(srv, "_ensure_workspace_dirs", lambda ws: None)

    class _FakeSearch:
        def set_researcher(self, r):  # noqa: ARG002
            pass

    calls: list[tuple[Any, Any]] = []

    def _factory(mcp, ctx):
        calls.append((mcp, ctx))

    reg = PluginRegistry()
    reg.register_mcp_tools(_factory)
    _set_singleton(reg, monkeypatch)

    workspace = tmp_path / "ws"
    mcp = srv.create_mcp_server(_FakeSearch(), object(), object(), workspace, {})
    assert mcp is not None
    assert len(calls) == 1
    assert calls[0][1] is not None  # ctx passed through


def test_create_mcp_server_survives_plugin_factory_failure(monkeypatch, tmp_path):
    """A raising plugin factory does not abort create_mcp_server."""
    import mcp_exploit_server as srv

    for fn_name in [
        "register_runtime_skill_tools", "register_peer_model_tools",
        "register_terminal_tools", "register_workspace_tools",
        "register_research_tools", "register_metasploit_tools",
        "register_credential_tools", "register_recon_tools",
        "register_payload_tools", "register_attack_module_tools",
        "register_session_tools",
    ]:
        monkeypatch.setattr(srv, fn_name, lambda mcp, *, ctx=None: None)
    monkeypatch.setattr(srv, "_ensure_workspace_dirs", lambda ws: None)

    def _bad_factory(mcp, ctx):  # noqa: ARG001
        raise RuntimeError("plugin boom")

    reg = PluginRegistry()
    reg.register_mcp_tools(_bad_factory)
    _set_singleton(reg, monkeypatch)

    class _FakeSearch:
        def set_researcher(self, r):  # noqa: ARG002
            pass

    workspace = tmp_path / "ws"
    mcp = srv.create_mcp_server(_FakeSearch(), object(), object(), workspace, {})
    assert mcp is not None  # still returned despite the bad factory