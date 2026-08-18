"""Tests for the snmp plugin under plugins/snmp/.

Pure stdlib, no real network, no real snmpwalk. The MCP factory tests use
FakeMcp + FakeCtx so no real MCP server / allowlist / audit trail is touched.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Callable

from tools.attack_modules.base import AttackModule, ModuleContext
from tools.plugins import Plugin, PluginManager, PluginRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_DIR = _REPO_ROOT / "plugins" / "snmp"


def _load_plugin_module():
    mod_path = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location("snmp_plugin", str(mod_path))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeMcp:
    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Any]] = {}

    def tool(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class FakeCtx:
    def __init__(self, workspace: Path | None = None, config: dict | None = None) -> None:
        self.workspace = workspace or _REPO_ROOT / "exploit_workspace"
        self.config = config or {}

    def require_allowlist(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn

        return decorator

    def audit_tool(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn

        return decorator


def test_create_plugin_returns_plugin_with_expected_manifest():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    assert isinstance(plugin, Plugin)
    assert plugin.manifest.name == "snmp"
    assert plugin.manifest.enabled is False
    assert plugin.manifest.version == "0.1.0"
    assert "attack_module" in plugin.manifest.capabilities
    assert "mcp_tool" in plugin.manifest.capabilities
    assert plugin.manifest.config_section is not None
    assert "snmp" in plugin.manifest.config_section


def test_register_registers_attack_module_and_config_and_factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert len(registry.extra_module_classes) == 1
    cls = registry.extra_module_classes[0]
    assert cls.__name__ == "SNMPEnumeration"
    assert issubclass(cls, AttackModule)
    assert cls.target_ports == [161]
    assert "snmp" in registry.config_sections
    assert len(registry.mcp_tool_factories) == 1


def test_plugin_does_not_load_when_disabled():
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=["snmp"])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "snmp" not in [m.name for m in loaded]


def test_plugin_loads_when_enabled():
    assert _PLUGIN_DIR.is_dir()
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["snmp"], disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "snmp" in [m.name for m in loaded]
    assert len(registry.extra_module_classes) == 1
    assert registry.extra_module_classes[0].__name__ == "SNMPEnumeration"
    assert len(registry.mcp_tool_factories) >= 1


def _factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    return registry.mcp_tool_factories[0]


def test_mcp_factory_registers_two_tools():
    factory = _factory()
    mcp = FakeMcp()
    ctx = FakeCtx()
    factory(mcp, ctx)
    assert "snmp_enum_target" in mcp.tools
    assert "snmp_crack_community" in mcp.tools


def test_mcp_factory_gates_every_tool_with_require_allowlist():
    """Both SNMP tools are target-touching, so both use @require_allowlist()."""
    factory = _factory()

    class TrackingCtx:
        def __init__(self) -> None:
            self.require_called = 0
            self.workspace = Path("/tmp")
            self.config = {}

        def require_allowlist(self, *args: Any, **kwargs: Any):
            self.require_called += 1

            def decorator(fn):
                return fn

            return decorator

        def audit_tool(self, *args: Any, **kwargs: Any):
            def decorator(fn):
                return fn

            return decorator

    mcp = FakeMcp()
    ctx = TrackingCtx()
    factory(mcp, ctx)
    assert ctx.require_called == 2


def test_snmp_enum_blocked_when_plugin_disabled_in_config():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(config={"snmp": {"enabled": False}})
    factory(mcp, ctx)

    out = mcp.tools["snmp_enum_target"](target_ip="10.0.0.1")
    assert out.startswith("BLOCKED:")


def test_snmp_enum_success_and_failure(monkeypatch):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(config={"snmp": {"enabled": True}})
    factory(mcp, ctx)

    monkeypatch.setattr(module, "_run_snmpwalk", lambda *a, **k: (0, "iso.3.6.1.2.1.1.0 = STRING: TestHost"))
    out = mcp.tools["snmp_enum_target"](target_ip="10.0.0.1")
    assert "SNMP_ENUM_RESULT" in out
    assert "TestHost" in out

    monkeypatch.setattr(module, "_run_snmpwalk", lambda *a, **k: (1, "Timeout"))
    out = mcp.tools["snmp_enum_target"](target_ip="10.0.0.1")
    assert "SNMP_ENUM_ERROR" in out


def test_snmp_crack_community_works(monkeypatch):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(config={"snmp": {"enabled": True}})
    factory(mcp, ctx)

    def fake_walk(ip, community, version="2c", oid="", timeout=10, runner=None):
        if community == "public":
            return (0, "iso.3.6.1.2.1.1.1.0 = STRING: TestHost")
        return (1, "")

    monkeypatch.setattr(module, "_run_snmpwalk", fake_walk)
    out = mcp.tools["snmp_crack_community"](target_ip="10.0.0.1")
    assert "SNMP_COMMUNITY_RESULT" in out
    assert "COMMUNITY: public" in out
    assert "OK" in out
    assert "FAIL" not in out


def test_attack_module_applicability():
    module = _load_plugin_module()
    ctx = ModuleContext(
        target_ip="10.0.0.1",
        services=[{"service": "snmp", "port": "161/udp", "version": ""}],
    )
    score = module.SNMPEnumeration().applicability(ctx)
    assert score > 0
