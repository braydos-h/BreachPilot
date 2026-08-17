"""Tests for the mobile-attack plugin under plugins/mobile_attack/.

Pure stdlib, no real network, no real device. The MCP factory tests use
FakeMcp + FakeCtx so no real MCP server / allowlist / audit trail is touched.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Callable

from tools.plugins import Plugin, PluginManager, PluginRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_DIR = _REPO_ROOT / "plugins" / "mobile_attack"


def _load_plugin_module():
    mod_path = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location("mobile_attack_plugin", str(mod_path))
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

    def audit_tool(self, *args: Any, **kwargs: Any):
        # @audit_tool is used as a DIRECT decorator (no parens): args[0] is the fn.
        if args and callable(args[0]) and not kwargs:
            return args[0]

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn

        return decorator


def test_create_plugin_returns_plugin_with_expected_manifest():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    assert isinstance(plugin, Plugin)
    assert plugin.manifest.name == "mobile_attack"
    assert plugin.manifest.enabled is False


def test_register_registers_mcp_tool_factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert len(registry.mcp_tool_factories) == 1


def test_plugin_does_not_load_when_disabled_by_default():
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=["mobile_attack"])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "mobile_attack" not in [m.name for m in loaded]


def test_plugin_loads_from_real_directory_when_enabled():
    assert _PLUGIN_DIR.is_dir()
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["mobile_attack"], disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "mobile_attack" in [m.name for m in loaded]
    assert len(registry.mcp_tool_factories) >= 1


def _factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    return registry.mcp_tool_factories[0]


def test_mcp_factory_registers_four_tools():
    factory = _factory()
    mcp = FakeMcp()
    ctx = FakeCtx()
    factory(mcp, ctx)
    # 2 audit_tool (local APK analysis) + 2 require_allowlist (device-touching)
    assert "mobile_apk_decompile" in mcp.tools
    assert "mobile_apk_inspect" in mcp.tools
    assert "mobile_frida_attach" in mcp.tools
    assert "mobile_frida_list_apps" in mcp.tools


def test_mcp_factory_uses_both_decorators():
    """Local APK analysis uses @audit_tool; device-touching uses @require_allowlist()."""
    factory = _factory()

    class TrackingCtx:
        def __init__(self) -> None:
            self.require_called = 0
            self.audit_called = 0
            self.workspace = Path("/tmp")
            self.config = {}

        def require_allowlist(self, *args: Any, **kwargs: Any):
            self.require_called += 1

            def decorator(fn):
                return fn

            return decorator

        def audit_tool(self, *args: Any, **kwargs: Any):
            self.audit_called += 1
            # @audit_tool is used as a DIRECT decorator (no parens).
            if args and callable(args[0]) and not kwargs:
                return args[0]

            def decorator(fn):
                return fn

            return decorator

    mcp = FakeMcp()
    ctx = TrackingCtx()
    factory(mcp, ctx)
    # 2 require_allowlist (frida attach + frida list apps)
    assert ctx.require_called == 2
    # 2 audit_tool (decompile + inspect)
    assert ctx.audit_called == 2


def test_apk_decompile_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["mobile_apk_decompile"](apk_path="app.apk")
    assert "BLOCKED" in out
    assert "not enabled" in out


def test_apk_decompile_rejects_missing_apk_path(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"mobile_attack": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["mobile_apk_decompile"](apk_path="")
    assert "BLOCKED" in out


def test_apk_decompile_rejects_nonexistent_apk(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"mobile_attack": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["mobile_apk_decompile"](apk_path="does_not_exist.apk")
    assert "BLOCKED" in out
    assert "not found" in out


def test_frida_attach_rejects_missing_app_id(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"mobile_attack": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["mobile_frida_attach"](target_ip="10.0.0.50", app_id="")
    assert "BLOCKED" in out
    assert "app_id" in out


def test_frida_attach_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["mobile_frida_attach"](target_ip="10.0.0.50", app_id="com.example.app")
    assert "BLOCKED" in out
    assert "not enabled" in out


def test_frida_list_apps_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["mobile_frida_list_apps"](target_ip="10.0.0.50")
    assert "BLOCKED" in out
    assert "not enabled" in out
