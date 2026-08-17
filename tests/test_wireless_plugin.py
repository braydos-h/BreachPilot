"""Tests for the wireless plugin under plugins/wireless/.

Pure stdlib, no real network, no real radio. The MCP factory tests use
FakeMcp + FakeCtx so no real MCP server / allowlist / audit trail is touched.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Callable

from tools.plugins import Plugin, PluginManager, PluginRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_DIR = _REPO_ROOT / "plugins" / "wireless"


def _load_plugin_module():
    mod_path = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location("wireless_plugin", str(mod_path))
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
    assert plugin.manifest.name == "wireless"
    assert plugin.manifest.enabled is False


def test_register_registers_mcp_tool_factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert len(registry.mcp_tool_factories) == 1


def test_plugin_does_not_load_when_disabled_by_default():
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=["wireless"])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "wireless" not in [m.name for m in loaded]


def test_plugin_loads_from_real_directory_when_enabled():
    assert _PLUGIN_DIR.is_dir()
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["wireless"], disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "wireless" in [m.name for m in loaded]
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
    assert "wireless_recon" in mcp.tools
    assert "wireless_deauth" in mcp.tools
    assert "wireless_pmkid_capture" in mcp.tools
    assert "wireless_crack_pmkid" in mcp.tools


def test_mcp_factory_uses_require_allowlist_from_ctx():
    """All wireless tools are radio-touching, so all use @require_allowlist()."""
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
    # 4 tools, all require_allowlist-gated
    assert ctx.require_called == 4


def test_recon_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["wireless_recon"](target_ip="AA:BB:CC:DD:EE:FF")
    assert "BLOCKED" in out
    assert "not enabled" in out


def test_deauth_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["wireless_deauth"](target_ip="AA:BB:CC:DD:EE:FF")
    assert "BLOCKED" in out
    assert "not enabled" in out


def test_pmkid_capture_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["wireless_pmkid_capture"](target_ip="AA:BB:CC:DD:EE:FF")
    assert "BLOCKED" in out


def test_crack_pmkid_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["wireless_crack_pmkid"](
        target_ip="AA:BB:CC:DD:EE:FF",
        capture_path="x.pcapng",
    )
    assert "BLOCKED" in out


def test_crack_pmkid_rejects_missing_capture_path(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"wireless": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["wireless_crack_pmkid"](
        target_ip="AA:BB:CC:DD:EE:FF",
        capture_path="",
    )
    assert "BLOCKED" in out


def test_crack_pmkid_rejects_nonexistent_capture(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"wireless": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["wireless_crack_pmkid"](
        target_ip="AA:BB:CC:DD:EE:FF",
        capture_path="does_not_exist.pcapng",
    )
    assert "BLOCKED" in out
    assert "not found" in out
