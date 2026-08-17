"""Tests for the ZAP scan plugin under plugins/zap_scan/.

Pure stdlib, no real network, no real ZAP daemon. The MCP factory tests use
FakeMcp + FakeCtx so no real MCP server / allowlist / audit trail is touched.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Callable

from tools.plugins import Plugin, PluginManager, PluginRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_DIR = _REPO_ROOT / "plugins" / "zap_scan"


def _load_plugin_module():
    mod_path = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location("zap_scan_plugin", str(mod_path))
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
    assert plugin.manifest.name == "zap_scan"
    assert plugin.manifest.enabled is False


def test_register_registers_mcp_tool_factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert len(registry.mcp_tool_factories) == 1


def test_plugin_does_not_load_when_disabled_by_default():
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=["zap_scan"])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "zap_scan" not in [m.name for m in loaded]


def test_plugin_loads_from_real_directory_when_enabled():
    assert _PLUGIN_DIR.is_dir()
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["zap_scan"], disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "zap_scan" in [m.name for m in loaded]
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
    assert "zap_spider" in mcp.tools
    assert "zap_active_scan" in mcp.tools
    assert "zap_scan_status" in mcp.tools
    assert "zap_alerts" in mcp.tools


def test_mcp_factory_uses_require_allowlist_from_ctx():
    factory = _factory()

    class TrackingCtx:
        def __init__(self) -> None:
            self.require_called = False
            self.workspace = Path("/tmp")
            self.config = {}

        def require_allowlist(self, *args: Any, **kwargs: Any):
            self.require_called = True

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
    assert ctx.require_called is True


def test_zap_spider_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["zap_spider"](target_ip="10.0.0.50", url="http://10.0.0.50/")
    assert "BLOCKED" in out
    assert "not enabled" in out


def test_zap_spider_rejects_missing_url(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"zap_scan": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["zap_spider"](target_ip="10.0.0.50", url="")
    assert "BLOCKED" in out
    assert "url" in out


def test_zap_active_scan_rejects_missing_url(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"zap_scan": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["zap_active_scan"](target_ip="10.0.0.50", url="")
    assert "BLOCKED" in out


def test_zap_scan_status_rejects_missing_scan_id(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"zap_scan": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["zap_scan_status"](target_ip="10.0.0.50", scan_id="")
    assert "BLOCKED" in out


def test_zap_spider_with_mocked_api(monkeypatch, tmp_path):
    module = _load_plugin_module()

    def fake_post(config, path, params, timeout=30):
        return 200, json.dumps({"scan": "42"})

    monkeypatch.setattr(module, "_zap_post", fake_post)
    monkeypatch.setattr(module, "_zap_get", lambda c, p, params=None, timeout=30: (200, "{}"))

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"zap_scan": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["zap_spider"](target_ip="10.0.0.50", url="http://10.0.0.50/")
    assert "ZAP_SPIDER_RESULT" in out
    assert "42" in out
