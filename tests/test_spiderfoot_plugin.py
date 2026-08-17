"""Tests for the SpiderFoot plugin under plugins/spiderfoot/.

Pure stdlib, no real network, no real SpiderFoot daemon. The MCP factory tests
use FakeMcp + FakeCtx so no real MCP server / allowlist / audit trail is
touched. SpiderFoot is passive-only; every tool uses @audit_tool (no
require_allowlist gate).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any, Callable

from tools.plugins import Plugin, PluginManager, PluginRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_DIR = _REPO_ROOT / "plugins" / "spiderfoot"


def _load_plugin_module():
    mod_path = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location("spiderfoot_plugin", str(mod_path))
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
        # Be permissive: if called with a callable, return it; else return a decorator.
        if args and callable(args[0]) and not kwargs:
            return args[0]

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn

        return decorator


def test_create_plugin_returns_plugin_with_expected_manifest():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    assert isinstance(plugin, Plugin)
    assert plugin.manifest.name == "spiderfoot"
    assert plugin.manifest.enabled is False


def test_register_registers_mcp_tool_factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert len(registry.mcp_tool_factories) == 1


def test_plugin_does_not_load_when_disabled_by_default():
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=["spiderfoot"])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "spiderfoot" not in [m.name for m in loaded]


def test_plugin_loads_from_real_directory_when_enabled():
    assert _PLUGIN_DIR.is_dir()
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["spiderfoot"], disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "spiderfoot" in [m.name for m in loaded]
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
    assert "spiderfoot_scan" in mcp.tools
    assert "spiderfoot_scan_status" in mcp.tools
    assert "spiderfoot_results" in mcp.tools
    assert "spiderfoot_list_modules" in mcp.tools


def test_mcp_factory_uses_audit_tool_only():
    """SpiderFoot is passive; every tool uses @audit_tool, NOT @require_allowlist()."""
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
            # @audit_tool is used as a DIRECT decorator (no parens): args[0] is the fn.
            if args and callable(args[0]) and not kwargs:
                return args[0]

            def decorator(fn):
                return fn

            return decorator

    mcp = FakeMcp()
    ctx = TrackingCtx()
    factory(mcp, ctx)
    # All 4 tools use @audit_tool, none use @require_allowlist.
    assert ctx.audit_called == 4
    assert ctx.require_called == 0


def test_scan_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["spiderfoot_scan"](target="example.com")
    assert "BLOCKED" in out
    assert "not enabled" in out


def test_scan_rejects_missing_target(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"spiderfoot": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["spiderfoot_scan"](target="")
    assert "BLOCKED" in out


def test_scan_status_rejects_missing_scan_id(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"spiderfoot": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["spiderfoot_scan_status"](scan_id="")
    assert "BLOCKED" in out


def test_results_rejects_missing_scan_id(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"spiderfoot": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["spiderfoot_results"](scan_id="")
    assert "BLOCKED" in out


def test_list_modules_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["spiderfoot_list_modules"]()
    assert "BLOCKED" in out


def test_scan_with_mocked_api(monkeypatch, tmp_path):
    module = _load_plugin_module()

    def fake_request(config, method, path, body=None, timeout=60):
        return 200, json.dumps({"scan_id": "abc-123"})

    monkeypatch.setattr(module, "_sf_request", fake_request)

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"spiderfoot": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["spiderfoot_scan"](target="example.com")
    assert "SPIDERFOOT_SCAN_RESULT" in out
    assert "abc-123" in out


def test_scan_status_with_mocked_api(monkeypatch, tmp_path):
    module = _load_plugin_module()

    def fake_request(config, method, path, body=None, timeout=60):
        return 200, json.dumps({"status": "RUNNING", "scan_id": "abc-123"})

    monkeypatch.setattr(module, "_sf_request", fake_request)

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"spiderfoot": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["spiderfoot_scan_status"](scan_id="abc-123")
    assert "SPIDERFOOT_SCAN_STATUS" in out
    assert "RUNNING" in out
