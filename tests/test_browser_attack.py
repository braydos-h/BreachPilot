"""Tests for the browser-attack plugin under plugins/browser_attack/.

Pure stdlib, no real network, no real browser. The MCP factory tests use
FakeMcp + FakeCtx so no real MCP server / allowlist / audit trail is touched.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Callable

from tools.plugins import Plugin, PluginManager, PluginRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_DIR = _REPO_ROOT / "plugins" / "browser_attack"


def _load_plugin_module():
    mod_path = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location("browser_attack_plugin", str(mod_path))
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
    assert plugin.manifest.name == "browser_attack"
    assert plugin.manifest.enabled is False


def test_register_registers_mcp_tool_factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert len(registry.mcp_tool_factories) == 1


def test_plugin_does_not_load_when_disabled_by_default():
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=["browser_attack"])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "browser_attack" not in [m.name for m in loaded]


def test_plugin_loads_from_real_directory_when_enabled():
    assert _PLUGIN_DIR.is_dir()
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["browser_attack"], disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "browser_attack" in [m.name for m in loaded]
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
    assert "browser_attack_navigate" in mcp.tools
    assert "browser_dom_xss_probe" in mcp.tools
    assert "browser_xss_callbacks" in mcp.tools
    assert "browser_xss_record_callback" in mcp.tools


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


def test_navigate_rejects_missing_url(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"browser_attack": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["browser_attack_navigate"](target_ip="10.0.0.50", url="")
    assert "BLOCKED" in out


def test_navigate_rejects_when_plugin_disabled(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["browser_attack_navigate"](target_ip="10.0.0.50", url="http://10.0.0.50/")
    assert "BLOCKED" in out
    assert "not enabled" in out


def test_navigate_rejects_when_playwright_missing(monkeypatch, tmp_path):
    """When playwright is unavailable, the tool must BLOCK rather than crash."""
    module = _load_plugin_module()

    # Force the lazy import to fail so the "not installed" path is exercised
    # even when playwright is installed on the dev box.
    monkeypatch.setattr(module, "_get_playwright", lambda cfg: None)

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"browser_attack": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["browser_attack_navigate"](target_ip="10.0.0.50", url="http://10.0.0.50/")
    assert "playwright not installed" in out or "BLOCKED" in out


def test_dom_xss_rejects_missing_callback_host(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"browser_attack": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["browser_dom_xss_probe"](
        target_ip="10.0.0.50",
        url="http://10.0.0.50/",
    )
    assert "BLOCKED" in out
    assert "callback_host" in out or "xss_callback_host" in out


def test_dom_xss_rejects_callback_host_not_allowlisted(monkeypatch, tmp_path):
    module = _load_plugin_module()
    monkeypatch.setattr(
        "tools.mcp_shared._check_allowlist",
        lambda host, cfg: (False, f"{host} not in exploit.allowed_targets"),
    )

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(
        workspace=tmp_path,
        config={"browser_attack": {"enabled": True, "xss_callback_host": "1.2.3.4", "xss_callback_port": 5555}},
    )
    factory(mcp, ctx)

    out = mcp.tools["browser_dom_xss_probe"](
        target_ip="10.0.0.50",
        url="http://10.0.0.50/",
    )
    assert "BLOCKED" in out
    assert "1.2.3.4" in out


def test_record_callback_and_list(tmp_path):
    module = _load_plugin_module()
    module._reset_callbacks()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"browser_attack": {"enabled": True}})
    factory(mcp, ctx)

    # No callbacks recorded yet
    out = mcp.tools["browser_xss_callbacks"](target_ip="10.0.0.50")
    assert "none recorded" in out

    # Record one
    out = mcp.tools["browser_xss_record_callback"](
        target_ip="10.0.0.50",
        callback_id="abc-123",
        payload="alert(1)",
    )
    assert "RECORDED" in out
    assert "abc-123" in out

    # Now there should be one callback
    out = mcp.tools["browser_xss_callbacks"](target_ip="10.0.0.50")
    assert "BROWSER_XSS_CALLBACKS" in out
    assert "abc-123" in out


def test_record_callback_rejects_missing_id(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"browser_attack": {"enabled": True}})
    factory(mcp, ctx)

    out = mcp.tools["browser_xss_record_callback"](
        target_ip="10.0.0.50",
        callback_id="",
        payload="x",
    )
    assert "BLOCKED" in out
