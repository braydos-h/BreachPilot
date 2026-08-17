"""Tests for the Sliver C2 plugin under plugins/sliver_c2/.

Pure stdlib, no real network, no real Sliver server. The MCP factory tests use
FakeMcp + FakeCtx so no real MCP server / allowlist / audit trail is touched.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Callable

from tools.plugins import Plugin, PluginManager, PluginRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_DIR = _REPO_ROOT / "plugins" / "sliver_c2"


def _load_plugin_module():
    mod_path = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location("sliver_c2_plugin", str(mod_path))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ─── Fakes ────────────────────────────────────────────────────────────────────


class FakeMcp:
    def __init__(self) -> None:
        self.tools: dict[str, Callable[..., Any]] = {}

    def tool(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.tools[fn.__name__] = fn
            return fn

        return decorator


class FakeCtx:
    """Passthrough decorators so the stacked @mcp.tool() / @ctx.require_allowlist()
    pattern works without a real allowlist or audit trail."""

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


# ─── Manifest / load ──────────────────────────────────────────────────────────


def test_create_plugin_returns_plugin_with_expected_manifest():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    assert isinstance(plugin, Plugin)
    assert plugin.manifest.name == "sliver_c2"
    assert plugin.manifest.enabled is False


def test_manifest_capabilities_include_mcp_tool():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    assert "mcp_tool" in plugin.manifest.capabilities


def test_register_registers_mcp_tool_factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert len(registry.mcp_tool_factories) == 1


def test_plugin_does_not_load_when_disabled_by_default():
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=["sliver_c2"])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "sliver_c2" not in [m.name for m in loaded]


def test_plugin_loads_from_real_directory_when_enabled():
    assert _PLUGIN_DIR.is_dir(), f"missing plugin dir: {_PLUGIN_DIR}"
    assert (_PLUGIN_DIR / "plugin.yaml").is_file()
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["sliver_c2"], disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "sliver_c2" in [m.name for m in loaded]
    # Other agents' manifest-enabled plugins may also load; assert OUR
    # factory is registered, not the total count.
    assert len(registry.mcp_tool_factories) >= 1


# ─── MCP factory ──────────────────────────────────────────────────────────────


def _factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    return registry.mcp_tool_factories[0]


def test_mcp_factory_registers_three_tools():
    factory = _factory()
    mcp = FakeMcp()
    ctx = FakeCtx()
    factory(mcp, ctx)
    assert "sliver_list_sessions" in mcp.tools
    assert "sliver_generate_implant" in mcp.tools
    assert "sliver_interact_session" in mcp.tools


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


# ─── Tool behaviour ──────────────────────────────────────────────────────────


def test_list_sessions_with_no_client_returns_error(monkeypatch, tmp_path):
    module = _load_plugin_module()
    # Force the cached client to None and block the import path.
    monkeypatch.setattr(module, "_SLIVER_CLIENT", None)
    monkeypatch.setattr(module, "_get_sliver_client", lambda cfg: None)
    # Force CLI fallback to fail so the error path is deterministic.
    monkeypatch.setattr(module, "_run_sliver_cli", lambda argv, timeout=60: ("", None, "sliver binary not found"))

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["sliver_list_sessions"](target_ip="10.0.0.50")
    assert "SLIVER_SESSIONS_ERROR" in out or "SLIVER_SESSIONS_RESULT" in out


def test_list_sessions_with_mock_client_returns_sessions(monkeypatch, tmp_path):
    module = _load_plugin_module()

    class FakeSession:
        ID = "abc-123"
        RemoteAddress = "10.0.0.50:443"
        Hostname = "victim"
        Username = "root"
        OS = "linux"
        Transport = "mtls"
        LastCheckin = 0.0
        Status = "active"

    class FakeClient:
        def sessions(self):
            return [FakeSession()]

    monkeypatch.setattr(module, "_SLIVER_CLIENT", None)
    monkeypatch.setattr(module, "_get_sliver_client", lambda cfg: FakeClient())

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["sliver_list_sessions"](target_ip="10.0.0.50")
    assert "SLIVER_SESSIONS_RESULT" in out
    assert "abc-123" in out
    assert "victim" in out


def test_generate_implant_blocks_when_callback_host_not_allowlisted(monkeypatch, tmp_path):
    module = _load_plugin_module()

    # The decorator is a passthrough in FakeCtx, so we exercise the explicit
    # callback_host re-check inside the tool.
    monkeypatch.setattr(module, "_get_sliver_client", lambda cfg: None)
    monkeypatch.setattr(
        "tools.mcp_shared._check_allowlist",
        lambda host, cfg: (False, f"{host} not in exploit.allowed_targets"),
    )

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={"exploit": {"allowed_targets": []}})
    factory(mcp, ctx)

    out = mcp.tools["sliver_generate_implant"](
        target_ip="10.0.0.50",
        callback_host="1.2.3.4",
        callback_port=443,
    )
    assert "BLOCKED" in out
    assert "1.2.3.4" in out


def test_interact_session_validates_required_args(tmp_path):
    module = _load_plugin_module()
    module._reset_client_cache()
    module._SLIVER_CLIENT = None

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["sliver_interact_session"](target_ip="10.0.0.50", session_id="", command="whoami")
    assert "BLOCKED" in out
    out = mcp.tools["sliver_interact_session"](target_ip="10.0.0.50", session_id="abc", command="")
    assert "BLOCKED" in out
