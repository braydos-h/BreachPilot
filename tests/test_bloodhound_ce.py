"""Tests for the BloodHound CE plugin under plugins/bloodhound_ce/.

Pure stdlib, no real network, no real neo4j. The MCP factory tests use FakeMcp
+ FakeCtx so no real MCP server / allowlist / audit trail is touched.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Callable

from tools.plugins import Plugin, PluginManager, PluginRegistry

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_DIR = _REPO_ROOT / "plugins" / "bloodhound_ce"


def _load_plugin_module():
    mod_path = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location("bloodhound_ce_plugin", str(mod_path))
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
    assert plugin.manifest.name == "bloodhound_ce"
    assert plugin.manifest.enabled is False


def test_register_registers_mcp_tool_factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert len(registry.mcp_tool_factories) == 1


def test_plugin_does_not_load_when_disabled_by_default():
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=["bloodhound_ce"])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "bloodhound_ce" not in [m.name for m in loaded]


def test_plugin_loads_from_real_directory_when_enabled():
    assert _PLUGIN_DIR.is_dir()
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["bloodhound_ce"], disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "bloodhound_ce" in [m.name for m in loaded]
    assert len(registry.mcp_tool_factories) >= 1


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
    assert "bloodhound_ce_ingest" in mcp.tools
    assert "bloodhound_ce_query" in mcp.tools
    assert "bloodhound_ce_list_queries" in mcp.tools


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


def test_list_queries_returns_catalog(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["bloodhound_ce_list_queries"](target_ip="10.0.0.50")
    assert "BLOODHOUND_CE_QUERIES" in out
    assert "shortest_path_to_domain_admin" in out
    assert "kerberoastable_users" in out


def test_query_rejects_unknown_name(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["bloodhound_ce_query"](target_ip="10.0.0.50", query_name="not_a_real_query")
    assert "BLOCKED" in out
    assert "unknown query" in out


def test_ingest_rejects_missing_zip_path(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["bloodhound_ce_ingest"](target_ip="10.0.0.50", zip_path="")
    assert "BLOCKED" in out


def test_ingest_rejects_nonexistent_zip(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["bloodhound_ce_ingest"](target_ip="10.0.0.50", zip_path="does_not_exist.zip")
    assert "BLOCKED" in out


def test_ingest_rejects_non_zip_extension(tmp_path):
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    # Create a non-zip file.
    fake = tmp_path / "data.txt"
    fake.write_text("not a zip")
    out = mcp.tools["bloodhound_ce_ingest"](target_ip="10.0.0.50", zip_path=str(fake))
    assert "BLOCKED" in out
    assert ".zip" in out


def test_query_with_mock_driver_returns_results(monkeypatch, tmp_path):
    module = _load_plugin_module()

    class FakeSession:
        def __init__(self) -> None:
            self.records = [
                {"name": "Administrator", "groups": ["Domain Admins"]},
                {"name": "svc-sql", "groups": ["Domain Admins"]},
            ]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def run(self, query):
            class _R:
                def __init__(self, records):
                    self._records = records

                def __iter__(self):
                    return iter(self._records)

            return _R(self.records)

    class FakeDriver:
        def session(self):
            return FakeSession()

    monkeypatch.setattr(module, "_NEO4J_DRIVER", None)
    monkeypatch.setattr(module, "_build_neo4j_driver", lambda cfg: FakeDriver())

    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx(workspace=tmp_path, config={})
    factory(mcp, ctx)

    out = mcp.tools["bloodhound_ce_query"](
        target_ip="10.0.0.50",
        query_name="all_admins",
        limit=50,
    )
    assert "BLOODHOUND_CE_QUERY_RESULT" in out
    assert "Administrator" in out
