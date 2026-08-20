"""Tests for the reference plugin under plugins/example_recon_report/.

Pure stdlib, no real network. The MCP factory test uses FakeMcp + FakeCtx so no
real MCP server / allowlist / audit trail is touched. Filesystem load test uses
the real plugin directory via pathlib + a fresh PluginRegistry (not the
singleton) to avoid cross-test pollution.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest

from tools.attack_modules.base import ModuleContext
from tools.plugins import Plugin, PluginManager, PluginRegistry

# Real plugin directory (sibling of tests/): <repo>/plugins/example_recon_report
_REPO_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_DIR = _REPO_ROOT / "plugins" / "example_recon_report"

# Import the plugin module by path so we can call create_plugin() directly.
import importlib.util  # noqa: E402


def _load_plugin_module():
    mod_path = _PLUGIN_DIR / "plugin.py"
    spec = importlib.util.spec_from_file_location("example_recon_report_plugin", str(mod_path))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _example_factory_registered(registry: PluginRegistry) -> bool:
    """True if the example plugin's own MCP factory is in the registry.

    Filesystem plugins are loaded under a ``netattackai_plugin_<name>_<hash>``
    module name (see tools/plugins._load_module_from_file), so match by prefix.
    """
    return any(
        getattr(f, "__module__", "").startswith("netattackai_plugin_example_recon_report_")
        for f in registry.mcp_tool_factories
    )


# ─── Fakes ────────────────────────────────────────────────────────────────────


class FakeMcp:
    """Records functions decorated with @mcp.tool()."""

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

    def require_allowlist(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn

        return decorator

    def audit_tool(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return fn

        return decorator


# ─── Tests ────────────────────────────────────────────────────────────────────


def test_create_plugin_returns_plugin_with_expected_manifest():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    assert isinstance(plugin, Plugin)
    assert plugin.manifest.name == "example_recon_report"
    assert plugin.manifest.enabled is False


def test_manifest_version_description_author_capabilities():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    m = plugin.manifest
    assert m.version == "0.1.0"
    assert m.author == "NetAttackAi"
    assert "attack_module" in m.capabilities
    assert "mcp_tool" in m.capabilities
    assert m.description.startswith("Example plugin")


def test_register_registers_one_attack_module():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert module.ExampleReportModule in registry.extra_module_classes
    assert len(registry.extra_module_classes) == 1


def test_register_registers_one_mcp_tool_factory():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    assert len(registry.mcp_tool_factories) == 1


def test_register_attack_module_class_is_attack_module_subclass():
    from tools.attack_modules.base import AttackModule

    module = _load_plugin_module()
    assert issubclass(module.ExampleReportModule, AttackModule)


def test_module_class_metadata_defaults():
    module = _load_plugin_module()
    cls = module.ExampleReportModule
    assert cls.name == "example_plugin_recon_report"
    assert cls.target_services == []
    assert cls.target_ports == []
    assert cls.required_cves == []
    assert cls.target_versions == {}


def test_module_run_returns_info_status_and_target_ip():
    module = _load_plugin_module()
    mod = module.ExampleReportModule()
    ctx = ModuleContext(target_ip="10.0.0.50")
    result = mod.run(ctx)
    assert result["status"] == "info"
    assert result["module"] == "example_plugin_recon_report"
    assert result["target_ip"] == "10.0.0.50"
    assert result["summary"] == "example plugin recon report"
    assert result["note"] == "read-only"


def test_module_run_never_sets_shell_type_or_privilege_level():
    module = _load_plugin_module()
    mod = module.ExampleReportModule()
    ctx = ModuleContext(target_ip="10.0.0.50")
    result = mod.run(ctx)
    assert "shell_type" not in result
    assert "privilege_level" not in result


def test_module_run_target_locked_to_ctx_target_ip():
    module = _load_plugin_module()
    mod = module.ExampleReportModule()
    ctx = ModuleContext(target_ip="192.168.1.10")
    result = mod.run(ctx)
    assert result["target_ip"] == "192.168.1.10"


def test_module_applicability_returns_ten():
    module = _load_plugin_module()
    mod = module.ExampleReportModule()
    ctx = ModuleContext(target_ip="10.0.0.50", services=[{"service": "http", "port": "80/tcp"}])
    assert mod.applicability(ctx) == 10


def test_module_applicability_baseline_always_selectable_no_matches():
    module = _load_plugin_module()
    mod = module.ExampleReportModule()
    ctx = ModuleContext(target_ip="10.0.0.50", services=[], cves=[])
    # No service/port/CVE matches but still 10 (baseline, always selectable).
    assert mod.applicability(ctx) == 10


def test_mcp_factory_registers_plugin_info_handler():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx()
    factory(mcp, ctx)

    assert "plugin_info" in mcp.tools


def test_mcp_factory_handler_returns_info_string_with_target_ip():
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    mcp = FakeMcp()
    ctx = FakeCtx()
    factory(mcp, ctx)

    handler = mcp.tools["plugin_info"]
    out = handler(target_ip="10.0.0.50")
    assert isinstance(out, str)
    assert "PLUGIN_INFO" in out
    assert "example_recon_report" in out
    assert "0.1.0" in out
    assert "10.0.0.50" in out


def test_mcp_factory_uses_require_allowlist_from_ctx():
    """The factory must pull require_allowlist off ctx (the safety hook)."""
    module = _load_plugin_module()
    plugin = module.create_plugin()
    registry = PluginRegistry()
    plugin.register(registry)
    factory = registry.mcp_tool_factories[0]

    class TrackingCtx:
        def __init__(self) -> None:
            self.require_called = False

        def require_allowlist(self):
            self.require_called = True

            def decorator(fn):
                return fn

            return decorator

        def audit_tool(self):
            def decorator(fn):
                return fn

            return decorator

    mcp = FakeMcp()
    ctx = TrackingCtx()
    factory(mcp, ctx)
    assert ctx.require_called is True


def test_plugin_loads_from_real_directory_when_enabled():
    """PluginManager loads the real plugin when enabled via config list."""
    assert _PLUGIN_DIR.is_dir(), f"missing plugin dir: {_PLUGIN_DIR}"
    assert (_PLUGIN_DIR / "plugin.yaml").is_file()

    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["example_recon_report"], disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)

    names = [m.name for m in loaded]
    assert "example_recon_report" in names
    # Attack module + MCP factory both registered. Shipped plugins under
    # plugins/ default to enabled, so other factories may be registered too;
    # assert the example plugin's own factory is present rather than a total
    # count.
    assert any(c.__name__ == "ExampleReportModule" for c in registry.extra_module_classes)
    assert _example_factory_registered(registry)


def test_plugin_does_not_load_when_disabled_by_default():
    """With no enabled list and manifest enabled:false, the plugin is NOT loaded."""
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=[])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)

    names = [m.name for m in loaded]
    assert "example_recon_report" not in names
    # Shipped plugins under plugins/ default to enabled and may load here; the
    # example plugin specifically must not register anything.
    assert not any(c.__name__ == "ExampleReportModule" for c in registry.extra_module_classes)
    assert not _example_factory_registered(registry)


def test_plugin_does_not_load_when_explicitly_disabled():
    """Even if manifest were enabled, explicit disabled list wins."""
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=["example_recon_report"], disabled=["example_recon_report"])
    loaded = manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)
    assert "example_recon_report" not in [m.name for m in loaded]


def test_plugin_discovered_but_not_loaded_appears_in_discovered_list():
    """list_discovered_plugins reports it; loaded flag is False when disabled."""
    from tools.plugins import list_discovered_plugins, _reset_discovered

    _reset_discovered()
    registry = PluginRegistry()
    manager = PluginManager(registry, enabled=None, disabled=[])
    manager.load_all([str(_PLUGIN_DIR.parent)], entry_points=False)

    discovered = list_discovered_plugins()
    entry = next((d for d in discovered if d["name"] == "example_recon_report"), None)
    assert entry is not None
    assert entry["loaded"] is False