"""Tests for tools.plugins (plugin manager).

Pure-stdlib, no real network, no real filesystem entry points. Filesystem
discovery uses tmp_path; entry-point discovery uses an injected loader.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from tools.plugins import (
    PLUGIN_REGISTRY,
    Plugin,
    PluginManager,
    PluginManifest,
    PluginRegistry,
    get_plugin_registry,
    list_discovered_plugins,
    load_plugins,
)

# ─── helpers ──────────────────────────────────────────────────────────────────


def _make_manifest(**kw) -> PluginManifest:
    return PluginManifest.from_dict(kw)


def _write_plugin_yaml(plugin_dir: Path, manifest: dict) -> Path:
    plugin_dir.mkdir(parents=True, exist_ok=True)
    path = plugin_dir / "plugin.yaml"
    lines = []
    for key, val in manifest.items():
        if key == "capabilities" and isinstance(val, (list, tuple)):
            lines.append("capabilities:")
            for item in val:
                lines.append(f"  - {item}")
        elif key == "config_section" and isinstance(val, dict):
            lines.append("config_section:")
            for sub_k, sub_v in val.items():
                lines.append(f"  {sub_k}: {sub_v}")
        elif isinstance(val, bool):
            lines.append(f"{key}: {'true' if val else 'false'}")
        else:
            lines.append(f"{key}: {val}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_plugin_py(plugin_dir: Path, source: str) -> Path:
    plugin_dir.mkdir(parents=True, exist_ok=True)
    path = plugin_dir / "plugin.py"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _reset_registry():
    """Isolate every test from the module-level singleton."""
    PLUGIN_REGISTRY.reset()
    from tools import plugins as plugins_mod

    plugins_mod._reset_discovered()
    yield
    PLUGIN_REGISTRY.reset()
    plugins_mod._reset_discovered()


# ─── PluginManifest ───────────────────────────────────────────────────────────


def test_manifest_defaults():
    m = PluginManifest(name="foo")
    assert m.name == "foo"
    assert m.version == "0.0.1"
    assert m.description == ""
    assert m.author == ""
    assert m.capabilities == ()
    assert m.enabled is False
    assert m.config_section is None


def test_manifest_from_dict_tolerant_of_missing_keys():
    m = PluginManifest.from_dict(None)
    assert m.name == ""
    assert m.enabled is False
    assert m.capabilities == ()


def test_manifest_from_dict_full():
    m = PluginManifest.from_dict(
        {
            "name": "foo",
            "version": "1.2.3",
            "description": "desc",
            "author": "me",
            "capabilities": ["attack_module", "mcp_tool"],
            "enabled": True,
            "config_section": {"foo": {"x": 1}},
        }
    )
    assert m.name == "foo"
    assert m.version == "1.2.3"
    assert m.capabilities == ("attack_module", "mcp_tool")
    assert m.enabled is True
    assert m.config_section == {"foo": {"x": 1}}


def test_manifest_from_dict_drops_unknown_capabilities():
    m = PluginManifest.from_dict({"name": "foo", "capabilities": ["attack_module", "bogus"]})
    assert m.capabilities == ("attack_module",)


def test_manifest_from_dict_caps_as_string():
    m = PluginManifest.from_dict({"name": "foo", "capabilities": "mcp_tool"})
    assert m.capabilities == ("mcp_tool",)


def test_manifest_to_dict_round_trip():
    m = PluginManifest(
        name="foo",
        version="1.0.0",
        description="d",
        author="a",
        capabilities=("mcp_tool",),
        enabled=True,
        config_section={"s": {"k": "v"}},
    )
    d = m.to_dict()
    assert d["name"] == "foo"
    assert d["capabilities"] == ["mcp_tool"]
    assert d["enabled"] is True
    assert d["config_section"] == {"s": {"k": "v"}}
    # round-trip back
    m2 = PluginManifest.from_dict(d)
    assert m2.name == m.name
    assert m2.capabilities == m.capabilities
    assert m2.enabled == m.enabled
    assert m2.config_section == m.config_section


# ─── PluginRegistry ───────────────────────────────────────────────────────────


def test_registry_register_attack_module():
    reg = PluginRegistry()

    class Foo: ...

    reg.register_attack_module(Foo)
    assert reg.extra_module_classes == [Foo]


def test_registry_register_mcp_tools():
    reg = PluginRegistry()

    def factory(mcp, ctx): ...

    reg.register_mcp_tools(factory)
    assert reg.mcp_tool_factories == [factory]


def test_registry_register_skill_dir_str_and_path(tmp_path: Path):
    reg = PluginRegistry()
    reg.register_skill_dir(tmp_path)
    reg.register_skill_dir("/some/where")
    assert reg.skill_dirs == [tmp_path, Path("/some/where")]


def test_registry_register_config_section():
    reg = PluginRegistry()
    reg.register_config_section("foo", {"x": {"type": "str"}})
    assert reg.config_sections == {"foo": {"x": {"type": "str"}}}


def test_registry_register_config_section_rejects_bad():
    reg = PluginRegistry()
    with pytest.raises(ValueError):
        reg.register_config_section("", {})
    with pytest.raises(TypeError):
        reg.register_config_section("ok", "notadict")  # type: ignore[arg-type]


def test_registry_mark_plugin_loaded_and_accessors():
    reg = PluginRegistry()
    m = _make_manifest(name="foo")
    reg.mark_plugin_loaded(m)
    assert reg.loaded_plugins == {"foo": m}


def test_registry_reset_clears_everything():
    reg = PluginRegistry()

    class C: ...

    reg.register_attack_module(C)
    reg.register_mcp_tools(lambda mcp, ctx: None)
    reg.register_skill_dir("/x")
    reg.register_config_section("foo", {})
    reg.mark_plugin_loaded(_make_manifest(name="foo"))
    reg.reset()
    assert reg.extra_module_classes == []
    assert reg.mcp_tool_factories == []
    assert reg.skill_dirs == []
    assert reg.config_sections == {}
    assert reg.loaded_plugins == {}


def test_get_plugin_registry_returns_singleton():
    assert get_plugin_registry() is PLUGIN_REGISTRY


# ─── PluginManager.discover_filesystem ────────────────────────────────────────


def test_discover_filesystem_loads_plugin(tmp_path: Path):
    pdir = tmp_path / "foo"
    _write_plugin_yaml(pdir, {"name": "foo", "version": "1.0.0", "capabilities": ["mcp_tool"]})
    _write_plugin_py(
        pdir,
        """
        from tools.plugins import Plugin, PluginManifest, PluginRegistry

        class MyPlugin(Plugin):
            def __init__(self):
                self.manifest = PluginManifest(name="foo")
            def register(self, registry: PluginRegistry) -> None:
                registry.register_config_section("foo", {"k": "v"})

        def create_plugin():
            return MyPlugin()
        """,
    )
    reg = PluginRegistry()
    mgr = PluginManager(reg)
    plugins = mgr.discover_filesystem([tmp_path])
    assert len(plugins) == 1
    assert plugins[0].manifest.name == "foo"
    assert plugins[0].manifest.capabilities == ("mcp_tool",)


def test_discover_filesystem_skips_nonexistent_path(tmp_path: Path):
    reg = PluginRegistry()
    mgr = PluginManager(reg)
    # no raise; returns empty
    plugins = mgr.discover_filesystem([tmp_path / "does-not-exist"])
    assert plugins == []


def test_discover_filesystem_manifest_only_without_plugin_py(tmp_path: Path):
    pdir = tmp_path / "bar"
    _write_plugin_yaml(pdir, {"name": "bar"})
    reg = PluginRegistry()
    mgr = PluginManager(reg)
    plugins = mgr.discover_filesystem([tmp_path])
    assert len(plugins) == 1
    p = plugins[0]
    assert p.manifest.name == "bar"
    # register() is a no-op
    before = dict(reg.loaded_plugins)
    p.register(reg)
    assert reg.loaded_plugins == before
    assert reg.config_sections == {}


def test_discover_filesystem_plugin_py_with_Plugin_subclass(tmp_path: Path):
    pdir = tmp_path / "baz"
    _write_plugin_yaml(pdir, {"name": "baz"})
    _write_plugin_py(
        pdir,
        """
        from tools.plugins import Plugin, PluginManifest, PluginRegistry

        class Plugin(Plugin):  # noqa: F811 - re-export name is intentional
            def __init__(self):
                self.manifest = PluginManifest(name="baz")
            def register(self, registry: PluginRegistry) -> None:
                registry.register_skill_dir("/skills/baz")
        """,
    )
    reg = PluginRegistry()
    mgr = PluginManager(reg)
    plugins = mgr.discover_filesystem([tmp_path])
    assert len(plugins) == 1
    assert plugins[0].manifest.name == "baz"
    plugins[0].register(reg)
    assert reg.skill_dirs == [Path("/skills/baz")]


def test_discover_filesystem_bad_plugin_py_skipped(tmp_path: Path):
    pdir = tmp_path / "broken"
    _write_plugin_yaml(pdir, {"name": "broken"})
    _write_plugin_py(pdir, "raise RuntimeError('boom on import')\n")
    reg = PluginRegistry()
    mgr = PluginManager(reg)
    plugins = mgr.discover_filesystem([tmp_path])
    # manifest-only fallback; never raises
    assert len(plugins) == 1
    assert plugins[0].manifest.name == "broken"


def test_discover_filesystem_ignores_non_plugin_subdirs(tmp_path: Path):
    (tmp_path / "notaplugin").mkdir()
    (tmp_path / "notaplugin" / "random.txt").write_text("hi", encoding="utf-8")
    reg = PluginRegistry()
    mgr = PluginManager(reg)
    assert mgr.discover_filesystem([tmp_path]) == []


# ─── PluginManager.discover_entry_points ──────────────────────────────────────


class _FakeEP:
    def __init__(self, name: str, obj):
        self.name = name
        self._obj = obj

    def load(self):
        return self._obj


def test_discover_entry_points_with_injected_loader():
    class EP(Plugin):
        def __init__(self):
            self.manifest = PluginManifest(name="epplugin", enabled=True)

        def register(self, registry: PluginRegistry) -> None:
            registry.register_config_section("epplugin", {})

    def loader(group: str):
        assert group == "netattackai.plugins"
        return [_FakeEP("epplugin", EP)]

    reg = PluginRegistry()
    mgr = PluginManager(reg)
    plugins = mgr.discover_entry_points(loader=loader)
    assert len(plugins) == 1
    assert plugins[0].manifest.name == "epplugin"


def test_discover_entry_points_factory_returning_plugin():
    class P(Plugin):
        def __init__(self):
            self.manifest = PluginManifest(name="factoryplug")

        def register(self, registry: PluginRegistry) -> None: ...

    def loader(group: str):
        return [_FakeEP("factoryplug", lambda: P())]

    reg = PluginRegistry()
    mgr = PluginManager(reg)
    plugins = mgr.discover_entry_points(loader=loader)
    assert len(plugins) == 1
    assert plugins[0].manifest.name == "factoryplug"


def test_discover_entry_points_tolerates_load_failure():
    class BadEP:
        def load(self):
            raise ValueError("nope")

    def loader(group: str):
        return [BadEP()]

    reg = PluginRegistry()
    mgr = PluginManager(reg)
    assert mgr.discover_entry_points(loader=loader) == []


# ─── PluginManager.load_all enablement gating ─────────────────────────────────


def _fs_plugin(tmp_path: Path, name: str, *, enabled: bool = False) -> Path:
    pdir = tmp_path / name
    _write_plugin_yaml(pdir, {"name": name, "enabled": "true" if enabled else "false"})
    _write_plugin_py(
        pdir,
        f"""
        from tools.plugins import Plugin, PluginManifest, PluginRegistry

        class P(Plugin):
            def __init__(self):
                self.manifest = PluginManifest(name="{name}")
            def register(self, registry: PluginRegistry) -> None:
                registry.register_config_section("{name}", {{}})

        def create_plugin():
            return P()
        """,
    )
    return pdir


def test_load_all_default_off_when_enabled_none_and_manifest_disabled(tmp_path: Path):
    _fs_plugin(tmp_path, "foo", enabled=False)
    reg = PluginRegistry()
    mgr = PluginManager(reg, enabled=None)
    loaded = mgr.load_all([tmp_path], entry_points=False)
    assert loaded == []
    assert reg.loaded_plugins == {}


def test_load_all_enabled_list_loads_named_plugin(tmp_path: Path):
    _fs_plugin(tmp_path, "foo", enabled=False)
    _fs_plugin(tmp_path, "bar", enabled=False)
    reg = PluginRegistry()
    mgr = PluginManager(reg, enabled=["foo"])
    loaded = mgr.load_all([tmp_path], entry_points=False)
    assert [m.name for m in loaded] == ["foo"]
    assert "foo" in reg.loaded_plugins
    assert "bar" not in reg.loaded_plugins


def test_load_all_manifest_enabled_loads_when_enabled_none(tmp_path: Path):
    _fs_plugin(tmp_path, "foo", enabled=True)
    reg = PluginRegistry()
    mgr = PluginManager(reg, enabled=None)
    loaded = mgr.load_all([tmp_path], entry_points=False)
    assert [m.name for m in loaded] == ["foo"]
    assert "foo" in reg.loaded_plugins


def test_load_all_disabled_overrides_manifest_enabled(tmp_path: Path):
    _fs_plugin(tmp_path, "foo", enabled=True)
    reg = PluginRegistry()
    mgr = PluginManager(reg, enabled=None, disabled=["foo"])
    loaded = mgr.load_all([tmp_path], entry_points=False)
    assert loaded == []
    assert reg.loaded_plugins == {}


def test_load_all_register_failure_skips_without_aborting_siblings(tmp_path: Path):
    good = tmp_path / "good"
    _write_plugin_yaml(good, {"name": "good", "enabled": "true"})
    _write_plugin_py(
        good,
        """
        from tools.plugins import Plugin, PluginManifest, PluginRegistry
        class P(Plugin):
            def __init__(self):
                self.manifest = PluginManifest(name="good", enabled=True)
            def register(self, registry: PluginRegistry) -> None:
                registry.register_config_section("good", {})
        def create_plugin():
            return P()
        """,
    )
    bad = tmp_path / "bad"
    _write_plugin_yaml(bad, {"name": "bad", "enabled": "true"})
    _write_plugin_py(
        bad,
        """
        from tools.plugins import Plugin, PluginManifest, PluginRegistry
        class P(Plugin):
            def __init__(self):
                self.manifest = PluginManifest(name="bad", enabled=True)
            def register(self, registry: PluginRegistry) -> None:
                raise RuntimeError("register boom")
        def create_plugin():
            return P()
        """,
    )
    reg = PluginRegistry()
    mgr = PluginManager(reg, enabled=None)
    loaded = mgr.load_all([tmp_path], entry_points=False)
    loaded_names = sorted(m.name for m in loaded)
    assert "good" in loaded_names
    assert "bad" not in loaded_names
    assert "good" in reg.loaded_plugins
    assert "bad" not in reg.loaded_plugins


def test_load_all_entry_points_combined_with_filesystem(tmp_path: Path):
    _fs_plugin(tmp_path, "fsplug", enabled=True)

    class EP(Plugin):
        def __init__(self):
            self.manifest = PluginManifest(name="epplug", enabled=True)

        def register(self, registry: PluginRegistry) -> None:
            registry.register_config_section("epplug", {})

    reg = PluginRegistry()
    mgr = PluginManager(reg, enabled=None)
    loaded = mgr.load_all(
        [tmp_path],
        entry_points=True,
        entry_point_loader=lambda group: [_FakeEP("epplug", EP)],
    )
    names = sorted(m.name for m in loaded)
    assert names == ["epplug", "fsplug"]


# ─── load_plugins / list_discovered_plugins ───────────────────────────────────


def test_load_plugins_reads_config(tmp_path: Path):
    _fs_plugin(tmp_path, "foo", enabled=False)
    cfg = {
        "plugins": {
            "enabled": ["foo"],
            "disabled": [],
            "search_paths": [str(tmp_path)],
            "entry_points": False,
        }
    }
    loaded = load_plugins(cfg, entry_point_loader=lambda group: [])
    assert [m.name for m in loaded] == ["foo"]
    assert "foo" in PLUGIN_REGISTRY.loaded_plugins


def test_load_plugins_tolerant_of_missing_config(tmp_path):
    # Missing config -> no plugins configured. Scope the search path to an
    # empty dir so the result is deterministic: shipped plugins under plugins/
    # default to enabled and would otherwise load here.
    loaded = load_plugins(
        None,
        search_paths=[str(tmp_path)],
        entry_point_loader=lambda group: [],
    )
    assert loaded == []


def test_load_plugins_tolerant_of_partial_config(tmp_path: Path):
    _fs_plugin(tmp_path, "foo", enabled=True)
    # only enabled given; search_paths defaults to ["plugins"], which likely
    # does not exist -> no discovery -> empty. Use explicit search_paths.
    loaded = load_plugins(
        {"plugins": {"enabled": ["foo"]}},
        search_paths=[str(tmp_path)],
        entry_point_loader=lambda group: [],
    )
    assert [m.name for m in loaded] == ["foo"]


def test_load_plugins_disabled_filters(tmp_path: Path):
    _fs_plugin(tmp_path, "foo", enabled=True)
    cfg = {
        "plugins": {
            "disabled": ["foo"],
            "search_paths": [str(tmp_path)],
            "entry_points": False,
        }
    }
    loaded = load_plugins(cfg, entry_point_loader=lambda group: [])
    assert loaded == []
    assert "foo" not in PLUGIN_REGISTRY.loaded_plugins


def test_list_discovered_plugins_shape(tmp_path: Path):
    _fs_plugin(tmp_path, "foo", enabled=True)
    _fs_plugin(tmp_path, "bar", enabled=False)
    load_plugins(
        {
            "plugins": {
                "enabled": ["foo"],
                "search_paths": [str(tmp_path)],
                "entry_points": False,
            }
        },
        entry_point_loader=lambda group: [],
    )
    listed = list_discovered_plugins()
    by_name = {d["name"]: d for d in listed}
    assert set(by_name) == {"foo", "bar"}
    foo = by_name["foo"]
    assert set(foo.keys()) == {
        "name",
        "version",
        "description",
        "author",
        "capabilities",
        "loaded",
        "enabled",
        "config_section",
    }
    assert foo["loaded"] is True
    assert by_name["bar"]["loaded"] is False


def test_list_discovered_plugins_empty_when_nothing_discovered():
    # Hermetic: pass an empty search-path list so the real repo ``plugins/``
    # directory is not scanned, and an empty entry-point loader so no
    # installed-package plugins are discovered either.
    load_plugins(None, search_paths=[], entry_point_loader=lambda group: [])
    assert list_discovered_plugins() == []


# ─── Plugin ABC ───────────────────────────────────────────────────────────────


def test_plugin_abc_cannot_instantiate_without_register():
    with pytest.raises(TypeError):
        Plugin()  # type: ignore[abstract]


# ─── import hygiene ───────────────────────────────────────────────────────────


def test_no_flow_b_imports_at_runtime():
    """plugins.py must not import any Flow B entanglement modules."""
    import subprocess

    forbidden = [
        "tools.recon_pipeline",
        "tools.scope_gate",
        "tools.mission",
        "tools.db",
        "tools.agent_loop",
        "tools.tool_router",
        "tools.risk_controller",
        "tools.safety_reviewer",
    ]
    code = (
        "import sys\n"
        "import tools.plugins\n"
        "loaded = set(sys.modules.keys())\n"
        "forbidden = {!r}\n"
        "print('|'.join(sorted(set(forbidden) & loaded)))\n"
    ).format(forbidden)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(Path(__file__).resolve().parent.parent),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    leaked = [m for m in proc.stdout.strip().split("|") if m]
    assert not leaked, f"plugins.py pulled in Flow B modules: {leaked}"
    # module file must not reference these names
    src = Path(__file__).resolve().parent.parent / "tools" / "plugins.py"
    text = src.read_text(encoding="utf-8")
    for name in forbidden:
        assert name not in text, f"plugins.py references {name}"


def test_manifest_only_plugin_is_a_plugin_subclass():
    from tools.plugins import _ManifestOnlyPlugin

    m = PluginManifest(name="x")
    p = _ManifestOnlyPlugin(m)
    assert isinstance(p, Plugin)
    assert p.manifest is m
