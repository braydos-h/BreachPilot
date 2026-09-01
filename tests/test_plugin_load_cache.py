"""Tests for the plugin load cache (tools.plugins.load_plugins).

Run creation used to call ``load_plugins`` on every POST /runs: each call
re-walked the search paths, re-imported every plugin.py, and re-registered
into the process-wide singleton registry — duplicating every registration
once per run. The load result is now cached per config signature; these tests
verify caching, invalidation, and thread safety.
"""

from __future__ import annotations

import textwrap
import threading
from pathlib import Path

from tools.plugins import (
    PLUGIN_REGISTRY,
    get_plugin_registry,
    load_plugins,
    reset_plugin_load_cache,
)


def _write_plugin(root: Path, name: str, *, enabled: bool = True, with_module: bool = True) -> None:
    plugin_dir = root / name
    plugin_dir.mkdir(parents=True, exist_ok=True)
    (plugin_dir / "plugin.yaml").write_text(
        f"name: {name}\nversion: 1.0.0\ndescription: test\ncapabilities:\n  - attack_module\n"
        f"enabled: {'true' if enabled else 'false'}\n",
        encoding="utf-8",
    )
    if with_module:
        (plugin_dir / "plugin.py").write_text(
            textwrap.dedent(
                """
                from tools.plugins import Plugin, PluginManifest

                class Plugin(Plugin):
                    manifest = PluginManifest(name="__manifest__")

                    def register(self, registry):
                        registry.register_attack_module(type("Mod", (), {}))
                """
            ),
            encoding="utf-8",
        )


def _config(root: Path, *, enabled: list[str] | None = None) -> dict:
    return {
        "plugins": {
            "enabled": enabled if enabled is not None else ["foo"],
            "search_paths": [str(root)],
            "entry_points": False,
        }
    }


def test_repeat_load_with_same_config_does_not_duplicate_registrations(tmp_path):
    """The old behavior re-registered the plugin into the singleton registry on
    every load_plugins call (duplicate MCP tool factories / skill dirs)."""
    _write_plugin(tmp_path, "foo")
    cfg = _config(tmp_path)
    first = load_plugins(cfg)
    assert [m.name for m in first] == ["foo"]
    count_after_first = len(PLUGIN_REGISTRY.extra_module_classes)
    assert count_after_first == 1

    second = load_plugins(cfg)
    third = load_plugins(cfg)
    assert [m.name for m in second] == ["foo"]
    assert [m.name for m in third] == ["foo"]
    # The registry saw exactly ONE registration despite three loads.
    assert len(PLUGIN_REGISTRY.extra_module_classes) == count_after_first


def test_cache_invalidated_when_plugin_config_changes(tmp_path):
    root = tmp_path / "p1"
    _write_plugin(root, "foo")
    _write_plugin(root, "bar")
    on = load_plugins(_config(root, enabled=["foo"]))
    assert [m.name for m in on] == ["foo"]

    # Changing the enabled list must trigger a real reload.
    both = load_plugins(_config(root, enabled=["foo", "bar"]))
    assert sorted(m.name for m in both) == ["bar", "foo"]


def test_reset_plugin_load_cache_forces_reload(tmp_path):
    _write_plugin(tmp_path, "foo")
    cfg = _config(tmp_path)
    load_plugins(cfg)
    reset_plugin_load_cache()
    load_plugins(cfg)
    # Registry.reset() also clears the cache — either way a fresh load must
    # leave exactly one registration (not two).
    assert len(PLUGIN_REGISTRY.extra_module_classes) == 1


def test_concurrent_loads_are_thread_safe_and_load_once(tmp_path):
    """N threads calling load_plugins with an unchanged config must produce
    exactly one discovery + one registration (no duplicate registrations, no
    torn state)."""
    _write_plugin(tmp_path, "foo")
    cfg = _config(tmp_path)
    results: list[list[str]] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def _worker() -> None:
        try:
            barrier.wait(timeout=5)
            loaded = load_plugins(cfg)
            results.append(sorted(m.name for m in loaded))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert not errors, errors
    assert len(results) == 8
    assert all(r == ["foo"] for r in results)
    assert len(get_plugin_registry().extra_module_classes) == 1
