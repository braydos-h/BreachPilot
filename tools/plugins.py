"""Plugin manager for BreachPilot (lab build).

Plugins are *trusted* Python packages that extend the engine with attack
modules, MCP tools, skill directories, and config sections. A plugin is a
directory containing a ``plugin.yaml`` manifest and (optionally) a sibling
``plugin.py`` module that exposes a ``create_plugin()`` factory or a ``Plugin``
subclass. Plugins may also be distributed as importlib entry points in the
``breachpilot.plugins`` group.

SAFETY (lab build)
------------------
Plugins are NOT sandboxed. They run with full operator-box privileges, exactly
like the built-in ``tools/mcp_tools/*`` modules. The plugin manager enforces
only **opt-in loading** (plugins are disabled by default) and documents the
safety-decorator requirement: any MCP tool a plugin registers MUST wrap its
handler with ``ctx.require_allowlist()`` (target-touching tools) or
``ctx.audit_tool`` (free-text command tools) so the target-IP allowlist lock
and JSONL audit trail still apply. The manager does not and cannot verify
this at load time -- it is the plugin author's responsibility.

Hard-blocked plugin behaviours (regardless of opt-in): log clearing,
timestomping, EDR/AV defeat, denial of service, malware distribution. These
are policy expectations documented here; the manager itself does not execute
plugin code beyond calling ``register()``.

This module is pure stdlib (importlib, importlib.metadata, dataclasses,
pathlib, typing, re). No import-time network/time/random. All discovery
surfaces (entry points, search paths) accept injectable fakes so the test
suite never touches the real filesystem entry-point database.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import logging
import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("tools.plugins")

# ─── Capability vocabulary ────────────────────────────────────────────────────
_VALID_CAPABILITIES = ("attack_module", "mcp_tool", "skill_dir", "config", "event_subscriber")

# ─── Minimal YAML parser (stdlib only) ────────────────────────────────────────
# plugin.yaml manifests use a tiny YAML subset: scalar key/value pairs, block
# lists ("- item"), flow lists (["a", "b"]), one level of nested mapping for
# ``config_section``, comments (#), and quoted strings. We do not depend on
# PyYAML so this module stays pure-stdlib.

_INT_RE = re.compile(r"-?\d+$")


def _indent(line: str) -> int:
    n = 0
    for ch in line:
        if ch == " ":
            n += 1
        else:
            break
    return n


def _split_flow(s: str) -> list[str]:
    """Split a flow-list inner string on commas not inside quotes."""
    items: list[str] = []
    cur: list[str] = []
    in_q: str | None = None
    for ch in s:
        if in_q is not None:
            cur.append(ch)
            if ch == in_q:
                in_q = None
        elif ch in ('"', "'"):
            in_q = ch
            cur.append(ch)
        elif ch == ",":
            items.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        items.append(tail)
    return items


def _parse_scalar(s: str) -> Any:
    s = s.strip()
    if not s:
        return ""
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item) for item in _split_flow(inner)]
    low = s.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "~", "none"):
        return None
    if _INT_RE.fullmatch(s):
        try:
            return int(s)
        except ValueError:
            pass
    return s


def _parse_list(lines: list[str], start: int, indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    i = start
    while i < len(lines):
        line = lines[i]
        cur_indent = _indent(line)
        if cur_indent < indent:
            break
        if cur_indent > indent:
            # unexpected deeper indent under a list item; skip defensively
            i += 1
            continue
        content = line.strip()
        if not content.startswith("- "):
            break
        val = content[2:].strip()
        items.append(_parse_scalar(val))
        i += 1
    return items, i


def _parse_block(lines: list[str], start: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    i = start
    while i < len(lines):
        line = lines[i]
        cur_indent = _indent(line)
        if cur_indent < indent:
            break
        if cur_indent > indent:
            i += 1
            continue
        content = line.strip()
        if content.startswith("- "):
            # a list at this indent level is not part of a mapping; bail
            break
        if ":" not in content:
            i += 1
            continue
        key, _, rest = content.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest:
            result[key] = _parse_scalar(rest)
            i += 1
        else:
            # nested block: peek next non-blank line
            j = i + 1
            if j < len(lines):
                next_indent = _indent(lines[j])
                if next_indent > cur_indent:
                    nxt = lines[j].strip()
                    if nxt.startswith("- "):
                        sub, i = _parse_list(lines, j, next_indent)
                        result[key] = sub
                    else:
                        sub, i = _parse_block(lines, j, next_indent)
                        result[key] = sub
                else:
                    result[key] = None
                    i += 1
            else:
                result[key] = None
                i += 1
    return result, i


def _parse_manifest_yaml(text: str) -> dict[str, Any]:
    """Parse the restricted YAML subset used by plugin manifests."""
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(line)
    if not lines:
        return {}
    base_indent = _indent(lines[0])
    parsed, _ = _parse_block(lines, 0, base_indent)
    return parsed


# ─── Manifest ─────────────────────────────────────────────────────────────────


@dataclass
class PluginManifest:
    """Declares a plugin's identity, capabilities, and enablement default."""

    name: str
    version: str = "0.0.1"
    description: str = ""
    author: str = ""
    capabilities: tuple[str, ...] = ()
    enabled: bool = False  # manifest default; config plugins.enabled overrides
    config_section: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> PluginManifest:
        d = dict(d or {})
        caps = d.get("capabilities") or ()
        if isinstance(caps, str):
            caps = (caps,)
        else:
            caps = tuple(caps)
        # Tolerantly filter to known capabilities; unknown ones are dropped with a warning.
        if caps:
            known = tuple(c for c in caps if c in _VALID_CAPABILITIES)
            if len(known) != len(caps):
                dropped = [c for c in caps if c not in _VALID_CAPABILITIES]
                log.warning("plugin %s: dropping unknown capabilities %s", d.get("name", "?"), dropped)
            caps = known
        config_section = d.get("config_section")
        if config_section is not None and not isinstance(config_section, dict):
            log.warning("plugin %s: config_section is not a mapping, ignoring", d.get("name", "?"))
            config_section = None
        return cls(
            name=str(d.get("name", "")),
            version=str(d.get("version", "0.0.1")),
            description=str(d.get("description", "")),
            author=str(d.get("author", "")),
            capabilities=caps,
            enabled=bool(d.get("enabled", False)),
            config_section=config_section,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "capabilities": list(self.capabilities),
            "enabled": self.enabled,
            "config_section": self.config_section,
        }


# ─── Plugin base class ────────────────────────────────────────────────────────


class Plugin(ABC):
    """Base class plugins implement. Subclasses set ``.manifest`` and implement ``register()``."""

    manifest: PluginManifest

    @abstractmethod
    def register(self, registry: PluginRegistry) -> None:
        """Contribute registrations (attack modules, MCP tools, skills, config) to ``registry``."""
        raise NotImplementedError


class _ManifestOnlyPlugin(Plugin):
    """A plugin that only carries a manifest (no plugin.py / no register logic).

    ``register()`` is a no-op so it can be passed through the same load pipeline
    as real plugins without side effects.
    """

    def __init__(self, manifest: PluginManifest) -> None:
        self.manifest = manifest

    def register(self, registry: PluginRegistry) -> None:  # noqa: ARG002
        return None


# ─── Registry ─────────────────────────────────────────────────────────────────


class PluginRegistry:
    """Holds dynamic registrations contributed by loaded plugins.

    Existing core registries (attack-module registry, MCP tool wiring, skill
    loader, config validator) consult this singleton via its accessors.
    """

    def __init__(self) -> None:
        self._extra_module_classes: list[type] = []
        self._mcp_tool_factories: list[Callable[[Any, Any], None]] = []
        self._skill_dirs: list[Path] = []
        self._config_sections: dict[str, dict[str, Any]] = {}
        self._loaded_plugins: dict[str, PluginManifest] = {}
        self._event_subscribers: list[Callable[[dict[str, Any]], None]] = []

    def register_attack_module(self, cls: type) -> None:
        """Append an AttackModule subclass to the extra-modules list."""
        if not isinstance(cls, type):
            raise TypeError("register_attack_module requires a class")
        self._extra_module_classes.append(cls)

    def register_mcp_tools(self, factory: Callable[[Any, Any], None]) -> None:
        """Register a factory(mcp, ctx) that adds @mcp.tool() handlers.

        The factory MUST wrap each target-touching handler with
        ``ctx.require_allowlist()`` and each free-text command tool with
        ``ctx.audit_tool`` so the target-IP allowlist lock + audit trail apply.
        """
        if not callable(factory):
            raise TypeError("register_mcp_tools requires a callable factory")
        self._mcp_tool_factories.append(factory)

    def register_skill_dir(self, path: Path | str) -> None:
        """Append a skill directory to contribute to load_skill_registry roots."""
        self._skill_dirs.append(Path(path))

    def register_config_section(self, name: str, schema: dict[str, Any]) -> None:
        """Register a plugin config block name + its schema dict."""
        if not isinstance(name, str) or not name:
            raise ValueError("config section name must be a non-empty string")
        if not isinstance(schema, dict):
            raise TypeError("config section schema must be a dict")
        self._config_sections[name] = schema

    def register_event_subscriber(self, fn: Callable[[dict[str, Any]], None]) -> None:
        """Register a synchronous callable that receives every emitted run event.

        The subscriber receives the full event dict (``{sequence, timestamp,
        run_id, type, payload}``) AFTER it has been persisted to JSONL. It MUST
        be non-blocking and MUST NOT raise -- a failure in one subscriber is
        swallowed so it never blocks the run or kills sibling subscribers.
        Outbound-only (webhook/ticketing) subscribers belong here.
        """
        if not callable(fn):
            raise TypeError("register_event_subscriber requires a callable")
        self._event_subscribers.append(fn)

    def mark_plugin_loaded(self, manifest: PluginManifest) -> None:
        """Record a loaded plugin manifest by name."""
        self._loaded_plugins[manifest.name] = manifest

    @property
    def extra_module_classes(self) -> list[type]:
        return self._extra_module_classes

    @property
    def mcp_tool_factories(self) -> list[Callable[[Any, Any], None]]:
        return self._mcp_tool_factories

    @property
    def skill_dirs(self) -> list[Path]:
        return self._skill_dirs

    @property
    def config_sections(self) -> dict[str, dict[str, Any]]:
        return self._config_sections

    @property
    def loaded_plugins(self) -> dict[str, PluginManifest]:
        return self._loaded_plugins

    @property
    def event_subscribers(self) -> list[Callable[[dict[str, Any]], None]]:
        return self._event_subscribers

    def reset(self) -> None:
        """Clear all registrations (for tests)."""
        self._extra_module_classes.clear()
        self._mcp_tool_factories.clear()
        self._skill_dirs.clear()
        self._config_sections.clear()
        self._loaded_plugins.clear()
        self._event_subscribers.clear()
        # A reset clears the load cache too: the next load_plugins() call must
        # re-run discovery so tests that reset the registry see fresh state.
        reset_plugin_load_cache()


# ─── Manager ──────────────────────────────────────────────────────────────────

# Module-level discovered-manifest cache, populated during discovery so
# ``list_discovered_plugins`` can report both loaded and not-loaded plugins.
_DISCOVERED_PLUGINS: list[PluginManifest] = []


def _reset_discovered() -> None:
    _DISCOVERED_PLUGINS.clear()


class PluginManager:
    """Discovers plugins from the filesystem and importlib entry points, then
    loads the enabled ones into a :class:`PluginRegistry`."""

    def __init__(
        self,
        registry: PluginRegistry,
        *,
        enabled: list[str] | None = None,
        disabled: list[str] | None = None,
        entry_point_group: str = "breachpilot.plugins",
    ) -> None:
        self._registry = registry
        self._enabled = list(enabled) if enabled is not None else None
        self._disabled = list(disabled) if disabled is not None else []
        self._entry_point_group = entry_point_group

    # ── enablement ──────────────────────────────────────────────────────────
    def _is_enabled(self, manifest: PluginManifest) -> bool:
        name = manifest.name
        if name in self._disabled:
            return False
        if self._enabled is not None:
            return name in self._enabled or bool(manifest.enabled)
        return bool(manifest.enabled)

    # ── filesystem discovery ────────────────────────────────────────────────
    def discover_filesystem(self, search_paths: list[Path | str]) -> list[Plugin]:
        """Walk each search path for plugin directories.

        A plugin directory is a subdir containing ``plugin.yaml``. The manifest
        is parsed, then a sibling ``plugin.py`` is loaded via
        :func:`importlib.util.spec_from_file_location`; its ``create_plugin()``
        factory is called (or a ``Plugin`` subclass named ``Plugin`` is
        instantiated). Tolerant: missing search paths are skipped; a plugin dir
        without ``plugin.py`` yields a manifest-only Plugin whose ``register()``
        is a no-op. NEVER raise on a bad plugin -- log a warning and skip it.
        """
        plugins: list[Plugin] = []
        for search in search_paths:
            base = Path(search)
            try:
                if not base.exists() or not base.is_dir():
                    continue
            except OSError as exc:
                log.warning("plugin search path %s unreadable: %s", base, exc)
                continue
            try:
                children = sorted(base.iterdir())
            except OSError as exc:
                log.warning("plugin search path %s not listable: %s", base, exc)
                continue
            for child in children:
                try:
                    if not child.is_dir():
                        continue
                except OSError:
                    continue
                manifest_path = child / "plugin.yaml"
                if not manifest_path.is_file():
                    continue
                plugin = self._load_filesystem_plugin(child, manifest_path)
                if plugin is not None:
                    plugins.append(plugin)
                    _DISCOVERED_PLUGINS.append(plugin.manifest)
        return plugins

    def _load_filesystem_plugin(self, plugin_dir: Path, manifest_path: Path) -> Plugin | None:
        try:
            manifest_text = manifest_path.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("plugin manifest %s unreadable: %s", manifest_path, exc)
            return None
        try:
            manifest_dict = _parse_manifest_yaml(manifest_text)
        except Exception as exc:  # noqa: BLE001
            log.warning("plugin manifest %s parse failed: %s", manifest_path, exc)
            return None
        manifest = PluginManifest.from_dict(manifest_dict)
        if not manifest.name:
            manifest.name = plugin_dir.name
        plugin_py = plugin_dir / "plugin.py"
        if not plugin_py.is_file():
            return _ManifestOnlyPlugin(manifest)
        try:
            module = self._load_module_from_file(plugin_py, plugin_dir.name)
        except Exception as exc:  # noqa: BLE001
            log.warning("plugin %s: failed to import plugin.py: %s", plugin_dir.name, exc)
            return _ManifestOnlyPlugin(manifest)
        return self._instantiate_from_module(module, manifest)

    @staticmethod
    def _load_module_from_file(path: Path, name: str):
        mod_name = f"breachpilot_plugin_{name}_{abs(hash(path))}".replace("-", "_")
        spec = importlib.util.spec_from_file_location(mod_name, str(path))
        if spec is None or spec.loader is None:
            raise ImportError(f"could not create module spec for {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _instantiate_from_module(module: Any, manifest: PluginManifest) -> Plugin:
        # The plugin.yaml manifest is authoritative for filesystem plugins; it
        # is what the operator configures (name/version/enablement/capabilities).
        # Whatever manifest the factory sets is overridden here.
        factory = getattr(module, "create_plugin", None)
        if callable(factory):
            plugin = factory()
            if isinstance(plugin, Plugin):
                plugin.manifest = manifest
                return plugin
            # factory returned a class; try to use as Plugin subclass
            if isinstance(plugin, type) and issubclass(plugin, Plugin) and plugin is not Plugin:
                inst = plugin()
                inst.manifest = manifest
                return inst
            log.warning("plugin %s: create_plugin() did not return a Plugin", manifest.name)
            return _ManifestOnlyPlugin(manifest)
        plugin_cls = getattr(module, "Plugin", None)
        if isinstance(plugin_cls, type) and issubclass(plugin_cls, Plugin) and plugin_cls is not Plugin:
            inst = plugin_cls()
            inst.manifest = manifest
            return inst
        log.warning("plugin %s: plugin.py has no create_plugin() or Plugin subclass", manifest.name)
        return _ManifestOnlyPlugin(manifest)

    # ── entry-point discovery ───────────────────────────────────────────────
    def discover_entry_points(self, *, loader: Callable[[str], list[Any]] | None = None) -> list[Plugin]:
        """Discover plugins via importlib entry points.

        ``loader`` is an injectable ``callable(group: str) -> list`` of fake
        entry-point objects, each with a ``.load()`` method. When ``loader`` is
        None, the real :mod:`importlib.metadata` is used. Each entry point's
        ``.load()`` returns a ``create_plugin`` factory or a ``Plugin``
        subclass; instantiate. Tolerant of errors (skip + warn).
        """
        plugins: list[Plugin] = []
        try:
            eps = self._entry_points(loader)
        except Exception as exc:  # noqa: BLE001
            log.warning("entry-point discovery failed: %s", exc)
            return plugins
        for ep in eps:
            try:
                obj = ep.load()
            except Exception as exc:  # noqa: BLE001
                log.warning("entry point %s: load() failed: %s", getattr(ep, "name", "?"), exc)
                continue
            plugin = self._coerce_entry_point(obj, getattr(ep, "name", "?"))
            if plugin is not None:
                plugins.append(plugin)
                _DISCOVERED_PLUGINS.append(plugin.manifest)
        return plugins

    def _entry_points(self, loader: Callable[[str], list[Any]] | None) -> list[Any]:
        if loader is not None:
            return list(loader(self._entry_point_group))
        try:
            all_eps = importlib.metadata.entry_points()
        except Exception:  # noqa: BLE001
            return []
        # importlib.metadata.entry_points returns EntryPoints or dict-like across versions
        if hasattr(all_eps, "select"):
            try:
                return list(all_eps.select(group=self._entry_point_group))
            except Exception:  # noqa: BLE001
                return []
        # older dict-style fallback
        try:
            return list(all_eps.get(self._entry_point_group, []))
        except Exception:  # noqa: BLE001
            return []

    @staticmethod
    def _coerce_entry_point(obj: Any, ep_name: str) -> Plugin | None:
        if isinstance(obj, Plugin):
            return obj
        if callable(obj):
            try:
                result = obj()
            except Exception as exc:  # noqa: BLE001
                log.warning("entry point %s: factory call failed: %s", ep_name, exc)
                return None
            if isinstance(result, Plugin):
                return result
            if isinstance(result, type) and issubclass(result, Plugin):
                try:
                    return result()
                except Exception as exc:  # noqa: BLE001
                    log.warning("entry point %s: Plugin instantiation failed: %s", ep_name, exc)
                    return None
            log.warning("entry point %s: did not yield a Plugin instance", ep_name)
            return None
        if isinstance(obj, type) and issubclass(obj, Plugin):
            try:
                return obj()
            except Exception as exc:  # noqa: BLE001
                log.warning("entry point %s: Plugin instantiation failed: %s", ep_name, exc)
                return None
        log.warning("entry point %s: unsupported object %r", ep_name, type(obj))
        return None

    # ── load all ────────────────────────────────────────────────────────────
    def load_all(
        self,
        search_paths: list[Path | str],
        *,
        entry_points: bool = True,
        entry_point_loader: Callable[[str], list[Any]] | None = None,
    ) -> list[PluginManifest]:
        """Discover, filter to enabled plugins, and register each.

        Returns the list of loaded :class:`PluginManifest`. A plugin is loaded
        iff (``self._enabled`` is None -> use ``manifest.enabled``; otherwise
        ``name in self._enabled`` OR ``manifest.enabled``) AND ``name`` not in
        ``self._disabled``. Default OFF when ``enabled`` is None and the
        manifest does not opt in. Each ``register()`` is wrapped so one bad
        plugin does not abort the rest.
        """
        _reset_discovered()
        discovered: list[Plugin] = self.discover_filesystem(search_paths)
        if entry_points:
            discovered.extend(self.discover_entry_points(loader=entry_point_loader))
        # discover_filesystem / discover_entry_points already recorded manifests
        # into _DISCOVERED_PLUGINS (after the reset above).
        loaded: list[PluginManifest] = []
        for plugin in discovered:
            manifest = plugin.manifest
            if not self._is_enabled(manifest):
                continue
            try:
                plugin.register(self._registry)
            except Exception as exc:  # noqa: BLE001
                log.warning("plugin %s: register() failed: %s", manifest.name, exc)
                continue
            self._registry.mark_plugin_loaded(manifest)
            loaded.append(manifest)
        return loaded


# ─── Module-level singleton + helpers ─────────────────────────────────────────

PLUGIN_REGISTRY = PluginRegistry()


def get_plugin_registry() -> PluginRegistry:
    """Return the process-wide :class:`PluginRegistry` singleton."""
    return PLUGIN_REGISTRY


# ─── load_plugins cache ───────────────────────────────────────────────────────
# ``load_plugins`` re-walks every search path, re-imports each plugin.py, and
# re-registers into the SINGLETON registry. Calling it per run creation (the
# old behavior on the WebUI create-run path) cost ~70-135ms per run AND
# duplicated every registration (extra module classes, MCP tool factories,
# skill dirs, event subscribers) once per call. Discovery output depends only
# on the plugins config + the injectable loader, so the load result is cached
# by that signature: cold init happens once, warm run creation reuses it.
# ``PluginRegistry.reset()`` (tests) and :func:`reset_plugin_load_cache` clear it.

_PLUGIN_LOAD_CACHE: dict[tuple[Any, ...], list[PluginManifest]] = {}
_PLUGIN_LOAD_LOCK = threading.RLock()


def _plugin_load_signature(
    enabled: Any,
    disabled: Any,
    paths: list[str],
    entry_points_flag: bool,
    entry_point_loader: Any,
) -> tuple[Any, ...]:
    return (
        tuple(enabled) if isinstance(enabled, list) else enabled,
        tuple(disabled) if isinstance(disabled, list) else disabled,
        tuple(str(p) for p in paths),
        entry_points_flag,
        entry_point_loader,
    )


def reset_plugin_load_cache() -> None:
    """Drop the cached plugin-load result (tests; config/file changes)."""
    with _PLUGIN_LOAD_LOCK:
        _PLUGIN_LOAD_CACHE.clear()
    # The cache is what prevents re-registration on repeated loads with the
    # same config. Clearing the cache without clearing the registry would
    # cause the next load to duplicate every registration (the test
    # ``test_reset_plugin_load_cache_forces_reload`` expects exactly one).
    # Clear the registry's plugin state as well so a cache reset + reload is
    # idempotent. ``reset()`` already clears these collections directly and
    # then calls us, so this is not recursive.
    try:
        PLUGIN_REGISTRY._extra_module_classes.clear()  # type: ignore[attr-defined]
        PLUGIN_REGISTRY._mcp_tool_factories.clear()  # type: ignore[attr-defined]
        PLUGIN_REGISTRY._skill_dirs.clear()  # type: ignore[attr-defined]
        PLUGIN_REGISTRY._config_sections.clear()  # type: ignore[attr-defined]
        PLUGIN_REGISTRY._loaded_plugins.clear()  # type: ignore[attr-defined]
        PLUGIN_REGISTRY._event_subscribers.clear()  # type: ignore[attr-defined]
        _DISCOVERED_PLUGINS.clear()
    except Exception:
        pass


def load_plugins(
    config: dict[str, Any] | None = None,
    *,
    search_paths: list[Path | str] | None = None,
    entry_point_loader: Callable[[str], list[Any]] | None = None,
) -> list[PluginManifest]:
    """Load plugins according to ``config["plugins"]``.

    Reads ``enabled`` (list), ``disabled`` (list), ``search_paths`` (list), and
    ``entry_points`` (bool). Defaults: ``search_paths=["plugins"]``,
    ``entry_points=True``. Tolerant of missing config.

    Result is cached per (enabled, disabled, search_paths, entry_points,
    loader) signature: repeated calls with an unchanged config return the
    first load's manifests without re-discovering/re-registering (discovery
    appends to the process-wide singleton registry, so re-running it would
    duplicate every registration). Call :func:`reset_plugin_load_cache` after
    changing plugin files on disk.
    """
    plugins_cfg: dict[str, Any] = {}
    if isinstance(config, dict):
        plugins_cfg = config.get("plugins") or {}
    if not isinstance(plugins_cfg, dict):
        plugins_cfg = {}
    enabled = plugins_cfg.get("enabled")
    disabled = plugins_cfg.get("disabled")
    cfg_search = plugins_cfg.get("search_paths")
    if search_paths is not None:
        paths = list(search_paths)
    elif isinstance(cfg_search, list):
        paths = list(cfg_search)
    else:
        paths = ["plugins"]
    entry_points_flag = bool(plugins_cfg.get("entry_points", True))
    signature = _plugin_load_signature(enabled, disabled, paths, entry_points_flag, entry_point_loader)
    with _PLUGIN_LOAD_LOCK:
        cached = _PLUGIN_LOAD_CACHE.get(signature)
        if cached is not None:
            return list(cached)
        manager = PluginManager(
            PLUGIN_REGISTRY,
            enabled=enabled if isinstance(enabled, list) else None,
            disabled=disabled if isinstance(disabled, list) else None,
        )
        loaded = manager.load_all(
            paths,
            entry_points=entry_points_flag,
            entry_point_loader=entry_point_loader,
        )
        _PLUGIN_LOAD_CACHE[signature] = list(loaded)
        return loaded


def list_discovered_plugins() -> list[dict[str, Any]]:
    """Return ``{name, version, description, capabilities, loaded, enabled,
    config_section}`` dicts.

    ``loaded`` is True iff the plugin name is in
    ``PLUGIN_REGISTRY.loaded_plugins``. ``enabled`` is the manifest default
    (config plugins.enabled/disabled may still override it at load time).
    ``config_section`` is the manifest's declared config block schema (the
    gating fields like ``api_key_env`` / ``url`` / ``enabled`` the WebUI uses
    to derive a "BLOCKED: no <key>" hint without calling the tool). Intended
    for ``--list-plugins`` CLI and the ``GET /plugins`` WebUI route.
    """
    loaded_names = set(PLUGIN_REGISTRY.loaded_plugins.keys())
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for manifest in _DISCOVERED_PLUGINS:
        if manifest.name in seen:
            continue
        seen.add(manifest.name)
        out.append(
            {
                "name": manifest.name,
                "version": manifest.version,
                "description": manifest.description,
                "author": manifest.author,
                "capabilities": list(manifest.capabilities),
                "loaded": manifest.name in loaded_names,
                "enabled": manifest.enabled,
                "config_section": manifest.config_section,
            }
        )
    return out


__all__ = [
    "PluginManifest",
    "Plugin",
    "PluginRegistry",
    "PluginManager",
    "PLUGIN_REGISTRY",
    "get_plugin_registry",
    "load_plugins",
    "list_discovered_plugins",
    "reset_plugin_load_cache",
]
