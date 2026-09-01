"""Process-level cache for the loaded ``SkillRegistry``.

Loading the registry rglobs every configured root for ``SKILL.md`` files
(138+ files in the default catalog). Several consumers need the registry --
the main exploit loop, the runtime-skill MCP tools, and the swarm --
so we cache one registry per unique set of resolved roots instead of
re-reading the disk for each consumer.

The cache is keyed by the resolved absolute root paths, so distinct configs
(or distinct ``tmp_path`` roots in tests) get distinct registries. Call
``clear_cache`` between filesystem-mutating test cases that share a root.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.skill_registry import SkillRegistry, load_skill_registry

_cache: dict[tuple[Path, ...], SkillRegistry] = {}


def _skills_roots(config: dict[str, Any] | None) -> list[str]:
    skills = (config or {}).get("skills", {}) or {}
    roots = skills.get("roots") or ["skills"]
    if isinstance(roots, str):
        roots = [roots]
    return [str(root) for root in roots if str(root).strip()]


def _resolve_key(roots: list[str], *, base_dir: Path) -> tuple[Path, ...]:
    resolved: list[Path] = []
    for root_value in roots:
        root = Path(root_value)
        if not root.is_absolute():
            root = base_dir / root
        try:
            resolved.append(root.resolve())
        except OSError:
            resolved.append(root)
    return tuple(resolved)


def get_registry(
    config: dict[str, Any] | None = None,
    *,
    base_dir: str | Path | None = None,
) -> SkillRegistry:
    """Return the cached ``SkillRegistry`` for the configured skill roots.

    Relative roots are resolved from ``base_dir`` (or the current working
    directory) when the config explicitly sets ``skills.roots``. When the
    config has no explicit roots (the common default), the **packaged**
    catalog via :func:`tools.paths.get_packaged_skills_dir` is used so a
    wheel installed to ``site-packages`` still finds the catalog without a
    repository checkout or cwd dependency.

    Explicit ``skills.roots`` values keep their intended semantics: absolute
    paths are used verbatim, relative paths are resolved from ``base_dir``
    (or cwd). The literal ``"skills"`` in an explicit list still prefers the
    packaged catalog when the cwd-relative path does not exist (keeps the
    default ``config.yaml`` working from any cwd).
    """

    skills = (config or {}).get("skills", {}) if isinstance(config, dict) else {}
    has_explicit_roots = isinstance(skills, dict) and "roots" in skills

    if base_dir is not None:
        base = Path(base_dir).resolve()
        roots = _skills_roots(config)
        key = _resolve_key(roots, base_dir=base)
        cached = _cache.get(key)
        if cached is not None:
            return cached
        registry = load_skill_registry(roots, base_dir=base)
        _cache[key] = registry
        return registry

    try:
        from tools.paths import get_packaged_skills_dir, resolve_skill_roots
    except ImportError:
        base = Path(".").resolve()
        roots = _skills_roots(config)
        key = _resolve_key(roots, base_dir=base)
        cached = _cache.get(key)
        if cached is not None:
            return cached
        registry = load_skill_registry(roots, base_dir=base)
        _cache[key] = registry
        return registry

    if not has_explicit_roots:
        pkg = get_packaged_skills_dir()
        try:
            key = (pkg.resolve(),)
        except OSError:
            key = (pkg,)
        cached = _cache.get(key)
        if cached is not None:
            return cached
        registry = load_skill_registry([str(pkg)], base_dir=str(pkg.parent) if pkg.exists() else ".")
        _cache[key] = registry
        return registry

    resolved_roots = resolve_skill_roots(config, base_dir=None, config_source_path=None)
    key = tuple(resolved_roots)
    cached = _cache.get(key)
    if cached is not None:
        return cached
    registry = load_skill_registry([str(p) for p in resolved_roots], base_dir=".")
    _cache[key] = registry
    return registry


def clear_cache() -> None:
    """Drop all cached registries (tests that mutate skill files use this)."""

    _cache.clear()
