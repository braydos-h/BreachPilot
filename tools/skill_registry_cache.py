"""Process-level cache for the loaded ``SkillRegistry``.

Loading the registry rglobs every configured root for ``SKILL.md`` files
(138+ files in the default catalog). Several consumers need the registry --
the main exploit loop, the runtime-skill MCP tools, the swarm, and the TUI --
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
    roots = skills.get("roots") or ["skills-to-add"]
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
    directory). The first call for a given root set loads and caches; later
    calls return the cached registry.
    """

    base = Path(base_dir or ".").resolve()
    roots = _skills_roots(config)
    key = _resolve_key(roots, base_dir=base)
    cached = _cache.get(key)
    if cached is not None:
        return cached
    registry = load_skill_registry(roots, base_dir=base)
    _cache[key] = registry
    return registry


def clear_cache() -> None:
    """Drop all cached registries (tests that mutate skill files use this)."""

    _cache.clear()