"""Compatibility shim — re-exports from :mod:`tools.paths`."""

from tools.paths import (  # noqa: F401
    ensure_runtime_dir,
    get_packaged_config_path,
    get_packaged_skills_dir,
    get_skill_roots_for_display,
    get_webui_dist_dir,
    is_packaged_resource,
    load_config_or_defaults,
    load_effective_config,
    resolve_config_path,
    resolve_skill_roots,
)

__all__ = [
    "ensure_runtime_dir",
    "get_packaged_config_path",
    "get_packaged_skills_dir",
    "get_skill_roots_for_display",
    "get_webui_dist_dir",
    "is_packaged_resource",
    "load_config_or_defaults",
    "load_effective_config",
    "resolve_config_path",
    "resolve_skill_roots",
]
