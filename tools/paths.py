"""Path and resource abstraction for BreachPilot."""
from __future__ import annotations
import copy, os
from pathlib import Path
from typing import Any
try:
    import importlib.resources as _resources
except ImportError:
    _resources = None  # type: ignore
from tools.config.schema import CONFIG_SCHEMA
_PACKAGED_SKILLS_CACHE: Path | None = None
_PACKAGED_CONFIG_CACHE: Path | None = None
def _repo_root_from_this_file() -> Path:
    return Path(__file__).resolve().parent.parent
def get_packaged_skills_dir() -> Path:
    global _PACKAGED_SKILLS_CACHE
    if _PACKAGED_SKILLS_CACHE is not None and _PACKAGED_SKILLS_CACHE.exists():
        return _PACKAGED_SKILLS_CACHE
    if _resources is not None:
        for pkg in ("skills", "tools.skills"):
            try:
                traversable = _resources.files(pkg)  # type: ignore
                candidate = Path(str(traversable))
                if candidate.is_dir() and any(candidate.rglob("SKILL.md")):
                    _PACKAGED_SKILLS_CACHE = candidate
                    return candidate
                if candidate.is_dir():
                    _PACKAGED_SKILLS_CACHE = candidate
                    return candidate
            except Exception:
                continue
    repo_root = _repo_root_from_this_file()
    candidate = repo_root / "skills"
    if candidate.is_dir():
        _PACKAGED_SKILLS_CACHE = candidate
        return candidate
    _PACKAGED_SKILLS_CACHE = Path("skills").resolve()
    return _PACKAGED_SKILLS_CACHE
def get_packaged_config_path() -> Path | None:
    global _PACKAGED_CONFIG_CACHE
    if _PACKAGED_CONFIG_CACHE is not None:
        return _PACKAGED_CONFIG_CACHE
    if _resources is not None:
        for pkg in ("tools",):
            try:
                traversable = _resources.files(pkg).joinpath("config.yaml")  # type: ignore
                if traversable.is_file():  # type: ignore
                    pass
                else:
                    if Path(str(traversable)).is_file():
                        _PACKAGED_CONFIG_CACHE = Path(str(traversable))
                        return _PACKAGED_CONFIG_CACHE
            except Exception:
                continue
    candidate = _repo_root_from_this_file() / "config.yaml"
    if candidate.is_file():
        _PACKAGED_CONFIG_CACHE = candidate
        return candidate
    return None
def get_webui_dist_dir() -> Path | None:
    if _resources is not None:
        for pkg in ("webui", "tools.webui"):
            try:
                traversable = _resources.files(pkg)  # type: ignore
                candidate = Path(str(traversable))
                if candidate.is_dir():
                    return candidate
                dist = candidate / "dist"
                if dist.is_dir():
                    return dist
            except Exception:
                continue
        try:
            traversable = _resources.files("tools").joinpath("webui/dist")  # type: ignore
            candidate = Path(str(traversable))
            if candidate.is_dir():
                return candidate
        except Exception:
            pass
    candidate = _repo_root_from_this_file() / "webui" / "dist"
    if candidate.is_dir():
        return candidate
    return None
def _user_config_candidates() -> list[Path]:
    candidates: list[Path] = []
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if xdg:
        candidates.append(Path(xdg) / "breachpilot" / "config.yaml")
    candidates.append(Path.home() / ".config" / "breachpilot" / "config.yaml")
    candidates.append(Path.home() / ".breachpilot" / "config.yaml")
    candidates.append(Path.home() / ".config" / "config.yaml")
    seen: set[str] = set()
    unique: list[Path] = []
    for p in candidates:
        key = str(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique
def resolve_config_path(explicit: Path | str | None = None) -> Path | None:
    if explicit is not None:
        p = Path(explicit)
        if not p.is_absolute() and p == Path("config.yaml"):
            cwd_candidate = Path.cwd() / "config.yaml"
            if cwd_candidate.is_file():
                return cwd_candidate
        else:
            return p
    cwd_config = Path.cwd() / "config.yaml"
    if cwd_config.is_file():
        return cwd_config
    for candidate in _user_config_candidates():
        if candidate.is_file():
            return candidate
    return None
def load_effective_config(explicit: Path | str | None = None) -> dict[str, Any]:
    from tools.config.validator import ConfigValidator
    resolved = resolve_config_path(explicit)
    if resolved is None:
        return copy.deepcopy(CONFIG_SCHEMA)
    validator = ConfigValidator(resolved)
    config, result = validator.load_and_validate()
    if not result.is_valid:
        error_msg = "; ".join(result.errors)
        raise ValueError(f"Config validation failed for {resolved}: {error_msg}")
    import logging as _logging
    _log = _logging.getLogger(__name__)
    if result.has_warnings:
        for w in result.warnings:
            _log.warning("Config warning: %s", w)
        for uk in result.unknown_keys:
            _log.warning("Unknown config key: %s", uk)
    return validator.apply_defaults()
def load_config_or_defaults(path: Path | str | None = None) -> dict[str, Any]:
    return load_effective_config(path)
def resolve_skill_roots(config: dict[str, Any] | None, *, base_dir: Path | str | None = None, config_source_path: Path | str | None = None) -> list[Path]:
    skills = (config or {}).get("skills", {}) if isinstance(config, dict) else {}
    has_explicit_roots = isinstance(skills, dict) and "roots" in skills
    raw_roots = skills.get("roots") if isinstance(skills, dict) else None
    if not has_explicit_roots or raw_roots is None:
        pkg = get_packaged_skills_dir()
        return [pkg.resolve() if pkg.exists() else pkg]
    if isinstance(raw_roots, str):
        raw_roots = [raw_roots]
    if not isinstance(raw_roots, list):
        raw_roots = []
    roots = [str(r).strip() for r in raw_roots if str(r).strip()]
    if not roots:
        pkg = get_packaged_skills_dir()
        return [pkg.resolve() if pkg.exists() else pkg]
    if config_source_path is not None:
        base = Path(config_source_path).parent.resolve()
    elif base_dir is not None:
        base = Path(base_dir).resolve()
    else:
        base = Path.cwd().resolve()
    pkg_dir = get_packaged_skills_dir()
    resolved: list[Path] = []
    for entry in roots:
        p = Path(entry)
        if p.is_absolute():
            resolved.append(p)
            continue
        if entry == "skills":
            cwd_candidate = (base / p).resolve()
            if cwd_candidate.is_dir() and any(cwd_candidate.rglob("SKILL.md")):
                resolved.append(cwd_candidate)
                continue
            if pkg_dir.is_dir():
                resolved.append(pkg_dir.resolve())
                continue
            resolved.append(cwd_candidate)
            continue
        resolved.append((base / p).resolve())
    return resolved
def get_skill_roots_for_display(config: dict[str, Any] | None) -> list[str]:
    return [str(p) for p in resolve_skill_roots(config)]
def is_packaged_resource(path: Path) -> bool:
    try:
        pkg_skills = get_packaged_skills_dir().resolve()
        if pkg_skills in path.resolve().parents or path.resolve() == pkg_skills:
            return True
    except Exception:
        pass
    webui = get_webui_dist_dir()
    if webui is not None:
        try:
            if webui.resolve() in path.resolve().parents or path.resolve() == webui.resolve():
                return True
        except Exception:
            pass
    return False
def ensure_runtime_dir(path: Path | str) -> Path:
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p
__all__ = ["get_packaged_skills_dir","get_packaged_config_path","get_webui_dist_dir","resolve_config_path","load_effective_config","load_config_or_defaults","resolve_skill_roots","get_skill_roots_for_display","is_packaged_resource","ensure_runtime_dir"]
