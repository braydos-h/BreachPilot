from __future__ import annotations

from pathlib import Path

from tools.skill_registry_cache import clear_cache, get_registry


def _write_skill(root: Path, name: str) -> None:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        "description: Cache test skill.\n"
        "tags:\n"
        "- nmap\n"
        "---\n"
        "# Skill\n\n## When to Use\nUse for authorized testing.\n",
        encoding="utf-8",
    )


def test_get_registry_caches_per_root_set(tmp_path: Path):
    clear_cache()
    root_a = tmp_path / "a"
    _write_skill(root_a, "skill-a")
    root_b = tmp_path / "b"
    _write_skill(root_b, "skill-b")

    reg_a1 = get_registry({"skills": {"roots": [str(root_a)]}}, base_dir=tmp_path)
    reg_a2 = get_registry({"skills": {"roots": [str(root_a)]}}, base_dir=tmp_path)
    reg_b = get_registry({"skills": {"roots": [str(root_b)]}}, base_dir=tmp_path)

    # Same root set returns the same cached object.
    assert reg_a1 is reg_a2
    # Different root set returns a different registry with its own skills.
    assert reg_a1 is not reg_b
    assert reg_a1.get("skill-a") is not None
    assert reg_b.get("skill-b") is not None
    assert reg_a1.get("skill-b") is None


def test_clear_cache_drops_cached_registries(tmp_path: Path):
    clear_cache()
    root = tmp_path / "root"
    _write_skill(root, "skill-x")

    first = get_registry({"skills": {"roots": [str(root)]}}, base_dir=tmp_path)
    clear_cache()
    second = get_registry({"skills": {"roots": [str(root)]}}, base_dir=tmp_path)

    assert first is not second
    assert second.get("skill-x") is not None


def test_get_registry_defaults_roots_when_unset(tmp_path: Path):
    clear_cache()
    # No skills.roots in config -> defaults to ["skills"]; must not
    # raise and must return a registry object.
    registry = get_registry({}, base_dir=tmp_path)
    assert registry is not None