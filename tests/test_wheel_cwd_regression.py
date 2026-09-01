"""Regression tests for wheel-installed BreachPilot cwd independence (issue #2)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml


def _clear_skill_cache():
    from tools.skill_registry_cache import clear_cache

    clear_cache()


class TestPackagedResources:
    def test_skills_package_is_importable(self):
        import importlib.resources as resources

        try:
            traversable = resources.files("skills")
            assert Path(str(traversable)).is_dir()
        except (ImportError, ModuleNotFoundError, TypeError) as exc:
            raise AssertionError(f"skills package not importable via importlib.resources: {exc}")

    def test_packaged_skills_dir_exists_and_has_catalog(self):
        from tools.paths import get_packaged_skills_dir

        pkg = get_packaged_skills_dir()
        assert pkg.is_dir(), f"packaged skills dir missing: {pkg}"
        skill_files = list(pkg.rglob("SKILL.md"))
        assert len(skill_files) > 100, f"expected >100 SKILL.md, got {len(skill_files)} under {pkg}"

    def test_webui_dist_helper_does_not_crash(self):
        from tools.paths import get_webui_dist_dir

        result = get_webui_dist_dir()
        assert result is None or isinstance(result, Path)


class TestConfigHierarchy:
    def test_effective_config_from_clean_cwd_has_defaults(self, tmp_path, monkeypatch):
        from tools.paths import load_effective_config

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no_xdg"))
        monkeypatch.setenv("HOME", str(tmp_path))

        cfg = load_effective_config()
        assert "sandbox" in cfg
        assert cfg["sandbox"]["enabled"] is True
        assert cfg["skills"]["roots"] == ["skills"]
        assert cfg["exploit"]["permission"] == "full_access"
        assert cfg["ollama"]["host"] == "https://api.ollama.com"

    def test_effective_config_explicit_custom_wins(self, tmp_path):
        from tools.paths import load_effective_config

        custom = tmp_path / "custom.yaml"
        yaml.safe_dump(
            {"sandbox": {"enabled": False}, "skills": {"roots": ["my_skills"]}}, custom.open("w", encoding="utf-8")
        )
        cfg = load_effective_config(custom)
        assert cfg["sandbox"]["enabled"] is False
        assert cfg["skills"]["roots"] == ["my_skills"]

    def test_effective_config_local_cwd_file_wins_over_defaults(self, tmp_path, monkeypatch):
        from tools.paths import load_effective_config

        monkeypatch.chdir(tmp_path)
        local = tmp_path / "config.yaml"
        yaml.safe_dump({"sandbox": {"enabled": False}}, local.open("w", encoding="utf-8"))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no_xdg"))
        monkeypatch.setenv("HOME", str(tmp_path))

        cfg = load_effective_config()
        assert cfg["sandbox"]["enabled"] is False

    def test_kernel_load_config_default_sentinel_returns_defaults_when_missing(self, tmp_path, monkeypatch):
        from tools.kernel.config import load_config

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no_xdg"))
        monkeypatch.setenv("HOME", str(tmp_path))

        cfg = load_config(Path("config.yaml"))
        assert cfg.get("sandbox", {}).get("enabled") is True
        assert cfg.get("skills", {}).get("roots") == ["skills"]

    def test_kernel_load_config_explicit_custom_missing_still_empty(self, tmp_path):
        from tools.kernel.config import load_config

        missing = tmp_path / "does_not_exist.yaml"
        cfg = load_config(missing)
        assert cfg == {}

    def test_sandbox_defaults_survive_missing_cwd_config(self, tmp_path, monkeypatch):
        from tools.paths import load_effective_config
        from tools.sandbox.models import SandboxConfig

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no_xdg"))
        monkeypatch.setenv("HOME", str(tmp_path))

        cfg = load_effective_config()
        scfg = SandboxConfig.from_config(cfg)
        assert scfg.enabled is True
        assert SandboxConfig.from_config({}).enabled is False
        assert SandboxConfig.from_config(None).enabled is False


class TestSkillDiscoveryFromCleanCwd:
    def test_default_registry_from_clean_cwd_has_skills(self, tmp_path, monkeypatch):
        from tools.skill_registry_cache import clear_cache, get_registry

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no_xdg"))
        monkeypatch.setenv("HOME", str(tmp_path))
        clear_cache()
        reg = get_registry()
        assert len(reg.skills) > 100
        assert not any("root does not exist" in e for e in reg.errors)

    def test_explicit_custom_skill_root_absolute(self, tmp_path):
        from tools.skill_registry_cache import clear_cache, get_registry

        skill_root = tmp_path / "my_skills" / "demo_skill"
        skill_root.mkdir(parents=True)
        (skill_root / "SKILL.md").write_text(
            "---\nname: demo-skill\ntags: [demo]\ndescription: demo\n---\n# Demo\nbody\n", encoding="utf-8"
        )
        clear_cache()
        cfg = {"skills": {"roots": [str(tmp_path / "my_skills")]}}
        reg = get_registry(cfg)
        assert "demo-skill" in reg.skills
        clear_cache()

    def test_explicit_custom_skill_root_relative_from_cwd(self, tmp_path, monkeypatch):
        from tools.skill_registry_cache import clear_cache, get_registry

        monkeypatch.chdir(tmp_path)
        rel_root = tmp_path / "rel_skills" / "rel_demo"
        rel_root.mkdir(parents=True)
        (rel_root / "SKILL.md").write_text(
            "---\nname: rel-demo\ntags: [demo]\ndescription: demo\n---\n# Rel Demo\n", encoding="utf-8"
        )
        clear_cache()
        cfg = {"skills": {"roots": ["rel_skills"]}}
        reg = get_registry(cfg)
        assert "rel-demo" in reg.skills
        clear_cache()

    def test_explicit_skills_literal_fallback_to_packaged_when_cwd_missing(self, tmp_path, monkeypatch):
        from tools.skill_registry_cache import clear_cache, get_registry

        monkeypatch.chdir(tmp_path)
        assert not (tmp_path / "skills").exists()
        clear_cache()
        cfg = {"skills": {"roots": ["skills"]}}
        reg = get_registry(cfg)
        assert len(reg.skills) > 100

    def test_skill_pipeline_from_clean_cwd(self, tmp_path, monkeypatch):
        from tools.skill_pipeline import build_skill_selection_for_context
        from tools.skill_registry_cache import clear_cache

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no_xdg"))
        monkeypatch.setenv("HOME", str(tmp_path))
        clear_cache()
        sel = build_skill_selection_for_context(config={}, goal_name="nmap", mode="recon")
        assert sel is not None


class TestDoctorFromCleanCwd:
    def test_doctor_sandbox_enabled_from_clean_cwd(self, tmp_path, monkeypatch):
        from tools.doctor import _collect_doctor_checks

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "no_xdg"))
        monkeypatch.setenv("HOME", str(tmp_path))

        checks, config, _info = _collect_doctor_checks(Path("config.yaml"))
        sandbox_checks = [c for c in checks if c.get("name") == "sandbox"]
        assert sandbox_checks
        sc = sandbox_checks[0]
        assert sc.get("enabled") is True or sc.get("ok") is not False

    def test_doctor_json_via_subprocess_from_clean_cwd(self, tmp_path):
        env = dict(**{k: v for k, v in __import__("os").environ.items()}, PYTHONPATH=str(Path.cwd()))
        main_py = str(Path.cwd() / "main.py")
        result = subprocess.run(
            [sys.executable, main_py, "--doctor", "--json"],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        assert result.stdout.strip()
        import json

        data = json.loads(result.stdout)
        assert "checks" in data and "is_valid" in data


class TestWheelArtifact:
    def test_wheel_contains_skills(self):
        import tempfile

        try:
            import build  # type: ignore
        except ImportError:
            import pytest

            pytest.skip("build not installed")

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            result = subprocess.run(
                [sys.executable, "-m", "build", "--wheel", "--outdir", str(td_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            assert result.returncode == 0, f"build failed: {result.stderr[:1000]}"
            wheels = list(td_path.glob("*.whl"))
            assert wheels
            wheel = wheels[0]
            import zipfile

            with zipfile.ZipFile(wheel) as zf:
                names = zf.namelist()
                assert any(n.startswith("skills/") for n in names), f"wheel missing skills/: {names[:20]}"
                assert any(n.endswith("SKILL.md") for n in names), "wheel missing SKILL.md"
                assert any("tools/paths.py" in n for n in names), "wheel missing tools/paths.py"
