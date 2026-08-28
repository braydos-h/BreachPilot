"""Tests for tools/ollama_models.py — Ollama API model-registry auto-update.

Covers spec parsing, same-family version comparison, registry refresh
(persist + in-memory mirror), and the boot-time gate (models.auto_update,
provider check). All network I/O is mocked via ``fetch_available_models``.
"""

from __future__ import annotations

import urllib.error

import yaml

from tools.ollama_models import (
    auto_refresh_on_startup,
    compute_registry_updates,
    parse_model_spec,
    refresh_model_registry,
)

# ── parse_model_spec ─────────────────────────────────────────────────────────


def test_parse_versioned_specs():
    assert parse_model_spec("glm-5.2:cloud") == ("glm", (5, 2))
    assert parse_model_spec("glm-5.10:cloud") == ("glm", (5, 10))
    assert parse_model_spec("kimi-k2.6:cloud") == ("kimi-k", (2, 6))
    assert parse_model_spec("minimax-m3:cloud") == ("minimax-m", (3,))
    assert parse_model_spec("llama3.1:8b") == ("llama", (3, 1))


def test_parse_version_ordering():
    # (5, 2) < (5, 10) numerically, and "5.2" > bare "5".
    assert parse_model_spec("glm-5.2")[1] < parse_model_spec("glm-5.10")[1]
    assert parse_model_spec("glm-5")[1] < parse_model_spec("glm-5.2")[1]


def test_parse_unversioned_specs():
    assert parse_model_spec("nomic-embed-text") == ("nomic-embed-text", None)
    assert parse_model_spec("gpt-oss:20b-cloud") == ("gpt-oss", None)
    assert parse_model_spec("deepseek-v4-pro:cloud") == ("deepseek-v4-pro", None)


# ── compute_registry_updates ─────────────────────────────────────────────────


def test_update_to_newer_version():
    updates = compute_registry_updates({"glm": "glm-5.2:cloud"}, ["glm-5.2:cloud", "glm-5.3:cloud"])
    assert updates == {"glm": {"old": "glm-5.2:cloud", "new": "glm-5.3:cloud"}}


def test_update_when_configured_version_gone():
    # Old version disappeared from the catalog; newest family member wins.
    updates = compute_registry_updates({"glm": "glm-5.2:cloud"}, ["glm-5.3:cloud"])
    assert updates == {"glm": {"old": "glm-5.2:cloud", "new": "glm-5.3:cloud"}}


def test_update_prefers_same_tag():
    updates = compute_registry_updates({"llama": "llama3.1:8b"}, ["llama3.2", "llama3.2:8b", "llama3.2:70b"])
    assert updates == {"llama": {"old": "llama3.1:8b", "new": "llama3.2:8b"}}


def test_already_newest_is_noop():
    updates = compute_registry_updates({"glm": "glm-5.3:cloud"}, ["glm-5.2:cloud", "glm-5.3:cloud"])
    assert updates == {}


def test_unversioned_specs_never_touched():
    updates = compute_registry_updates({"embed": "nomic-embed-text"}, ["nomic-embed-text:v2"])
    assert updates == {}


def test_no_family_candidates_leaves_spec():
    updates = compute_registry_updates({"glm": "glm-5.2:cloud"}, ["kimi-k2.6:cloud", "minimax-m3:cloud"])
    assert updates == {}


def test_families_are_independent():
    registry = {"glm": "glm-5.2:cloud", "kimi": "kimi-k2.6:cloud"}
    available = ["glm-5.3:cloud", "kimi-k2.6:cloud"]
    updates = compute_registry_updates(registry, available)
    assert updates == {"glm": {"old": "glm-5.2:cloud", "new": "glm-5.3:cloud"}}


# ── refresh_model_registry ───────────────────────────────────────────────────


def _write_config(path, registry=None, extra_models=""):
    lines = [
        "ollama:\n",
        "  host: http://localhost:11434\n",
        "models:\n",
        "  provider: ollama\n",
        "  default_alias: glm\n",
    ]
    if extra_models:
        lines.append(extra_models)
    lines.append("  registry:\n")
    for alias, spec in (registry or {"glm": "glm-5.2:cloud"}).items():
        lines.append(f"    {alias}: {spec}\n")
    path.write_text("".join(lines), encoding="utf-8")
    return path


def test_refresh_persists_and_reports(tmp_path, monkeypatch):
    cfg_path = _write_config(tmp_path / "config.yaml")
    monkeypatch.setattr(
        "tools.ollama_models.fetch_available_models",
        lambda host, api_key_env="OLLAMA_API_KEY", timeout=5.0: ["glm-5.2:cloud", "glm-5.3:cloud"],
    )
    config = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    result = refresh_model_registry(config, config_path=cfg_path, persist=True)
    assert result["ok"] is True
    assert result["persisted"] is True
    assert result["updates"] == {"glm": {"old": "glm-5.2:cloud", "new": "glm-5.3:cloud"}}
    # The caller's dict is NOT mutated by refresh_model_registry itself.
    assert config["models"]["registry"]["glm"] == "glm-5.2:cloud"
    on_disk = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert on_disk["models"]["registry"]["glm"] == "glm-5.3:cloud"


def test_refresh_no_updates_does_not_write(tmp_path, monkeypatch):
    cfg_path = _write_config(tmp_path / "config.yaml")
    before = cfg_path.read_text(encoding="utf-8")
    monkeypatch.setattr(
        "tools.ollama_models.fetch_available_models",
        lambda host, api_key_env="OLLAMA_API_KEY", timeout=5.0: ["glm-5.2:cloud"],
    )
    result = refresh_model_registry({}, host="http://localhost:11434", config_path=cfg_path, persist=True)
    assert result["ok"] is True
    assert result["persisted"] is False
    assert cfg_path.read_text(encoding="utf-8") == before


def test_refresh_unreachable_is_soft_error(monkeypatch):
    def _boom(host, api_key_env="OLLAMA_API_KEY", timeout=5.0):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("tools.ollama_models.fetch_available_models", _boom)
    result = refresh_model_registry({"ollama": {"host": "http://localhost:9"}, "models": {"registry": {}}})
    assert result["ok"] is False
    assert "URLError" in result["error"]
    assert result["updates"] == {}


def test_refresh_host_defaults_to_config(monkeypatch):
    seen: dict[str, str] = {}

    def _fake(host, api_key_env="OLLAMA_API_KEY", timeout=5.0):
        seen["host"] = host
        return ["glm-5.2:cloud"]

    monkeypatch.setattr("tools.ollama_models.fetch_available_models", _fake)
    refresh_model_registry({"ollama": {"host": "http://example.invalid:1"}, "models": {}}, persist=False)
    assert seen["host"] == "http://example.invalid:1"


# ── auto_refresh_on_startup ──────────────────────────────────────────────────


def test_auto_refresh_mutates_config_in_place(tmp_path, monkeypatch):
    cfg_path = _write_config(tmp_path / "config.yaml")
    monkeypatch.setattr(
        "tools.ollama_models.fetch_available_models",
        lambda host, api_key_env="OLLAMA_API_KEY", timeout=5.0: ["glm-5.3:cloud"],
    )
    config = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    result = auto_refresh_on_startup(config, config_path=cfg_path)
    assert result is not None and result["ok"] is True
    # In-memory mirror so create_app(config=config) sees the fresh registry.
    assert config["models"]["registry"]["glm"] == "glm-5.3:cloud"


def test_auto_refresh_skipped_when_disabled(tmp_path, monkeypatch):
    cfg_path = _write_config(tmp_path / "config.yaml", extra_models="  auto_update: false\n")
    config = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))

    def _fail(*args, **kwargs):
        raise AssertionError("fetch must not run when auto_update is false")

    monkeypatch.setattr("tools.ollama_models.fetch_available_models", _fail)
    assert auto_refresh_on_startup(config, config_path=cfg_path) is None


def test_auto_refresh_skipped_for_chatgpt(monkeypatch):
    config = {"models": {"provider": "chatgpt", "registry": {"glm": "glm-5.2:cloud"}, "auto_update": True}}

    def _fail(*args, **kwargs):
        raise AssertionError("fetch must not run for non-ollama providers")

    monkeypatch.setattr("tools.ollama_models.fetch_available_models", _fail)
    assert auto_refresh_on_startup(config, config_path="config.yaml") is None


def test_auto_refresh_absent_key_defaults_on(tmp_path, monkeypatch):
    # config_cli.load_config merges NO defaults: an absent models.auto_update
    # must still behave as enabled (matches the schema default).
    cfg_path = _write_config(tmp_path / "config.yaml")
    monkeypatch.setattr(
        "tools.ollama_models.fetch_available_models",
        lambda host, api_key_env="OLLAMA_API_KEY", timeout=5.0: ["glm-5.3:cloud"],
    )
    config = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert "auto_update" not in config["models"]
    result = auto_refresh_on_startup(config, config_path=cfg_path)
    assert result is not None and config["models"]["registry"]["glm"] == "glm-5.3:cloud"


# ── schema/validator sync ────────────────────────────────────────────────────


def test_validator_accepts_auto_update_key(tmp_path):
    from tools.config_manager import ConfigValidator

    cfg_path = _write_config(tmp_path / "config.yaml", extra_models="  auto_update: true\n")
    validator = ConfigValidator(cfg_path)
    validator.load()
    result = validator.validate()
    assert result.is_valid, result.errors
    assert not any("auto_update" in err for err in result.errors)
