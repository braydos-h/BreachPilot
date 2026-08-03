"""Regression tests for GITHUB_TOKEN bootstrap (Gap 6).

``cve_to_poc`` reads ``os.getenv("GITHUB_TOKEN")`` for the GitHub Search API
rate limit (60/hr unauth -> 5000/hr authed), but the token was not plumbed
through the api-key bootstrap. The fix mirrors NVD_API_KEY handling: the token
is declared in ``.env.example`` / ``config.yaml`` / ``config_manager.py`` and
added to ``api_key_store.configured_api_key_env_names`` so
``bootstrap_api_keys`` loads it from ``secr.json`` into env. It stays OPTIONAL
-- cve_to_poc falls through to searchsploit/NVD on rate-limit.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest


# ── api_key_store wiring ────────────────────────────────────────────────────


def test_configured_api_key_env_names_includes_github_with_block():
    from tools.api_key_store import configured_api_key_env_names

    config = {"cve_lookup": {"github": {"token_env": "GITHUB_TOKEN"}}}
    names = configured_api_key_env_names(config)
    assert "GITHUB_TOKEN" in names
    # The default keys are still present (mirrors NVD_API_KEY handling).
    assert "NVD_API_KEY" in names


def test_configured_api_key_env_names_includes_github_default():
    """Even without a github block, GITHUB_TOKEN is in the default set."""
    from tools.api_key_store import configured_api_key_env_names

    names = configured_api_key_env_names({})
    assert "GITHUB_TOKEN" in names
    assert "NVD_API_KEY" in names


def test_configured_api_key_env_names_custom_github_env():
    """A custom token_env is honored."""
    from tools.api_key_store import configured_api_key_env_names

    config = {"cve_lookup": {"github": {"token_env": "GH_TOKEN_CUSTOM"}}}
    names = configured_api_key_env_names(config)
    assert "GH_TOKEN_CUSTOM" in names
    assert "GITHUB_TOKEN" not in names  # custom overrides the default


# ── top-level ollama.api_key_env (cloud fallback wiring) ───────────────────


def test_configured_api_key_env_names_includes_top_level_ollama():
    """The top-level ollama.api_key_env is picked up even when research is absent.

    This is the key that gates the model_router cloud fallback on the MAIN
    model path. Without this discovery, the fallback never fires unless the
    operator manually exports OLLAMA_API_KEY in their shell.
    """
    from tools.api_key_store import configured_api_key_env_names

    config = {"ollama": {"api_key_env": "OLLAMA_API_KEY"}}
    names = configured_api_key_env_names(config)
    assert "OLLAMA_API_KEY" in names


def test_configured_api_key_env_names_top_level_ollama_without_research():
    """A config with only a top-level ollama block (no research) still loads the key."""
    from tools.api_key_store import configured_api_key_env_names

    config = {"ollama": {"host": "http://localhost:11434", "api_key_env": "OLLAMA_API_KEY"}}
    names = configured_api_key_env_names(config)
    assert "OLLAMA_API_KEY" in names
    # Defaults still present (NVD, GITHUB) — those are independent subsystems.
    assert "NVD_API_KEY" in names
    assert "GITHUB_TOKEN" in names


def test_configured_api_key_env_names_top_level_custom_env():
    """A custom top-level ollama.api_key_env is honored (dedup vs research.ollama)."""
    from tools.api_key_store import configured_api_key_env_names

    config = {
        "ollama": {"api_key_env": "OLLAMA_CLOUD_KEY"},
        "research": {"ollama": {"api_key_env": "OLLAMA_CLOUD_KEY"}},
    }
    names = configured_api_key_env_names(config)
    # Appears exactly once (dedup), not twice.
    assert names.count("OLLAMA_CLOUD_KEY") == 1


def test_load_api_keys_into_env_loads_top_level_ollama(tmp_path: Path, monkeypatch):
    """bootstrap path: a saved OLLAMA_API_KEY is loaded into env from the top-
    level ollama block, so model_router's cloud fallback can fire."""
    from tools.api_key_store import configured_api_key_env_names, load_api_keys_into_env

    store = tmp_path / "secr.json"
    store.write_text(json.dumps({
        "version": 1,
        "api_keys": {"OLLAMA_API_KEY": "sk-ollama-cloud"},
    }), encoding="utf-8")

    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)

    config = {"ollama": {"api_key_env": "OLLAMA_API_KEY"}}
    loaded = load_api_keys_into_env(store, allowed_names=configured_api_key_env_names(config))
    assert "OLLAMA_API_KEY" in loaded
    assert os.environ["OLLAMA_API_KEY"] == "sk-ollama-cloud"


def test_load_api_keys_into_env_top_level_only(tmp_path: Path, monkeypatch):
    """A config with only a top-level ollama block (no research) still loads the key."""
    from tools.api_key_store import configured_api_key_env_names, load_api_keys_into_env

    store = tmp_path / "secr.json"
    store.write_text(json.dumps({
        "version": 1,
        "api_keys": {"OLLAMA_API_KEY": "sk-cloud-only"},
    }), encoding="utf-8")

    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)

    config = {"ollama": {"host": "http://localhost:11434", "api_key_env": "OLLAMA_API_KEY"}}
    loaded = load_api_keys_into_env(store, allowed_names=configured_api_key_env_names(config))
    assert "OLLAMA_API_KEY" in loaded
    assert os.environ["OLLAMA_API_KEY"] == "sk-cloud-only"


# ── config_manager schema ───────────────────────────────────────────────────


def test_config_defaults_include_github_block():
    from tools.config_manager import CONFIG_SCHEMA

    cve = CONFIG_SCHEMA.get("cve_lookup", {})
    assert "github" in cve
    assert cve["github"]["token_env"] == "GITHUB_TOKEN"


def test_config_defaults_include_ollama_api_key_env():
    """The top-level ollama schema default includes api_key_env so a missing
    config.yaml still yields the cloud-fallback wiring."""
    from tools.config_manager import CONFIG_SCHEMA

    ollama = CONFIG_SCHEMA.get("ollama", {})
    assert ollama.get("api_key_env") == "OLLAMA_API_KEY"


def test_load_api_keys_into_env_loads_github(tmp_path: Path, monkeypatch):
    from tools.api_key_store import configured_api_key_env_names, load_api_keys_into_env

    store = tmp_path / "secr.json"
    store.write_text(json.dumps({
        "version": 1,
        "api_keys": {"GITHUB_TOKEN": "ghp_secret123", "NVD_API_KEY": "nvd-key"},
    }), encoding="utf-8")

    # Start clean so the load actually sets the value.
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    config = {"cve_lookup": {"github": {"token_env": "GITHUB_TOKEN"}}}
    loaded = load_api_keys_into_env(store, allowed_names=configured_api_key_env_names(config))
    assert "GITHUB_TOKEN" in loaded
    assert os.environ["GITHUB_TOKEN"] == "ghp_secret123"
    assert os.environ["NVD_API_KEY"] == "nvd-key"


# ── cve_to_poc uses the token ───────────────────────────────────────────────


def _make_search(monkeypatch):
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings

    settings = ExploitSearchSettings()
    # Ensure enabled (cve_to_poc early-returns BLOCKED when disabled).
    try:
        settings.enabled = True
    except Exception:
        pass
    return ExploitSearch(settings)


def _patch_net(monkeypatch, captured: dict[str, Any]):
    """Patch urlopen to capture the GitHub API request; return empty items so
    cve_to_poc falls through to searchsploit. Patch searchsploit to empty too."""
    import tools.exploit_search as es

    class _Resp:
        def __init__(self, code=200): self._c = code
        def getcode(self): return self._c
        def read(self): return b'{"items": []}'
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def _fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.header_items())
        captured["url"] = req.full_url
        return _Resp(200)
    monkeypatch.setattr(es.urllib.request, "urlopen", _fake_urlopen)

    def _fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0,
                                            stdout="{}", stderr="")
    monkeypatch.setattr(es.subprocess, "run", _fake_run)


def test_cve_to_poc_sends_bearer_when_token_present(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_token_xyz")
    search = _make_search(monkeypatch)
    captured: dict[str, Any] = {}
    _patch_net(monkeypatch, captured)
    result = search.cve_to_poc("CVE-2024-6387")
    # GitHub API was queried and the Authorization header was sent.
    assert captured.get("url", "").startswith("https://api.github.com/search/repositories")
    auth = captured["headers"].get("Authorization", "")
    assert auth == "Bearer ghp_token_xyz"
    # No verified PoC from the empty payload + empty searchsploit -> NO_VERIFIED.
    assert "NO_VERIFIED_POC_FOUND" in result or "CVE_TO_POC_RESULTS" in result


def test_cve_to_poc_works_without_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    search = _make_search(monkeypatch)
    captured: dict[str, Any] = {}
    _patch_net(monkeypatch, captured)
    result = search.cve_to_poc("CVE-2024-6387")
    # Still queried GitHub (unauth), no Authorization header.
    assert captured.get("url", "").startswith("https://api.github.com/search/repositories")
    assert "Authorization" not in captured["headers"]
    # Did not crash; fell through to searchsploit/NVD and reported no PoC.
    assert "NO_VERIFIED_POC_FOUND" in result or "CVE_TO_POC_RESULTS" in result