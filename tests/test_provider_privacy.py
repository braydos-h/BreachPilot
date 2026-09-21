"""Tests for the provider privacy boundary (todo p2-08-provider-privacy).

``BaseProvider.metadata()`` carries ``data_residency`` (local|cloud) +
``egress_target`` (display string, no secrets), derived from the effective
host/base_url at call time:

* Ollama loopback/localhost -> local, anything else -> cloud;
* opencode_go -> cloud (hosted Responses API base URL);
* chatgpt proxy -> cloud (via OpenAI account — never the loopback proxy URL).
"""

from __future__ import annotations

from typing import Any

from tools.providers.base import is_loopback_url
from tools.providers.registry import active_provider_metadata, get_provider


def _metadata(pid: str, config: dict[str, Any] | None) -> dict[str, Any]:
    return get_provider(pid).metadata(config)


# ── loopback helper ──────────────────────────────────────────────────────


def test_loopback_matches_localhost_forms():
    assert is_loopback_url("http://localhost:11434") is True
    assert is_loopback_url("http://127.0.0.1:11434") is True
    assert is_loopback_url("http://127.0.0.2:11434") is True
    assert is_loopback_url("http://[::1]:11434") is True
    assert is_loopback_url("http://app.localhost:11434") is True


def test_loopback_rejects_non_loopback():
    assert is_loopback_url("https://api.ollama.com") is False
    assert is_loopback_url("http://192.168.1.10:11434") is False
    assert is_loopback_url("http://10.0.0.5:11434") is False
    assert is_loopback_url("not-a-url") is False
    assert is_loopback_url("") is False


# ── residency mapping ────────────────────────────────────────────────────


def test_ollama_localhost_is_local():
    meta = _metadata("ollama", {"ollama": {"host": "http://localhost:11434"}})
    assert meta["data_residency"] == "local"
    assert meta["egress_target"] == ""


def test_ollama_loopback_ip_is_local():
    meta = _metadata("ollama", {"ollama": {"host": "http://127.0.0.1:11434"}})
    assert meta["data_residency"] == "local"


def test_ollama_cloud_host_is_cloud_with_target():
    meta = _metadata("ollama", {"ollama": {"host": "https://api.ollama.com"}})
    assert meta["data_residency"] == "cloud"
    assert meta["egress_target"] == "https://api.ollama.com"


def test_ollama_default_host_is_cloud():
    # Stock config (no ollama block) points at Ollama Cloud — must not claim local.
    meta = _metadata("ollama", {})
    assert meta["data_residency"] == "cloud"
    assert "api.ollama.com" in meta["egress_target"]


def test_ollama_lan_host_is_cloud():
    meta = _metadata("ollama", {"ollama": {"host": "http://192.168.1.10:11434"}})
    assert meta["data_residency"] == "cloud"


def test_opencode_go_is_cloud():
    meta = _metadata("opencode_go", {"opencode_go": {"enabled": True}})
    assert meta["data_residency"] == "cloud"
    assert meta["egress_target"].startswith("https://opencode.ai")


def test_chatgpt_proxy_is_cloud_via_openai_account():
    meta = _metadata("chatgpt", {"chatgpt": {"enabled": True}})
    assert meta["data_residency"] == "cloud"
    # Must name the true destination, never the loopback proxy URL.
    assert "127.0.0.1" not in meta["egress_target"]
    assert "10531" not in meta["egress_target"]
    assert "OpenAI" in meta["egress_target"] or "ChatGPT" in meta["egress_target"]


# ── no secrets ───────────────────────────────────────────────────────────


def test_metadata_carries_no_secrets(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "ollama-secret-value-xyz")
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "opencode-secret-value-xyz")
    for pid in ("ollama", "opencode_go", "chatgpt"):
        meta = _metadata(pid, {"ollama": {"host": "https://api.ollama.com"}})
        blob = " ".join(str(v) for v in meta.values())
        assert "ollama-secret-value-xyz" not in blob
        assert "opencode-secret-value-xyz" not in blob
        for key in meta:
            assert "api_key" not in str(key).lower(), f"secret-ish key {key!r} in metadata"
            assert "token" not in str(key).lower(), f"secret-ish key {key!r} in metadata"


# ── threading through active_provider_metadata ──────────────────────────


def test_active_provider_metadata_threads_privacy_fields():
    rows = active_provider_metadata({"ollama": {"host": "http://localhost:11434"}})["providers"]
    by_id = {row["id"]: row for row in rows}
    assert by_id["ollama"]["data_residency"] == "local"
    assert by_id["opencode_go"]["data_residency"] == "cloud"
    assert by_id["chatgpt"]["data_residency"] == "cloud"
    for row in rows:
        assert row["data_residency"] in ("local", "cloud")
        assert isinstance(row["egress_target"], str)
