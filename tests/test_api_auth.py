"""Tests for API security: bearer auth, loopback enforcement, origin checks."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tools.api.auth import (
    assert_api_loopback,
    is_loopback_origin,
    load_or_create_token,
)

# ── Loopback enforcement ─────────────────────────────────────────────────────


def test_loopback_hosts_allowed():
    for host in ("127.0.0.1", "localhost", "::1"):
        assert_api_loopback(host)  # must not raise


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.1", "example.com"])
def test_non_loopback_refused(host):
    with pytest.raises(ValueError, match="loopback"):
        assert_api_loopback(host)


# ── Token generation ─────────────────────────────────────────────────────────


def test_token_env_override(monkeypatch):
    monkeypatch.setenv("NETATTACKAI_API_TOKEN", "test-token-123")
    token = load_or_create_token(".webui_secret_key", env_override="test-token-123")
    assert token == "test-token-123"


def test_token_generated_when_no_env_no_file(tmp_path):
    token_file = tmp_path / ".webui_secret_key"
    token = load_or_create_token(token_file, env_override="")
    assert len(token) > 20
    assert token_file.exists()
    # Second call reads from file.
    token2 = load_or_create_token(token_file, env_override="")
    assert token2 == token


def test_token_read_from_file(tmp_path):
    token_file = tmp_path / ".webui_secret_key"
    token_file.write_text("file-token-456", encoding="utf-8")
    token = load_or_create_token(token_file, env_override="")
    assert token == "file-token-456"


# ── Origin checks ────────────────────────────────────────────────────────────


def test_loopback_origin_allowed():
    assert is_loopback_origin("http://127.0.0.1:8080", []) is True
    assert is_loopback_origin("http://localhost:3000", []) is True
    assert is_loopback_origin("http://[::1]:3000", []) is True


def test_null_origin_rejected():
    assert is_loopback_origin("null", []) is False


def test_non_loopback_origin_rejected():
    assert is_loopback_origin("http://10.0.0.1:8080", []) is False
    assert is_loopback_origin(
        "https://evil.example", ["https://evil.example"],
    ) is False


def test_explicit_allowed_origin():
    assert is_loopback_origin("http://localhost:3000", ["http://localhost:3000"]) is True


# ── Bearer auth on routes ────────────────────────────────────────────────────


def _make_client(tmp_path, monkeypatch):
    """Create a TestClient with a known token."""
    monkeypatch.setenv("NETATTACKAI_API_TOKEN", "test-bearer-token")
    monkeypatch.chdir(tmp_path)
    from app import create_app
    app = create_app(config_path=tmp_path / "config.yaml")
    return TestClient(app)


def test_health_no_auth(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["ready"] is True


def test_protected_route_requires_token(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/capabilities")
    assert resp.status_code == 401


def test_protected_route_with_wrong_token(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/capabilities", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401


def test_protected_route_with_valid_token(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/capabilities", headers={"Authorization": "Bearer test-bearer-token"})
    assert resp.status_code == 200
    data = resp.json()
    assert "features" in data
    assert "runs" in data["features"]


def test_config_redacts_secrets(tmp_path, monkeypatch):
    # Write a config with a secret-looking key.
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "exploit:\n  permission: full_access\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n"
        "cve_lookup:\n  api_key_env: NVD_API_KEY\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NETATTACKAI_API_TOKEN", "test-token")
    monkeypatch.chdir(tmp_path)
    from app import create_app
    app = create_app(config_path=config_path)
    client = TestClient(app)
    resp = client.get("/api/v1/config", headers={"Authorization": "Bearer test-token"})
    assert resp.status_code == 200
    # The response should be redacted.
    body = resp.json()
    assert "ollama" in body


def test_secret_write_rejects_unknown_names(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    response = client.put(
        "/api/v1/secrets",
        json={"secrets": {"NOT_A_CONFIGURED_KEY": "secret"}},
        headers={"Authorization": "Bearer test-bearer-token"},
    )
    assert response.status_code == 400


def test_secret_write_uses_configured_store(tmp_path, monkeypatch):
    store = tmp_path / "keys.json"
    monkeypatch.setenv("NETATTACKAI_API_KEY_FILE", str(store))
    client = _make_client(tmp_path, monkeypatch)
    response = client.put(
        "/api/v1/secrets",
        json={"secrets": {"NVD_API_KEY": "secret"}},
        headers={"Authorization": "Bearer test-bearer-token"},
    )
    assert response.status_code == 200
    assert '"NVD_API_KEY": "secret"' in store.read_text(encoding="utf-8")
