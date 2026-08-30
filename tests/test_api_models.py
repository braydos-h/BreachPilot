"""Tests for model registry management endpoints: add/remove/provider switch."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="test-token"):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from app import create_app

    return TestClient(create_app(config_path=config_path))


def _auth(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


def test_add_model_persists(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/models", json={"alias": "llama", "model": "llama3.1:8b"}, headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["registry"]["llama"] == "llama3.1:8b"
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert listed["registry"]["llama"] == "llama3.1:8b"


def test_remove_model(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    client.post("/api/v1/models", json={"alias": "llama", "model": "llama3.1:8b"}, headers=_auth())
    resp = client.delete("/api/v1/models/llama", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert "llama" not in listed["registry"]


def test_remove_default_alias_rejected(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.delete("/api/v1/models/glm", headers=_auth())
    assert resp.status_code == 400


def test_remove_missing_alias_404(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.delete("/api/v1/models/nope", headers=_auth())
    assert resp.status_code == 404


def test_switch_provider(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/models/provider", json={"provider": "chatgpt"}, headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["provider"] == "chatgpt"
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert listed["provider"] == "chatgpt"


def test_switch_provider_invalid(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/models/provider", json={"provider": "bogus"}, headers=_auth())
    assert resp.status_code == 400


# ── POST /models/refresh (Ollama API registry sync) ─────────────────────────


def _mock_fetch(monkeypatch, available):
    from tools import ollama_models

    monkeypatch.setattr(
        ollama_models,
        "fetch_available_models",
        lambda host, api_key_env="OLLAMA_API_KEY", timeout=5.0: list(available),
    )
    return ollama_models


def test_refresh_models_updates_registry_and_persists(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    _mock_fetch(monkeypatch, ["glm-5.2:cloud", "glm-5.3:cloud"])
    resp = client.post("/api/v1/models/refresh", headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["updates"] == {"glm": {"old": "glm-5.2:cloud", "new": "glm-5.3:cloud"}}
    assert body["persisted"] is True
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert listed["registry"]["glm"] == "glm-5.3:cloud"
    assert "glm-5.3:cloud" in (tmp_path / "config.yaml").read_text(encoding="utf-8")


def test_refresh_models_no_updates_is_noop(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    _mock_fetch(monkeypatch, ["glm-5.2:cloud"])
    resp = client.post("/api/v1/models/refresh", headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    assert body["updates"] == {}
    assert body["persisted"] is False
    listed = client.get("/api/v1/models", headers=_auth()).json()
    assert listed["registry"]["glm"] == "glm-5.2:cloud"


def test_refresh_models_unreachable_503(tmp_path, monkeypatch):
    import urllib.error

    client = _make_client(tmp_path, monkeypatch)
    ollama_models = _mock_fetch(monkeypatch, [])

    def _boom(host, api_key_env="OLLAMA_API_KEY", timeout=5.0):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(ollama_models, "fetch_available_models", _boom)
    resp = client.post("/api/v1/models/refresh", headers=_auth())
    assert resp.status_code == 503
    assert resp.json()["ok"] is False


def test_refresh_models_rejected_for_chatgpt(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    client.post("/api/v1/models/provider", json={"provider": "chatgpt"}, headers=_auth())
    resp = client.post("/api/v1/models/refresh", headers=_auth())
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_provider"
