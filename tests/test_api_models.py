"""Tests for model registry management endpoints: add/remove/provider switch."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="test-token"):
    monkeypatch.setenv("NETATTACKAI_API_TOKEN", token)
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
