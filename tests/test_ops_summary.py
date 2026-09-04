"""Ops summary route: read-only rollup for dormant backends (no execution)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", "test-token")
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  provider: opencode_go\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from tools import config_cli as _config_cli

    config = _config_cli.load_config(config_path)
    from app import create_app

    return TestClient(create_app(config_path=config_path, config=config))


def _headers():
    return {"Authorization": "Bearer test-token"}


def test_ops_summary_requires_auth(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    assert client.get("/api/v1/ops/summary").status_code == 401


def test_ops_summary_shape(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/ops/summary", headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"killchain", "snapshots", "eval", "browser", "provider"}
    assert body["provider"]["active"] == "opencode_go"
    assert body["killchain"]["enabled"] is False
    assert body["snapshots"]["enabled"] is False


def test_capabilities_advertises_ops(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/capabilities", headers=_headers())
    assert resp.status_code == 200
    assert "ops_summary" in resp.json()["features"]
