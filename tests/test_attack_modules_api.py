"""Tests for GET /attack/modules (read-only module catalog)."""

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


def test_attack_modules_requires_auth(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/attack/modules")
    assert resp.status_code == 401


def test_attack_modules_lists_catalog(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/attack/modules", headers=_auth())
    assert resp.status_code == 200
    body = resp.json()
    modules = body["modules"]
    assert isinstance(modules, list) and len(modules) > 0
    names = {m["name"] for m in modules}
    assert "Log4jRCE" in names and "SSHBruteForce" in names
    for m in modules:
        assert isinstance(m["name"], str) and m["name"]
        assert isinstance(m["description"], str)
        assert isinstance(m["family"], str) and m["family"]
        assert isinstance(m["target_services"], list)
        assert isinstance(m["target_ports"], list)
        assert isinstance(m["required_cves"], list)
        assert isinstance(m["destructive_ics"], bool)


def test_attack_modules_includes_ics_gate_flag(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/attack/modules", headers=_auth())
    modules = resp.json()["modules"]
    ics_write = [m for m in modules if m["destructive_ics"]]
    assert len(ics_write) >= 4, "expected the ICS destructive-write modules flagged"
    assert all(m["family"] == "ics_iot" for m in ics_write)
