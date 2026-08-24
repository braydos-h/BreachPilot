"""Tests for the /system/memory endpoint (attack memory + experience store)."""

from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="test-token"):
    monkeypatch.setenv("NETATTACKAI_API_TOKEN", token)
    monkeypatch.setenv("RESEARCH_WORKSPACE", str(tmp_path / "research_workspace"))
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "reports_dir: reports\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from db import reset_default

    reset_default()
    from app import create_app

    return TestClient(create_app(config_path=config_path))


def _auth(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


def _seed_lesson():
    from db import get_default_db

    db = get_default_db()
    with db.connection(write=True) as conn:
        conn.execute(
            "INSERT INTO lessons(id, pattern_hash, target_signature, action_type, outcome, "
            "confidence, embedding_json, metadata_json, text, created_at) "
            "VALUES('L1', 'sig:act', 'http:1.0:linux', 'mod:strat', 'success', 0.5, '[]', '{}', '', "
            "'2026-01-01T00:00:00+00:00')"
        )


def _seed_attack_memory(tmp_path):
    db_path = tmp_path / "reports" / "run-1" / "exploit_workspace" / "10.0.0.5" / "attempt-1" / "attack_memory.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE attack_memory_items (id TEXT PRIMARY KEY, session_id TEXT, target_ip TEXT, "
        "category TEXT, item_key TEXT, item_value TEXT, source_tool TEXT, success INTEGER, "
        "metadata_json TEXT, first_seen_at TEXT, last_seen_at TEXT, seen_count INTEGER)"
    )
    conn.execute(
        "INSERT INTO attack_memory_items VALUES('A1','sess-1','10.0.0.5','services','80/tcp',"
        "'10.0.0.5:80/tcp http','nmap',1,'{}','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00',1)"
    )
    conn.commit()
    conn.close()


def test_memory_returns_lessons_and_attack_memory(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    _seed_lesson()
    _seed_attack_memory(tmp_path)
    resp = client.get("/api/v1/system/memory", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert any(lesson["action_type"] == "mod:strat" for lesson in data["lessons"])
    assert any(c["action_type"] == "mod:strat" for c in data["confidence"])
    assert any(m["category"] == "services" for m in data["attack_memory"])


def test_memory_empty_when_no_data(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/system/memory", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert data["lessons"] == []
    assert data["confidence"] == []
    assert data["attack_memory"] == []
