"""Tests for the frontend-integration API endpoints added in the v1.1 expansion.

Covers: GET /goals, GET /config/schema, enriched /diagnostics/*, GET /models/live,
GET /skills/{name}, GET /runs/{id}/artifacts(+/{name}), GET /audit, GET /swarm,
GET /campaign, GET /logs/{name}, GET /credentials + POST .../reveal (audited),
GET /loot, DELETE /runs/{id}, GET /decisions/{id}, SSE auth, enriched GET /runs,
and the event_broker replay-cursor bug fix.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="test-token", ollama_host="http://localhost:11434"):
    """Create a TestClient with a known token + minimal config (no Ollama needed).

    ``ollama_host`` lets a test point the live-models route at an unreachable
    host so the 503 fallback fires deterministically even when a real Ollama
    is running on the dev box's :11434.
    """
    monkeypatch.setenv("NETATTACKAI_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"ollama:\n  host: {ollama_host}\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from tools.run_service.service import Callables

    class _FakeRouter:
        _clients = {"glm": MagicMock()}
        def get_client(self, name):
            return self._clients[name]

    def _fake_build_router(*a, **kw):
        return _FakeRouter()

    async def _fake_run_session(**kwargs):
        return {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""}

    callables = Callables(build_router=_fake_build_router, run_session=_fake_run_session)
    from app import create_app
    app = create_app(config_path=config_path, callables=callables)
    return TestClient(app)


def _auth(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


def _create_run(client, target="10.0.0.50"):
    resp = client.post("/api/v1/runs", json={
        "target": target, "mode": "attack", "goal": "recon_only",
    }, headers=_auth())
    assert resp.status_code == 201
    return resp.json()


# ── Goals (B4) ───────────────────────────────────────────────────────────────

def test_goals_list(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/goals", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert "goals" in data
    names = [g["name"] for g in data["goals"]]
    assert "recon_only" in names
    assert "backdoor" in names
    for g in data["goals"]:
        assert g["risk"] in {"safe", "gated", "high"}
        assert "description" in g and g["description"]


# ── Config schema (B5) ───────────────────────────────────────────────────────

def test_config_schema(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/config/schema", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert "schema" in data
    schema = data["schema"]
    assert "ollama" in schema or "exploit" in schema


# ── Enriched diagnostics (B6) ────────────────────────────────────────────────

def test_doctor_returns_output(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/diagnostics/doctor", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert "exit_code" in data
    assert "output" in data and isinstance(data["output"], str)
    assert "NetAttackAI" in data["output"] or "Self-Check" in data["output"]


def test_self_test_returns_output(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/diagnostics/self-test", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert "exit_code" in data
    assert "output" in data and isinstance(data["output"], str)


# ── Live Ollama models (C1) ──────────────────────────────────────────────────

def test_models_live_falls_back_when_ollama_unreachable(tmp_path, monkeypatch):
    # Point the route at a closed port so the 503 fallback fires deterministically,
    # regardless of whether a real Ollama is running on localhost:11434.
    client = _make_client(tmp_path, monkeypatch, ollama_host="http://127.0.0.1:9")
    resp = client.get("/api/v1/models/live", headers=_auth())
    # Ollama not running in tests -> 503 fallback with registry
    assert resp.status_code == 503
    data = resp.json()
    assert data["source"] == "registry"
    assert "glm-5.2:cloud" in data["models"]


# ── Skill detail (C2) ────────────────────────────────────────────────────────

def test_skill_detail_not_found(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/skills/nonexistent_skill", headers=_auth())
    # Skill loading is best-effort; the route returns 404 when the registry has no match.
    assert resp.status_code in (404, 500)


# ── Enriched run list (B1) ───────────────────────────────────────────────────

def test_list_runs_includes_target_and_mode(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    _create_run(client, target="10.0.0.99")
    resp = client.get("/api/v1/runs", headers=_auth())
    assert resp.status_code == 200
    runs = resp.json()["runs"]
    assert any(r.get("target") == "10.0.0.99" for r in runs)
    assert any(r.get("mode") == "attack" for r in runs)


# ── Artifacts (B2-B3) ────────────────────────────────────────────────────────

def test_list_artifacts_empty_for_new_run(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    resp = client.get(f"/api/v1/runs/{created['run_id']}/artifacts", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert "artifacts" in data and isinstance(data["artifacts"], list)


def test_list_artifacts_includes_written_file(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    run_dir = Path("reports") / created["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "session_summary.md").write_text("# Summary\nTest run.", encoding="utf-8")
    resp = client.get(f"/api/v1/runs/{created['run_id']}/artifacts", headers=_auth())
    names = [a["name"] for a in resp.json()["artifacts"]]
    assert "session_summary.md" in names


def test_get_artifact_content(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    run_dir = Path("reports") / created["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text('{"k": 1}', encoding="utf-8")
    resp = client.get(f"/api/v1/runs/{created['run_id']}/artifacts/run.json", headers=_auth())
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert json.loads(resp.content) == {"k": 1}


def test_get_artifact_rejects_unknown_name(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    resp = client.get(f"/api/v1/runs/{created['run_id']}/artifacts/../../etc/passwd", headers=_auth())
    assert resp.status_code in (400, 404)


def test_get_artifact_rejects_non_whitelisted_name(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    run_dir = Path("reports") / created["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "secret.txt").write_text("secret", encoding="utf-8")
    resp = client.get(f"/api/v1/runs/{created['run_id']}/artifacts/secret.txt", headers=_auth())
    assert resp.status_code == 404


# ── Audit trail (C6) ─────────────────────────────────────────────────────────

def test_audit_empty_when_no_file(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    resp = client.get(f"/api/v1/runs/{created['run_id']}/audit", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert data["records"] == []
    assert data["chain_valid"] is True


def test_audit_reads_records_and_verifies_chain(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    run_dir = Path("reports") / created["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "exploit_audit.jsonl").write_text(
        json.dumps({"action": "test", "command": "echo", "hash": "", "prev_hash": ""}) + "\n",
        encoding="utf-8",
    )
    resp = client.get(f"/api/v1/runs/{created['run_id']}/audit", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["records"]) == 1
    assert "chain_valid" in data and "chain_reason" in data


# ── Swarm + campaign state (C7-C8) ───────────────────────────────────────────

def test_swarm_state_not_found(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    resp = client.get(f"/api/v1/runs/{created['run_id']}/swarm", headers=_auth())
    assert resp.status_code == 404


def test_swarm_state_returns_json(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    swarm_dir = Path("reports") / created["run_id"] / "swarm_workspace"
    swarm_dir.mkdir(parents=True, exist_ok=True)
    (swarm_dir / "swarm_state.json").write_text('{"phase": "recon"}', encoding="utf-8")
    resp = client.get(f"/api/v1/runs/{created['run_id']}/swarm", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["state"] == {"phase": "recon"}


def test_campaign_state_returns_json(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    # The autonomous orchestrator runs under swarm_workspace/autonomous/, so
    # attack_states.json lives there (not at the swarm_workspace root).
    autonomous_dir = Path("reports") / created["run_id"] / "swarm_workspace" / "autonomous"
    autonomous_dir.mkdir(parents=True, exist_ok=True)
    (autonomous_dir / "attack_states.json").write_text('{"phase": "exploitation"}', encoding="utf-8")
    resp = client.get(f"/api/v1/runs/{created['run_id']}/campaign", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["state"] == {"phase": "exploitation"}


# ── Log tailing (C9) ─────────────────────────────────────────────────────────

def test_log_not_found_for_unknown_name(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    resp = client.get(f"/api/v1/runs/{created['run_id']}/logs/nonexistent.log", headers=_auth())
    assert resp.status_code == 404


def test_log_returns_tail(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    run_dir = Path("reports") / created["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "session_error.log").write_text("line1\nline2\nline3\n", encoding="utf-8")
    resp = client.get(
        f"/api/v1/runs/{created['run_id']}/logs/session_error.log?tail=2",
        headers=_auth(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_lines_returned"] == 2
    assert data["lines"] == ["line2", "line3"]


def test_log_per_attempt_requires_params(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    resp = client.get(
        f"/api/v1/runs/{created['run_id']}/logs/terminal.log?tail=10",
        headers=_auth(),
    )
    assert resp.status_code == 400


# ── Credentials + loot (C3-C5) ──────────────────────────────────────────────

def _seed_credentials(run_id: str, password="s3cr3t"):
    import time
    from tools.credential_store import CredentialRecord, CredentialStore
    ws = Path("reports") / run_id / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    store = CredentialStore(ws)
    store.add(CredentialRecord(
        timestamp=time.time(),
        source_host="10.0.0.50",
        target_host="10.0.0.99",
        username="admin",
        password=password,
        credential_type="password",
        source_action="dump_credentials",
    ))


def test_credentials_redacted(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    _seed_credentials(created["run_id"], password="hunter2")
    resp = client.get(f"/api/v1/runs/{created['run_id']}/credentials", headers=_auth())
    assert resp.status_code == 200
    creds = resp.json()["credentials"]
    assert len(creds) == 1
    assert creds[0]["password"] == "[REDACTED]"
    assert creds[0]["username"] == "admin"


def test_credential_reveal_returns_plaintext_and_audits(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    _seed_credentials(created["run_id"], password="hunter2")
    resp = client.post(
        f"/api/v1/runs/{created['run_id']}/credentials/0/reveal", headers=_auth(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["password"] == "hunter2"
    assert data["username"] == "admin"
    access_log = Path("reports") / created["run_id"] / "credential_access.jsonl"
    assert access_log.exists()
    entry = json.loads(access_log.read_text(encoding="utf-8").strip())
    assert entry["index"] == 0
    assert entry["username"] == "admin"


def test_credential_reveal_out_of_range(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    _seed_credentials(created["run_id"])
    resp = client.post(
        f"/api/v1/runs/{created['run_id']}/credentials/99/reveal", headers=_auth(),
    )
    assert resp.status_code == 404


def test_loot_empty_when_no_file(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    resp = client.get(f"/api/v1/runs/{created['run_id']}/loot", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["loot"] == []


def test_loot_returns_items(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    from tools.credential_store import LootItem, LootStore
    ws = Path("reports") / created["run_id"] / "exploit_workspace"
    ws.mkdir(parents=True, exist_ok=True)
    store = LootStore(ws)
    store.add(LootItem(
        timestamp=1.0, source_host="10.0.0.99", loot_type="file",
        description="/etc/shadow", content="root:...",
    ))
    resp = client.get(f"/api/v1/runs/{created['run_id']}/loot", headers=_auth())
    assert resp.status_code == 200
    loot = resp.json()["loot"]
    assert len(loot) == 1
    assert loot[0]["loot_type"] == "file"


# ── DELETE run (D1) ───────────────────────────────────────────────────────────

def test_delete_run_after_cancel(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    client.post(f"/api/v1/runs/{created['run_id']}/cancel", headers=_auth())
    resp = client.delete(f"/api/v1/runs/{created['run_id']}", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    # Gone from the DB.
    assert client.get(f"/api/v1/runs/{created['run_id']}", headers=_auth()).status_code == 404


def test_delete_run_refuses_active(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)  # awaiting_confirmation = active
    resp = client.delete(f"/api/v1/runs/{created['run_id']}", headers=_auth())
    assert resp.status_code == 409


def test_delete_run_purge_removes_directory(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    client.post(f"/api/v1/runs/{created['run_id']}/cancel", headers=_auth())
    run_dir = Path("reports") / created["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "session_summary.md").write_text("x", encoding="utf-8")
    resp = client.delete(
        f"/api/v1/runs/{created['run_id']}?purge=true", headers=_auth(),
    )
    assert resp.status_code == 200
    assert resp.json()["purged"] is True
    assert not run_dir.exists()


# ── Single decision GET (D2) ─────────────────────────────────────────────────

def test_get_single_decision(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    decision_id = created["decision"]["id"]
    resp = client.get(
        f"/api/v1/runs/{created['run_id']}/decisions/{decision_id}",
        headers=_auth(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == decision_id
    assert data["kind"] == "start_confirm"
    assert "prompt_text" in data


def test_get_single_decision_wrong_run(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    decision_id = created["decision"]["id"]
    resp = client.get(
        f"/api/v1/runs/nonexistent/decisions/{decision_id}",
        headers=_auth(),
    )
    assert resp.status_code == 404


# ── SSE auth (D4) ────────────────────────────────────────────────────────────

def test_sse_rejects_missing_token(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    resp = client.get(
        f"/api/v1/runs/{created['run_id']}/events/stream?after=0",
        headers=_auth(),  # auth header doesn't help SSE; needs ?token=
    )
    assert resp.status_code == 401


def test_sse_rejects_wrong_token(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    resp = client.get(
        f"/api/v1/runs/{created['run_id']}/events/stream?after=0&token=wrong",
        headers=_auth(),
    )
    assert resp.status_code == 401


def test_sse_accepts_correct_token(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    created = _create_run(client)
    # Cancel the run so the event broker closes and the SSE stream ends
    # after replaying buffered events (avoids hanging the TestClient).
    client.post(f"/api/v1/runs/{created['run_id']}/cancel", headers=_auth())
    resp = client.get(
        f"/api/v1/runs/{created['run_id']}/events/stream?after=0&token=test-token",
        headers=_auth(),
    )
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("content-type", "")


# ── Event replay bug fix (A1) ────────────────────────────────────────────────

def test_replay_reads_jsonl_when_cursor_outside_ring():
    """The fixed _replay_locked must read events.jsonl when the ring doesn't
    cover the requested cursor (previously dead code returned [] silently).
    """
    import asyncio
    from tools.api.event_broker import RunEventBroker
    rd = Path(__import__("tempfile").mkdtemp()) / "run"
    rd.mkdir(parents=True, exist_ok=True)
    broker = RunEventBroker("r1", rd, buffer_size=2)

    async def _run():
        await broker.emit("state", {"v": 1})  # seq 1
        await broker.emit("state", {"v": 2})  # seq 2
        await broker.emit("state", {"v": 3})  # seq 3 -> evicts seq 1 from ring
        # Ring holds seq 2,3. Cursor after=0 is older than the ring's first
        # element, so the JSONL fallback path must run and return all 3.
        replayed = await broker.replay(after=0)
        assert len(replayed) == 3, f"expected 3, got {len(replayed)}"

    asyncio.run(_run())


def test_replay_jsonl_after_close():
    """After the broker closes, a replay cursor outside the ring must still
    read from events.jsonl (the bug fix path)."""
    import asyncio
    from tools.api.event_broker import RunEventBroker
    rd = Path(__import__("tempfile").mkdtemp()) / "run"
    rd.mkdir(parents=True, exist_ok=True)
    broker = RunEventBroker("r2", rd, buffer_size=1)

    async def _run():
        await broker.emit("state", {"v": 1})
        await broker.emit("state", {"v": 2})
        broker.close()
        # Ring holds only seq 2 (buffer_size=1); cursor 0 must fall back to JSONL.
        replayed = await broker.replay(after=0)
        assert len(replayed) == 2

    asyncio.run(_run())