"""Regression tests for WebUI functional blockers fixed in this change.

Covers three regressions that blocked the attack wizard:

1. ``/openapi.json`` returned HTTP 500 (PydanticUserError on the bare
   ``Response`` return annotation of the SSE stream route) when the bundled
   WebUI was served. Now returns 200 with a valid schema.
2. Goal selection is persisted: ``goal`` / ``custom_goal`` sent in the
   create-run request reach the persisted run record (preview.goal_name /
   request_json).
3. Invalid IPv4 like ``999.999.999.999`` is rejected by the backend's strict
   validator (mirrors the browser-side check added in
   ``webui/src/lib/targetValidation.ts``).

These run against the real FastAPI app with a fake router (no Ollama).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from fastapi.testclient import TestClient


def _make_client(tmp_path, monkeypatch, token="test-token"):
    """Create a TestClient with a known token + minimal config (no Ollama needed)."""
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


def _auth_headers(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


# ── OpenAPI fix ───────────────────────────────────────────────────────────────


def test_openapi_json_returns_200(tmp_path, monkeypatch):
    """``/openapi.json`` must return 200 with a usable schema, not 500.

    Regression: the SSE stream route declared ``-> Response`` (bare starlette
    base class) as its return type. With ``from __future__ import annotations``
    that became an unresolved ForwardRef, and FastAPI's schema generator raised
    ``PydanticUserError`` for every ``/openapi.json`` request. The fix uses
    the concrete ``StreamingResponse`` return type.
    """
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/openapi.json")
    assert resp.status_code == 200, f"openapi.json returned {resp.status_code}"
    schema = resp.json()
    assert "paths" in schema
    # The core API routes are still present in the schema.
    assert "/api/v1/runs" in schema["paths"]


def test_openapi_json_200_with_serve_webui(tmp_path, monkeypatch):
    """The bundled-WebUI mount must not break ``/openapi.json`` either."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from tools import config_cli as _config_cli

    config = _config_cli.load_config(config_path)
    config.setdefault("api", {})["serve_webui"] = True
    from app import create_app

    app = create_app(config_path=config_path, config=config)
    client = TestClient(app)
    resp = client.get("/openapi.json")
    assert resp.status_code == 200, f"openapi.json returned {resp.status_code}"


# ── Goal persistence ─────────────────────────────────────────────────────────


def test_create_run_persists_preset_goal(tmp_path, monkeypatch):
    """``goal`` in the create-run request is reflected in preview.goal_name."""
    import time

    client = _make_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    assert resp.status_code == 201
    run_id = resp.json()["run_id"]
    assert resp.json()["state"] == "preparing"
    # The preview is filled when background preparation completes.
    detail: dict = {}
    for _ in range(100):
        detail = client.get(f"/api/v1/runs/{run_id}", headers=_auth_headers()).json()
        if detail.get("state") == "awaiting_confirmation":
            break
        time.sleep(0.02)
    assert detail.get("state") == "awaiting_confirmation"
    assert detail.get("preview", {}).get("goal_name") == "recon_only"


def test_create_run_persists_custom_goal(tmp_path, monkeypatch):
    """``custom_goal`` is accepted and persisted on the run record."""
    client = _make_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/runs",
        json={
            "target": "10.0.0.50",
            "mode": "attack",
            "custom_goal": "Demonstrate RCE via the exposed Jenkins console",
        },
        headers=_auth_headers(),
    )
    assert resp.status_code == 201
    run_id = resp.json()["run_id"]
    # Verify persistence on the GET /runs/{id} record.
    detail = client.get(f"/api/v1/runs/{run_id}", headers=_auth_headers()).json()
    req = detail.get("request", {})
    # custom_goal is stored on the persisted request payload.
    assert req.get("custom_goal") == "Demonstrate RCE via the exposed Jenkins console"


def test_create_run_state_is_awaiting_confirmation(tmp_path, monkeypatch):
    """A non-``yes`` attack run lands in awaiting_confirmation (the gate the
    wizard must advance to). This is the contract the wizard transition relies on.
    """
    import time

    client = _make_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/runs",
        json={
            "target": "127.0.0.1",
            "mode": "attack",
            "goal": "recon_only",
        },
        headers=_auth_headers(),
    )
    assert resp.status_code == 201
    run_id = resp.json()["run_id"]
    # POST returns immediately with state=preparing; preparation is async.
    assert resp.json()["state"] == "preparing"
    state = ""
    for _ in range(100):
        detail = client.get(f"/api/v1/runs/{run_id}", headers=_auth_headers()).json()
        state = detail.get("state", "")
        if state == "awaiting_confirmation":
            break
        time.sleep(0.02)
    assert state == "awaiting_confirmation"
    decisions = client.get(f"/api/v1/runs/{run_id}/decisions", headers=_auth_headers()).json()["decisions"]
    assert any(d["kind"] == "start_confirm" and d["status"] == "pending" for d in decisions), (
        "a start_confirm decision must be present for the review step"
    )


# ── Invalid IPv4 rejection (backend mirror of browser check) ─────────────────


def test_backend_rejects_invalid_ipv4_999(tmp_path, monkeypatch):
    """The backend's strict IPv4 validator rejects 999.999.999.999.

    Mirrors ``webui/src/lib/targetValidation.ts`` so the browser and backend
    agree. The create-run endpoint surfaces this as a 4xx (the run service
    refuses to prepare an invalid target) rather than silently accepting.
    """
    from tools.validation_utils import validate_target

    assert validate_target("999.999.999.999") is False
    assert validate_target("256.1.1.1") is False
    assert validate_target("127.0.0.1") is True
    assert validate_target("10.0.0.50") is True
