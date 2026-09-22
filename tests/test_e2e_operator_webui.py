"""Operator-level E2E: WebUI + localhost mission path (todo 13).

Covers the true operator path the unit suites only test in pieces:
start (loopback API daemon) → bearer-gated WebUI API → create a
localhost mission → stream events → inspect evidence → finish. Guard
rails are asserted in the same file: loopback bind + bearer + WS origin
checks, scope-guard refusal of non-allowlisted targets, and
sandbox-enforcing (fail-closed) configuration.

Everything here is hermetic: the engine (model router + ``run_session``)
is faked, the HTTP stack (FastAPI ``TestClient``) is real. No browser
launches, no docker, no model backend, no external targets — the mission
runs against ``127.0.0.1`` only. The live Playwright browser pass
(TokenGate → OnboardingGate → run wizard in a real Chromium) is the CI
browser job's domain; the ``integration``-marked scaffold at the bottom
pins its preconditions (playwright present, loopback-only origin, run
routes mounted) and skips without playwright.

DO NOT extend this file to touch non-loopback targets: the scope-guard
tests below fail the file if the allowlist story ever regresses.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

TOKEN = "test-token-0123456789abcdef01234567"
LOOPBACK_TARGET = "127.0.0.1"
OFF_ALLOWLIST_TARGET = "203.0.113.7"  # TEST-NET-3, never routable here


def _auth_headers(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _make_client(tmp_path, monkeypatch, token: str = TOKEN):
    """Loopback API daemon with a faked engine (no model backend needed)."""
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "  require_explicit_allowlist: true\n"
        "  allowed_targets: [127.0.0.1]\n"
        "sandbox:\n  enabled: true\n  fallback_native: false\n"
        "api:\n  host: 127.0.0.1\n  port: 8765\n",
        encoding="utf-8",
    )
    from tools.run_service.service import Callables

    class _FakeRouter:
        _clients = {"glm": MagicMock()}

        def get_client(self, name):
            return self._clients[name]

    async def _fake_run_session(**kwargs):
        """Fake engine: write operator-visible evidence, then report done."""
        reports_dir = Path(kwargs["reports_dir"])
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / "session_summary.md").write_text(
            f"# Operator E2E run\n\nTarget: {kwargs.get('target_ip')}\nMode: {kwargs.get('mode')}\n",
            encoding="utf-8",
        )
        (reports_dir / "exploit_audit.jsonl").write_text(
            json.dumps({"tool_name": "e2e_probe", "status": "completed", "target_ip": kwargs.get("target_ip")})
            + "\n",
            encoding="utf-8",
        )
        return {"total_actions": 1, "workspace": str(reports_dir), "audit_path": ""}

    callables = Callables(
        build_router=lambda *a, **kw: _FakeRouter(),
        run_session=_fake_run_session,
    )
    from app import create_app

    app = create_app(config_path=config_path, callables=callables)
    client = TestClient(app)
    client.__enter__()
    return client


def _wait_state(client, run_id: str, states: set[str], attempts: int = 300) -> dict:
    """Poll until the run reaches one of ``states`` (background tasks)."""
    import time

    last: dict = {}
    for _ in range(attempts):
        run = client.get(f"/api/v1/runs/{run_id}", headers=_auth_headers()).json()
        last = run
        if run.get("state") in states:
            return run
        time.sleep(0.02)
    raise AssertionError(f"run {run_id} never reached {states} (last state: {last.get('state')})")


def _wait_decision(client, run_id: str, attempts: int = 300) -> dict:
    """Poll until background preparation creates the start_confirm decision."""
    import time

    last: list[dict] = []
    for _ in range(attempts):
        resp = client.get(f"/api/v1/runs/{run_id}/decisions", headers=_auth_headers())
        assert resp.status_code == 200
        last = resp.json()["decisions"]
        for row in last:
            if row["kind"] == "start_confirm" and row["status"] == "pending":
                return row
        time.sleep(0.02)
    raise AssertionError(f"no pending start_confirm decision for {run_id} (got {last})")


# ── The operator path: start → mission → events → evidence → finish ──────────


def test_operator_path_localhost_mission_to_finish(tmp_path, monkeypatch):
    """Start → create localhost mission → events → evidence → finish."""
    client = _make_client(tmp_path, monkeypatch)

    # 1. Start a localhost mission (recon keeps the start_confirm non-destructive).
    created = client.post(
        "/api/v1/runs",
        json={"target": LOOPBACK_TARGET, "mode": "recon", "goal": "recon_only"},
        headers=_auth_headers(),
    )
    assert created.status_code == 201
    assert created.json()["state"] == "preparing"
    run_id = created.json()["run_id"]

    # 2. Preparation completes in the background: preview + start_confirm gate.
    run = _wait_state(client, run_id, {"awaiting_confirmation"})
    assert run["preview"]["target_ip"] == LOOPBACK_TARGET
    decision_id = _wait_decision(client, run_id)["id"]

    # 3. Observe the event stream (replay endpoint over the live broker).
    events = client.get(f"/api/v1/runs/{run_id}/events?after=0", headers=_auth_headers())
    assert events.status_code == 200
    assert isinstance(events.json().get("events"), list)

    # 4. Confirm start; the (faked) engine executes and finishes.
    answer = client.post(
        f"/api/v1/runs/{run_id}/decisions/{decision_id}",
        json={"answer": "yes"},
        headers=_auth_headers(),
    )
    assert answer.status_code == 200
    finished = _wait_state(client, run_id, {"completed"})
    assert finished["state"] == "completed"

    # 5. Inspect evidence: run-level artifacts written by the engine.
    artifacts = client.get(f"/api/v1/runs/{run_id}/artifacts", headers=_auth_headers())
    assert artifacts.status_code == 200
    names = {a["name"] for a in artifacts.json()["artifacts"]}
    assert "session_summary.md" in names
    assert "exploit_audit.jsonl" in names
    summary = client.get(f"/api/v1/runs/{run_id}/artifacts/session_summary.md", headers=_auth_headers())
    assert summary.status_code == 200
    assert LOOPBACK_TARGET in summary.text

    # 6. Finish: audit trail readable, run deletable (purge removes evidence).
    audit = client.get(f"/api/v1/runs/{run_id}/audit", headers=_auth_headers())
    assert audit.status_code == 200
    deleted = client.delete(f"/api/v1/runs/{run_id}?purge=true", headers=_auth_headers())
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert client.get(f"/api/v1/runs/{run_id}", headers=_auth_headers()).status_code == 404


# ── Guard rail 1: loopback bind + bearer + origin ────────────────────────────


def test_bearer_required_on_operator_api(tmp_path, monkeypatch):
    """No token → 401; wrong token → 401 (constant-time compare)."""
    client = _make_client(tmp_path, monkeypatch)
    assert client.get("/api/v1/runs").status_code == 401
    assert client.get("/api/v1/runs", headers=_auth_headers("wrong-token-0123456789abcdef01234567")).status_code == 401
    assert client.get("/api/v1/runs", headers=_auth_headers()).status_code == 200


def test_loopback_bind_refused():
    """v1 has no public-bind override: only 127.0.0.1/localhost/::1."""
    from tools.api.auth import assert_api_loopback

    for host in ("127.0.0.1", "localhost", "::1"):
        assert_api_loopback(host)  # must not raise
    for host in ("0.0.0.0", "10.0.0.1", "192.168.1.10", "example.com"):
        with pytest.raises(ValueError, match="loopback"):
            assert_api_loopback(host)


def test_ws_origin_table():
    """Non-loopback and null origins never pass; loopback passes."""
    from tools.api.auth import is_loopback_origin

    assert is_loopback_origin("http://127.0.0.1:8765", []) is True
    assert is_loopback_origin("http://localhost:5173", []) is True
    assert is_loopback_origin("http://[::1]:8765", []) is True
    assert is_loopback_origin("http://evil.com", []) is False
    assert is_loopback_origin("http://192.168.1.10:8765", []) is False
    assert is_loopback_origin("null", []) is False
    assert is_loopback_origin("", []) is False


class _StubWS:
    """Minimal WebSocket stub for authenticate_websocket (no server needed)."""

    def __init__(self, headers, messages=None):
        self.headers = headers
        self._messages = list(messages or [])
        self.accepted = False
        self.closed = None

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)

    async def receive_json(self):
        return self._messages.pop(0)


def test_ws_origin_rejected_before_auth():
    """A non-loopback Origin is closed 4403 before any auth is considered."""
    import asyncio

    from tools.api.auth import authenticate_websocket

    ws = _StubWS({"origin": "http://evil.com"})
    assert asyncio.run(authenticate_websocket(ws, TOKEN, [])) is None
    assert ws.closed is not None and ws.closed[0] == 4403
    assert ws.accepted is False


def test_ws_bad_token_rejected():
    """Loopback origin + wrong token over the legacy first-message path → 4401."""
    import asyncio

    from tools.api.auth import authenticate_websocket

    ws = _StubWS({"origin": "http://127.0.0.1:8765"}, [{"auth": "wrong-token"}])
    assert asyncio.run(authenticate_websocket(ws, TOKEN, [])) is None
    assert ws.closed is not None and ws.closed[0] == 4401


def test_ws_good_token_accepted():
    """Loopback origin + correct token → authenticated message."""
    import asyncio

    from tools.api.auth import authenticate_websocket

    ws = _StubWS({"origin": "http://127.0.0.1:8765"}, [{"auth": TOKEN}])
    first = asyncio.run(authenticate_websocket(ws, TOKEN, []))
    assert first is not None and first.get("after") == 0


# ── Guard rail 2: scope-guard fails on non-allowlisted targets ───────────────


def _lab_config() -> dict:
    return {
        "exploit": {
            "require_explicit_allowlist": True,
            "allowed_targets": [LOOPBACK_TARGET],
        }
    }


def _isolate_allowlist_env(monkeypatch):
    """Drop env-union entries so the test pins config behavior, not ambient env."""
    for var in ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN", "EXPLOIT_DISCOVERED_TARGETS"):
        monkeypatch.delenv(var, raising=False)


def test_scope_guard_allows_loopback_denies_external(monkeypatch):
    """The target-IP lock: loopback in, TEST-NET-3 out, reason names the fix."""
    from tools.kernel.allowlist import _check_allowlist

    _isolate_allowlist_env(monkeypatch)
    allowed, _ = _check_allowlist(LOOPBACK_TARGET, _lab_config())
    assert allowed is True
    ok, reason = _check_allowlist(OFF_ALLOWLIST_TARGET, _lab_config())
    assert ok is False
    assert "allowlist" in reason


def test_scope_guard_rejects_mixed_target_list(monkeypatch):
    """One off-allowlist host poisons the whole list (fail closed)."""
    from tools.kernel.allowlist import check_targets_allowlist

    _isolate_allowlist_env(monkeypatch)
    ok, _ = check_targets_allowlist([LOOPBACK_TARGET], _lab_config())
    assert ok is True
    ok, reason = check_targets_allowlist([LOOPBACK_TARGET, OFF_ALLOWLIST_TARGET], _lab_config())
    assert ok is False
    assert "allowlist" in reason


# ── Guard rail 3: sandbox stays enforcing ────────────────────────────────────


def test_sandbox_enforcing_fail_closed():
    """Lab default: sandbox on, no host-execution fallback (fail closed)."""
    from tools.sandbox.models import SandboxConfig

    cfg = SandboxConfig.from_config({"sandbox": {"enabled": True, "fallback_native": False}})
    assert cfg.enabled is True
    assert cfg.fallback_native is False


def test_sandbox_explicit_disable_required():
    """Missing sandbox section defaults to contained; only explicit false opts out."""
    from tools.sandbox.models import SandboxConfig

    assert SandboxConfig.from_config({}).enabled is True
    assert SandboxConfig.from_config({"sandbox": {"enabled": False}}).enabled is False


# ── WebUI gates (static: TokenGate → OnboardingGate → run routes) ────────────


def test_webui_token_and_onboarding_gates_present():
    """The SPA mounts TokenGate + OnboardingGate above the run routes."""
    app_tsx = Path(__file__).resolve().parent.parent / "webui" / "src" / "App.tsx"
    assert app_tsx.is_file(), "webui/src/App.tsx missing — WebUI gate check needs it"
    src = app_tsx.read_text(encoding="utf-8")
    assert "TokenGate" in src
    assert "OnboardingGate" in src
    assert "/runs" in src


# ── Live browser scaffold (CI browser job; skipped without playwright) ───────


@pytest.mark.integration
def test_browser_operator_pass_preconditions():
    """Preconditions for the live Chromium operator pass (CI browser job).

    The live pass drives TokenGate → OnboardingGate → new run on
    127.0.0.1 → waits for events → asserts evidence → finishes, against
    the same loopback-only allowlist pinned above. It needs a built SPA
    (``webui/dist/``), a real daemon, and playwright+chromium, so it is
    ``integration``-marked and skipped here; this scaffold fails loudly
    if the opening move (loopback origin, run routes) ever regresses.
    """

    pytest.importorskip("playwright")
    from tools.api.auth import is_loopback_origin

    # The browser job serves the SPA from the loopback daemon only.
    assert is_loopback_origin("http://127.0.0.1:8765", []) is True
    assert is_loopback_origin("http://localhost:5173", []) is True
    # Run routes the browser wizard drives must stay mounted.
    from tools.api.routes import events as _events_mod
    from tools.api.routes import runs as _runs_mod

    assert hasattr(_runs_mod, "create_router")
    assert hasattr(_events_mod, "create_router")
