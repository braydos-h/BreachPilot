"""Tests for the per-run sandbox summary endpoint (GET /runs/{id}/sandbox).

The endpoint derives everything from on-disk run artifacts (exploit_audit.jsonl
sandbox rows + events.jsonl tool_result SANDBOX_* blocks); these tests write
synthetic artifacts and assert the summary shape, counts, cleanup exclusion,
recent-block limit, and 404/empty behavior.
"""

from __future__ import annotations

import json

from tests.test_api_runs import _auth_headers, _make_client


def _write_jsonl(path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _sandbox_payload(container: str = "abc123def456") -> dict:
    return {
        "enabled": True,
        "backend": "docker",
        "run_id": "sandboxrun1",
        "container_id": container,
        "image": "breachpilot-sandbox:latest",
        "user": "sandbox",
        "env_keys": ["EXPLOIT_SANDBOX", "EXPLOIT_WORKSPACE", "TERM"],
        "network": {
            "authorized_destinations": ["10.0.0.50/32"],
            "explicitly_blocked": ["169.254.169.254/32"],
            "allow_dns": "controlled",
            "resolved_domains": {"example.com": "93.184.216.34"},
            "unresolved_targets": [],
            "enforced": True,
            "fingerprint": "fp-123",
        },
        "exit_code": 0,
        "timeout_seconds": 300,
    }


def _create_run(client) -> str:
    resp = client.post(
        "/api/v1/runs",
        json={"target": "10.0.0.50", "mode": "attack", "goal": "recon_only"},
        headers=_auth_headers(),
    )
    assert resp.status_code == 201
    return resp.json()["run_id"]


def test_sandbox_endpoint_404_for_unknown_run(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/runs/nonexistent/sandbox", headers=_auth_headers())
    assert resp.status_code == 404


def test_sandbox_endpoint_empty_run(tmp_path, monkeypatch):
    """A run with no artifacts returns a found=false summary, not a 404/500."""
    client = _make_client(tmp_path, monkeypatch)
    run_id = _create_run(client)
    resp = client.get(f"/api/v1/runs/{run_id}/sandbox", headers=_auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is False
    assert data["executions"]["total"] == 0
    assert data["blocked"] == {"total": 0, "recent": []}


def test_sandbox_endpoint_summarizes_audit_and_events(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    run_id = _create_run(client)
    run_dir = tmp_path / "reports" / run_id
    payload = _sandbox_payload()
    _write_jsonl(
        run_dir / "exploit_audit.jsonl",
        [
            {
                "timestamp": "2026-08-29T10:00:00+00:00",
                "tool_name": "sandbox.run_exploit_terminal",
                "status": "started",
                "command": "id",
                "sandbox": payload,
            },
            {
                "timestamp": "2026-08-29T10:00:05+00:00",
                "tool_name": "sandbox.run_exploit_terminal",
                "status": "completed",
                "command": "id",
                "sandbox": payload,
            },
            # Generic blocked tool row (no sandbox payload) -> blocked count only.
            {
                "timestamp": "2026-08-29T10:00:06+00:00",
                "tool_name": "run_exploit_terminal",
                "status": "blocked",
                "command": "",
            },
            # Cleanup row must NOT inflate execution counts.
            {
                "timestamp": "2026-08-29T10:01:00+00:00",
                "tool_name": "sandbox.cleanup",
                "status": "completed",
                "command": "",
                "sandbox": {**payload, "network": None},
            },
        ],
    )
    _write_jsonl(
        run_dir / "events.jsonl",
        [
            {
                "timestamp": "2026-08-29T10:02:00+00:00",
                "type": "tool_result",
                "payload": {
                    "name": "run_exploit_terminal",
                    "success": False,
                    "result": "TERMINAL_RESULT: BLOCKED\nSANDBOX_UNAVAILABLE\ndocker daemon unreachable\nTOOL: run_exploit_terminal",
                },
            },
            {
                "timestamp": "2026-08-29T10:03:00+00:00",
                "type": "tool_result",
                "payload": {"name": "web_scan", "success": True, "result": "scan ok"},
            },
        ],
    )
    resp = client.get(f"/api/v1/runs/{run_id}/sandbox", headers=_auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["config"]["image"] == "breachpilot-sandbox:latest"
    assert data["config"]["user"] == "sandbox"
    assert data["container"]["id"] == "abc123def456"
    assert data["container"]["sandbox_run_id"] == "sandboxrun1"
    assert data["executions"] == {"attempts": 1, "completed": 1, "failed": 0, "timed_out": 0, "total": 1}
    assert data["network"]["enforced"] is True
    assert data["network"]["fingerprint"] == "fp-123"
    assert data["network"]["authorized_destinations"] == ["10.0.0.50/32"]
    assert data["network"]["resolved_domains"] == {"example.com": "93.184.216.34"}
    assert data["blocked"]["total"] == 1
    assert len(data["blocked"]["recent"]) == 1
    block = data["blocked"]["recent"][0]
    assert block["tool"] == "run_exploit_terminal"
    assert block["code"] == "SANDBOX_UNAVAILABLE"
    assert block["message"] == "docker daemon unreachable"
    assert data["last_activity"] == "2026-08-29T10:01:00+00:00"


def test_sandbox_endpoint_recent_blocks_capped_at_five(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    run_id = _create_run(client)
    run_dir = tmp_path / "reports" / run_id
    codes = ["SANDBOX_SCOPE_DENIED", "SANDBOX_POLICY_FAILED", "SANDBOX_UNSUPPORTED", "SANDBOX_WORKSPACE_FAILED"]
    events = []
    for i in range(7):
        events.append(
            {
                "timestamp": f"2026-08-29T11:00:0{i}+00:00",
                "type": "tool_result",
                "payload": {
                    "name": "run_exploit_terminal",
                    "success": False,
                    "result": f"TERMINAL_RESULT: BLOCKED\n{codes[i % len(codes)]}\ndenied {i}\nTOOL: run_exploit_terminal",
                },
            }
        )
    _write_jsonl(run_dir / "events.jsonl", events)
    resp = client.get(f"/api/v1/runs/{run_id}/sandbox", headers=_auth_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["blocked"]["total"] == 7, "event-derived blocks count when the audit log is absent"
    assert len(data["blocked"]["recent"]) == 5
    # The LAST five events are kept, in file order.
    assert data["blocked"]["recent"][0]["message"] == "denied 2"
    assert data["blocked"]["recent"][-1]["message"] == "denied 6"


def test_sandbox_endpoint_requires_auth(tmp_path, monkeypatch):
    client = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/runs/x/sandbox")
    assert resp.status_code in (401, 403)
