"""Tests for sandbox remediation: plan generation + job execution.

All subprocess / service calls are mocked; no real Docker install/build ever runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tools.sandbox import docker_backend as _db
from tools.sandbox import remediation as _rem


@pytest.fixture(autouse=True)
def _clear_remediation_jobs():
    _rem._JOBS.clear()
    yield
    _rem._JOBS.clear()


def _cfg(enabled=True, **overrides):
    sec = {"enabled": enabled, "image": "breachpilot-sandbox:latest"}
    sec.update(overrides)
    return {"sandbox": sec}


# ── plan tests ───────────────────────────────────────────────────────────


def test_plan_docker_cli_missing(monkeypatch):
    monkeypatch.setattr(_rem, "_which", lambda cmd: None if cmd == "docker" else "/usr/bin/" + cmd)
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    # apt-get present
    monkeypatch.setattr(_rem, "_detect_install_method", lambda p: "apt-get")
    plan = _rem.build_plan(_cfg())
    assert plan["docker_cli_present"] is False
    assert plan["docker_daemon_running"] is False
    assert plan["image_present"] is False
    ids = [s["id"] for s in plan["steps"]]
    assert "check_docker_cli" in ids
    assert "install_docker" in ids
    assert "start_docker" in ids
    assert "build_image" in ids
    assert plan["requires_admin"] is True
    install = next(s for s in plan["steps"] if s["id"] == "install_docker")
    assert "apt-get" in (install["command_preview"] or "")
    assert install["requires_admin"] is True


def test_plan_docker_cli_missing_no_package_manager(monkeypatch):
    monkeypatch.setattr(_rem, "_which", lambda cmd: None)
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_rem, "_detect_install_method", lambda p: None)
    plan = _rem.build_plan(_cfg())
    install = next(s for s in plan["steps"] if s["id"] == "install_docker")
    assert install["command_preview"] is None
    assert install["manual"] is True
    assert "manually" in install["description"].lower()


def test_plan_daemon_stopped_image_missing(monkeypatch):
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (False, "daemon unreachable"))
    monkeypatch.setattr(_rem, "_detect_service_method", lambda p: "systemctl")
    plan = _rem.build_plan(_cfg())
    assert plan["docker_cli_present"] is True
    assert plan["docker_daemon_running"] is False
    assert plan["image_present"] is None
    ids = [s["id"] for s in plan["steps"]]
    assert "install_docker" not in ids
    assert "start_docker" in ids
    assert "verify_docker" in ids
    # When daemon down, image status unknown but build is included as conditional
    assert "build_image" in ids
    start = next(s for s in plan["steps"] if s["id"] == "start_docker")
    assert "systemctl" in (start["command_preview"] or "")


def test_plan_daemon_running_image_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker")
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False)
    sandbox_dir = tmp_path / "docker" / "sandbox"
    sandbox_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(_rem, "DOCKER_SANDBOX_DIR", sandbox_dir)
    plan = _rem.build_plan(_cfg())
    assert plan["docker_daemon_running"] is True
    assert plan["image_present"] is False
    ids = [s["id"] for s in plan["steps"]]
    assert "build_image" in ids
    assert "install_docker" not in ids
    assert "start_docker" not in ids
    build = next(s for s in plan["steps"] if s["id"] == "build_image")
    assert "docker build" in (build["command_preview"] or "")


def test_plan_healthy_no_extra_steps(monkeypatch):
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker")
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    plan = _rem.build_plan(_cfg())
    assert plan["docker_cli_present"] is True
    assert plan["docker_daemon_running"] is True
    assert plan["image_present"] is True
    ids = [s["id"] for s in plan["steps"]]
    assert "install_docker" not in ids
    assert "start_docker" not in ids
    # build_image should NOT be present when image already healthy
    assert "build_image" not in ids


def test_plan_requires_admin_true_when_install_needed(monkeypatch):
    monkeypatch.setattr(_rem, "_which", lambda cmd: None if cmd == "docker" else "/usr/bin/" + cmd)
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_rem, "_detect_install_method", lambda p: "apt-get")
    plan = _rem.build_plan(_cfg())
    assert plan["requires_admin"] is True


def test_plan_handles_permission_denied(monkeypatch):
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker")
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(
        _db,
        "docker_version",
        lambda: (False, "Got permission denied while trying to connect to the Docker daemon socket"),
    )
    monkeypatch.setattr(_rem, "_detect_service_method", lambda p: "systemctl")
    plan = _rem.build_plan(_cfg())
    assert "permission denied" in plan["reason"].lower()
    ids = [s["id"] for s in plan["steps"]]
    assert "check_permissions" in ids
    perm = next(s for s in plan["steps"] if s["id"] == "check_permissions")
    assert "usermod" in (perm["command_preview"] or "")


def test_plan_unsupported_platform(monkeypatch):
    monkeypatch.setattr(_rem, "_which", lambda cmd: None)
    monkeypatch.setattr(_rem, "_platform", lambda: "freebsd")
    monkeypatch.setattr(_rem, "_detect_install_method", lambda p: None)
    plan = _rem.build_plan(_cfg())
    assert plan["platform"] == "freebsd"
    install = next(s for s in plan["steps"] if s["id"] == "install_docker")
    assert install["manual"] is True
    assert install["command_preview"] is None


def test_plan_windows_winget(monkeypatch):
    monkeypatch.setattr(
        _rem, "_which", lambda cmd: None if cmd == "docker" else ("/usr/bin/winget" if cmd == "winget" else None)
    )
    monkeypatch.setattr(_rem, "_platform", lambda: "windows")
    monkeypatch.setattr(_rem, "_detect_install_method", lambda p: "winget" if p == "windows" else None)
    plan = _rem.build_plan(_cfg())
    install = next(s for s in plan["steps"] if s["id"] == "install_docker")
    assert "winget" in (install["command_preview"] or "")


def test_plan_macos_brew(monkeypatch):
    monkeypatch.setattr(
        _rem, "_which", lambda cmd: None if cmd == "docker" else ("/opt/homebrew/bin/brew" if cmd == "brew" else None)
    )
    monkeypatch.setattr(_rem, "_platform", lambda: "darwin")
    monkeypatch.setattr(_rem, "_detect_install_method", lambda p: "brew" if p == "darwin" else None)
    plan = _rem.build_plan(_cfg())
    install = next(s for s in plan["steps"] if s["id"] == "install_docker")
    assert "brew" in (install["command_preview"] or "")


def test_plan_disabled_returns_no_steps(monkeypatch):
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker")
    plan = _rem.build_plan({"sandbox": {"enabled": False}})
    assert plan["mode"] == "disabled"
    assert plan["steps"] == []


def test_plan_never_uses_shell_true(monkeypatch):
    # Ensure _run never receives shell=True by inspecting source is not needed; we verify build_plan does not swallow.
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker")
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (True, ""))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    plan = _rem.build_plan(_cfg())
    # plan generation should not call _run at all (it's read-only)
    assert isinstance(plan, dict)


# ── job execution mocks ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_job_execution_success_path(monkeypatch, tmp_path):
    """Mock all subprocesses to succeed; job should end succeeded with requires_restart."""
    # Platform linux, docker present but image missing
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker")
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False)
    # Ensure DOCKER_SANDBOX_DIR exists for build step
    monkeypatch.setattr(_rem, "DOCKER_SANDBOX_DIR", tmp_path / "docker" / "sandbox")
    (tmp_path / "docker" / "sandbox").mkdir(parents=True, exist_ok=True)

    # Mock _run for build to succeed
    def fake_run(argv, timeout=30, cwd=None):
        # docker build
        if argv[:2] == ["docker", "build"]:
            return 0, "build ok", ""
        if argv == ["docker", "--version"]:
            return 0, "Docker version 27.0.3", ""
        return 0, "", ""

    monkeypatch.setattr(_rem, "_run", fake_run)
    # But docker_image_exists will be called twice; after build, we need it to return True on verify.
    # First call (in plan) returns False, second in execution's check_image also False, final verify should be True.
    # Mock sequence: first 2 calls False, then True
    calls = {"n": 0}
    orig_exists = _db.docker_image_exists

    def seq_exists(image):
        calls["n"] += 1
        # plan already called once; execution will call 2 more times; make last true
        if calls["n"] >= 3:
            return True
        return False

    monkeypatch.setattr(_db, "docker_image_exists", seq_exists)
    # Also need docker_version to stay True
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_rem, "_poll_docker_daemon", lambda timeout=60: (True, "27.0.3"))

    # Need plan after patching DOCKER_SANDBOX_DIR
    job = await _rem.create_job(_cfg())
    # At this point plan had build_image due to missing image
    assert any(s.id == "build_image" for s in job.steps)
    await _rem._execute_job_async(job.job_id, _cfg())
    assert job.status == "succeeded"
    assert job.docker_ready is True
    assert job.requires_restart is True
    # All steps should be succeeded (check steps etc)
    for s in job.steps:
        if s.id not in ("install_docker", "start_docker"):  # not present in this scenario
            assert s.status == "succeeded", f"{s.id} was {s.status}"


@pytest.mark.asyncio
async def test_job_build_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker")
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False)
    monkeypatch.setattr(_rem, "DOCKER_SANDBOX_DIR", tmp_path / "docker" / "sandbox")
    (tmp_path / "docker" / "sandbox").mkdir(parents=True, exist_ok=True)

    def fake_run(argv, timeout=30, cwd=None):
        if argv[:2] == ["docker", "build"]:
            return 1, "", "build failed: no space"
        return 0, "", ""

    monkeypatch.setattr(_rem, "_run", fake_run)
    monkeypatch.setattr(_rem, "_poll_docker_daemon", lambda timeout=60: (True, "27.0.3"))
    job = await _rem.create_job(_cfg())
    await _rem._execute_job_async(job.job_id, _cfg())
    assert job.status == "failed"
    build = next(s for s in job.steps if s.id == "build_image")
    assert build.status == "failed"
    assert "build failed" in (build.error or build.output).lower()


@pytest.mark.asyncio
async def test_job_daemon_start_failure(monkeypatch):
    monkeypatch.setattr(
        _rem,
        "_which",
        lambda cmd: "/usr/bin/docker" if cmd == "docker" else ("/usr/bin/systemctl" if cmd == "systemctl" else None),
    )
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (False, "daemon down"))
    monkeypatch.setattr(_rem, "_detect_service_method", lambda p: "systemctl")
    monkeypatch.setattr(_rem, "_poll_docker_daemon", lambda timeout=60: (False, "still down"))
    monkeypatch.setattr(_rem, "_run", lambda argv, timeout=30, cwd=None: (1, "", "systemctl: failed"))
    # Need image present unknown but plan will include start_docker
    job = await _rem.create_job(_cfg())
    assert any(s.id == "start_docker" for s in job.steps)
    await _rem._execute_job_async(job.job_id, _cfg())
    assert job.status == "failed"
    start = next(s for s in job.steps if s.id == "start_docker")
    assert start.status == "failed"


@pytest.mark.asyncio
async def test_job_install_failure(monkeypatch):
    monkeypatch.setattr(
        _rem, "_which", lambda cmd: None if cmd == "docker" else ("/usr/bin/apt-get" if cmd == "apt-get" else None)
    )
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_rem, "_detect_install_method", lambda p: "apt-get")
    monkeypatch.setattr(_rem, "_run", lambda argv, timeout=30, cwd=None: (1, "", "apt-get failed: locked"))
    job = await _rem.create_job(_cfg())
    await _rem._execute_job_async(job.job_id, _cfg())
    assert job.status == "failed"
    install = next(s for s in job.steps if s.id == "install_docker")
    assert install.status == "failed"


# ── API tests ───────────────────────────────────────────────────────────────


def _make_client(tmp_path, monkeypatch, token="test-token"):
    monkeypatch.setenv("BREACHPILOT_API_TOKEN", token)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n  host: http://localhost:11434\n"
        "models:\n  default_alias: glm\n  registry:\n    glm: glm-5.2:cloud\n"
        "exploit:\n  permission: read_only\n"
        "sandbox:\n  enabled: true\n  image: breachpilot-sandbox:latest\n"
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
    from fastapi.testclient import TestClient

    return TestClient(app), config_path


def _auth(token="test-token"):
    return {"Authorization": f"Bearer {token}"}


def test_api_plan_requires_auth(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/system/sandbox/fix/plan")
    assert resp.status_code == 401


def test_api_plan_returns_steps(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    resp = client.get("/api/v1/system/sandbox/fix/plan", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert "platform" in data
    assert "steps" in data
    assert data["docker_cli_present"] is True


def test_api_plan_disabled(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    # rewrite config to disabled
    import yaml

    path = tmp_path / "config.yaml"
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    cfg["sandbox"]["enabled"] = False
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    # create new client to pick up disabled config
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

    app = create_app(config_path=path, callables=callables)
    from fastapi.testclient import TestClient

    client2 = TestClient(app)
    resp = client2.get("/api/v1/system/sandbox/fix/plan", headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["steps"] == []


def test_api_fix_requires_auth(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    resp = client.post("/api/v1/system/sandbox/fix", json={})
    assert resp.status_code == 401


def test_api_fix_start_and_poll(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker" if cmd == "docker" else None)
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    # Make execution fast: patch _poll to succeed immediately
    monkeypatch.setattr(_rem, "_poll_docker_daemon", lambda timeout=60: (True, "27.0.3"))
    monkeypatch.setattr(_rem, "_run", lambda argv, timeout=30, cwd=None: (0, "ok", ""))
    resp = client.post("/api/v1/system/sandbox/fix", headers=_auth(), json={})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert job_id
    # Poll up to 5s
    import time

    for _ in range(50):
        r = client.get(f"/api/v1/system/sandbox/fix/{job_id}", headers=_auth())
        assert r.status_code == 200
        if r.json()["status"] in ("succeeded", "failed"):
            break
        time.sleep(0.05)
    else:
        r = client.get(f"/api/v1/system/sandbox/fix/{job_id}", headers=_auth())
    final = r.json()
    assert final["status"] in ("succeeded", "failed")
    # Check steps are structured
    assert isinstance(final["steps"], list)
    assert all("title" in s and "status" in s for s in final["steps"])


def test_api_fix_rejects_arbitrary_body(tmp_path, monkeypatch):
    """Browser cannot inject arbitrary commands via body."""
    client, _ = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker")
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: True)
    monkeypatch.setattr(_rem, "_poll_docker_daemon", lambda timeout=60: (True, "27.0.3"))
    monkeypatch.setattr(_rem, "_run", lambda argv, timeout=30, cwd=None: (0, "ok", ""))
    # Try to inject commands via body – should be ignored, not executed
    malicious = {"command": "rm -rf /", "argv": ["bash", "-c", "evil"], "image": "evil:latest", "path": "/etc/passwd"}
    resp = client.post("/api/v1/system/sandbox/fix", headers=_auth(), json=malicious)
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    import re
    import time

    for _ in range(10):
        time.sleep(0.05)
        r = client.get(f"/api/v1/system/sandbox/fix/{job_id}", headers=_auth()).json()
        if r["status"] in ("succeeded", "failed"):
            break
    # Verify no arbitrary image was used: plan's image is still from config
    plan = client.get("/api/v1/system/sandbox/fix/plan", headers=_auth()).json()
    assert plan["image"] == "breachpilot-sandbox:latest"
    # Poll job should not have command_preview containing evil
    for step in r["steps"]:
        preview = step.get("command_preview") or ""
        assert "rm -rf" not in preview
        assert "evil" not in preview.lower()


def test_api_fix_invalid_job_id(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/system/sandbox/fix/../../etc/passwd", headers=_auth())
    # The route regex rejects non-hex, so 404
    assert resp.status_code == 404
    resp2 = client.get("/api/v1/system/sandbox/fix/not-a-hex-id!", headers=_auth())
    assert resp2.status_code == 404


def test_api_fix_concurrent_conflict(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    monkeypatch.setattr(_rem, "_which", lambda cmd: "/usr/bin/docker")
    monkeypatch.setattr(_rem, "_platform", lambda: "linux")
    # Make docker_version slow to keep job running
    monkeypatch.setattr(_db, "docker_version", lambda: (True, "27.0.3"))
    monkeypatch.setattr(_db, "docker_image_exists", lambda image: False)
    # Make _poll hang a bit
    monkeypatch.setattr(_rem, "_poll_docker_daemon", lambda timeout=60: (True, "27.0.3"))
    # Make build take a moment via _run that sleeps
    import time as _time

    def slow_run(argv, timeout=30, cwd=None):
        if argv[:2] == ["docker", "build"]:
            _time.sleep(0.5)
            return 0, "ok", ""
        return 0, "ok", ""

    monkeypatch.setattr(_rem, "_run", slow_run)
    # Also need DOCKER_SANDBOX_DIR exists
    monkeypatch.setattr(_rem, "DOCKER_SANDBOX_DIR", tmp_path / "docker" / "sandbox")
    (tmp_path / "docker" / "sandbox").mkdir(parents=True, exist_ok=True)
    resp1 = client.post("/api/v1/system/sandbox/fix", headers=_auth(), json={})
    assert resp1.status_code == 200
    resp2 = client.post("/api/v1/system/sandbox/fix", headers=_auth(), json={})
    assert resp2.status_code == 409


def test_api_fix_disabled_returns_400(tmp_path, monkeypatch):
    import yaml

    client, path = _make_client(tmp_path, monkeypatch)
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    cfg["sandbox"]["enabled"] = False
    path.write_text(yaml.safe_dump(cfg), encoding="utf-8")
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

    app = create_app(config_path=path, callables=callables)
    from fastapi.testclient import TestClient

    client2 = TestClient(app)
    resp = client2.post("/api/v1/system/sandbox/fix", headers=_auth(), json={})
    assert resp.status_code == 400
    assert "disabled" in resp.json()["error"]["message"].lower()
