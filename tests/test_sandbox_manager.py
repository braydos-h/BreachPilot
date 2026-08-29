"""Unit tests for SandboxManager (tools/sandbox/manager.py).

Security invariants covered:
- Disabled config resolves to None (explicit legacy host mode, never silent).
- ``require_explicit_allowlist`` + EMPTY allowlist => DENY target-touching
  execution (the empty-allowlist fail-open regression).
- Unauthorized target => SandboxScopeError before any container work.
- Sandbox/policy failure => SandboxError (fail closed; no host fallback).
- Environment is allowlisted (never a host-env copy).
- Output is size-clamped; timeouts surface as timed_out results.
- Workspace mapping blocks traversal/escape; destroy is idempotent.
- Stale cleanup touches only exited NetAttackAI-labeled resources.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.sandbox.exceptions import (
    SandboxError,
    SandboxScopeError,
    SandboxUnavailableError,
    SandboxWorkspaceError,
)
from tools.sandbox.manager import CONTAINER_WORKSPACE, SandboxManager, resolve_manager

_EXPLOIT_ENV_KEYS = ("EXPLOIT_TARGET", "EXPLOIT_TARGET_IP", "EXPLOIT_TARGET_DOMAIN", "EXPLOIT_DISCOVERED_TARGETS", "EXPLOIT_ALLOWED_TARGETS")


class FakeBackend:
    """Records lifecycle calls; never touches Docker."""

    def __init__(self) -> None:
        self.exec_calls: list[dict[str, Any]] = []
        self.destroy_results = {"container_removed": True, "network_removed": True}
        self.exec_impl: Any = None

    def ensure_docker(self) -> None:
        pass

    def ensure_image(self, image: str) -> None:
        pass

    def create_network(self, name: str) -> str:
        return name

    def create_worker(self, spec: Any, *, read_only_rootfs: bool) -> str:
        return spec.sandbox_id

    def exec(self, cid: str, argv: list[str], *, timeout: int, user: str = "", env=None, input_text: str = "", workdir: str = ""):
        self.exec_calls.append({"cid": cid, "argv": argv, "env": dict(env or {}), "user": user, "workdir": workdir})
        if self.exec_impl is not None:
            return self.exec_impl(cid, argv)
        return 0, "out", "err"

    def stop(self, cid: str) -> None:
        pass

    def destroy(self, cid: str, network: str) -> dict[str, bool]:
        return dict(self.destroy_results)


@pytest.fixture(autouse=True)
def _clear_target_env(monkeypatch):
    for key in _EXPLOIT_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def fake_backend(monkeypatch):
    backend = FakeBackend()
    # Stale-cleanup probes: no labeled resources exist.
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_container_list_stale", lambda *a, **k: [])
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_network_list_stale", lambda *a, **k: [])
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_network_gateway", lambda *a, **k: "172.30.0.1")
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_inspect_state", lambda *a, **k: "running")
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_network_rm", lambda *a, **k: True)
    # Policy install is a no-op (sidecar install is covered by network tests).
    monkeypatch.setattr("tools.sandbox.manager.apply_network_policy", lambda *a, **k: True)
    return backend


def _manager(tmp_path: Path, backend: FakeBackend, *, exploit: dict | None = None, sandbox: dict | None = None) -> SandboxManager:
    config: dict[str, Any] = {
        "exploit": exploit or {},
        "sandbox": {"enabled": True, "network": {"allow_research_hosts": False}, **(sandbox or {})},
    }
    mgr = resolve_manager_or_none(config, tmp_path, backend)
    assert mgr is not None
    mgr.workspace.mkdir(parents=True, exist_ok=True)
    return mgr


def resolve_manager_or_none(config: dict, tmp_path: Path, backend: Any = None) -> SandboxManager | None:
    # Local helper: build the manager against a tmp workspace with a fake backend
    # (audit rows land under tmp_path, never in the repo tree).
    from tools.sandbox.models import SandboxConfig

    cfg = SandboxConfig.from_config(config)
    if not cfg.enabled:
        return None
    return SandboxManager(cfg, tmp_path / "ws", config_dict=config, backend=backend)


class TestResolveManager:
    def test_missing_section_disables(self, tmp_path):
        assert resolve_manager(tmp_path, {}) is None

    def test_enabled_false_disables(self, tmp_path):
        assert resolve_manager(tmp_path, {"sandbox": {"enabled": False}}) is None

    def test_enabled_true_returns_manager(self, tmp_path):
        mgr = resolve_manager(tmp_path, {"sandbox": {"enabled": True}})
        assert mgr is not None
        assert mgr.cfg.image == "netattackai-sandbox:latest"
        mgr.destroy()


class TestExecutionFunnel:
    def test_execute_runs_inside_sandbox(self, tmp_path, fake_backend):
        mgr = _manager(tmp_path, fake_backend)
        result = mgr.execute("id", target_ip="192.0.2.5", tool_name="run_exploit_terminal")
        assert result.status == "completed"
        assert result.exit_code == 0
        assert fake_backend.exec_calls, "command must reach the sandbox backend"
        argv = fake_backend.exec_calls[0]["argv"]
        # The command is wrapped with timeout + bash inside the worker.
        assert argv[0] == "timeout"
        assert "id" in argv
        mgr.destroy()

    def test_unauthorized_target_denied_before_container_work(self, tmp_path, fake_backend):
        mgr = _manager(tmp_path, fake_backend, exploit={"require_explicit_allowlist": True, "allowed_targets": ["192.0.2.5"]})
        with pytest.raises(SandboxScopeError):
            mgr.execute("curl http://203.0.113.9", target_ip="203.0.113.9")
        assert not fake_backend.exec_calls, "denied execution must never reach the sandbox"

    def test_empty_allowlist_deny_all_target_touching(self, tmp_path, fake_backend):
        # THE empty-allowlist invariant: require_explicit_allowlist=true with an
        # empty effective allowlist denies ALL target-touching execution.
        mgr = _manager(tmp_path, fake_backend, exploit={"require_explicit_allowlist": True, "allowed_targets": []})
        with pytest.raises(SandboxScopeError, match="empty"):
            mgr.execute("nmap -sV 203.0.113.9", target_ip="203.0.113.9")
        assert not fake_backend.exec_calls

    def test_authorized_target_passes_scope(self, tmp_path, fake_backend):
        mgr = _manager(tmp_path, fake_backend, exploit={"require_explicit_allowlist": True, "allowed_targets": ["192.0.2.0/24"]})
        result = mgr.execute("id", target_ip="192.0.2.5")
        assert result.status == "completed"
        mgr.destroy()

    def test_research_hosts_exempt_from_target_allowlist(self, tmp_path, fake_backend):
        # Pinned research egress (github/gitlab) is authorized by the fixed set.
        mgr = _manager(
            tmp_path,
            fake_backend,
            exploit={"require_explicit_allowlist": True, "allowed_targets": []},
            sandbox={"network": {"allow_research_hosts": True}},
        )
        result = mgr.execute("git clone https://github.com/x/y", target_ip="github.com")
        assert result.status == "completed"
        mgr.destroy()

    def test_sandbox_failure_blocks_execution(self, tmp_path):
        class DeadBackend(FakeBackend):
            def ensure_docker(self) -> None:
                raise SandboxUnavailableError("daemon down")

        mgr = _manager(tmp_path, DeadBackend())
        with pytest.raises(SandboxError, match="daemon down"):
            mgr.execute("id")
        # No host fallback exists: there is no code path that ran the command.
        mgr.destroy()

    def test_timeout_surfaces_as_timed_out(self, tmp_path, fake_backend):
        def raise_timeout(cid, argv):
            raise TimeoutError("docker exec timed out")

        fake_backend.exec_impl = raise_timeout
        mgr = _manager(tmp_path, fake_backend)
        result = mgr.execute("sleep 999", timeout=5)
        assert result.status == "timed_out"
        assert result.timed_out is True
        assert result.exit_code is None
        mgr.destroy()

    def test_output_clamped_to_limit(self, tmp_path, fake_backend, monkeypatch):
        fake_backend.exec_impl = lambda cid, argv: (0, "A" * 50_000, "")
        mgr = _manager(tmp_path, fake_backend, sandbox={"resources": {"output_max_bytes": 2000}})
        result = mgr.execute("yes")
        assert len(result.stdout.encode()) <= 2500
        assert "truncated" in result.stdout
        mgr.destroy()


class TestEnvironmentAllowlist:
    def test_only_allowlisted_env_reaches_worker(self, tmp_path, fake_backend):
        mgr = _manager(tmp_path, fake_backend)
        mgr.execute(
            "env",
            env={"EXPLOIT_TARGET": "192.0.2.5", "SECRET_TOKEN": "hunter2", "PATH": "/evil"},
        )
        sent = fake_backend.exec_calls[0]["env"]
        assert sent.get("EXPLOIT_TARGET") == "192.0.2.5"
        assert "SECRET_TOKEN" not in sent
        assert "PATH" not in sent
        assert sent.get("EXPLOIT_SANDBOX") == "1"
        mgr.destroy()

    def test_env_passthrough_config_honored(self, tmp_path, fake_backend):
        mgr = _manager(tmp_path, fake_backend, sandbox={"env_passthrough": ["MY_TOOL_KEY"]})
        mgr.execute("env", env={"MY_TOOL_KEY": "value"})
        assert fake_backend.exec_calls[0]["env"].get("MY_TOOL_KEY") == "value"
        mgr.destroy()


class TestWorkspace:
    def test_container_path_maps_under_workspace(self, tmp_path):
        from tools.sandbox.models import SandboxConfig

        mgr = SandboxManager(SandboxConfig.from_config({"sandbox": {"enabled": True}}), tmp_path)
        assert mgr.container_path(tmp_path / "attempt1") == f"{CONTAINER_WORKSPACE}/attempt1"
        assert mgr.container_path(tmp_path) == CONTAINER_WORKSPACE

    def test_container_path_blocks_escape(self, tmp_path):
        from tools.sandbox.models import SandboxConfig

        mgr = SandboxManager(SandboxConfig.from_config({"sandbox": {"enabled": True}}), tmp_path)
        with pytest.raises(SandboxWorkspaceError):
            mgr.container_path(tmp_path.parent / "elsewhere")
        with pytest.raises(SandboxWorkspaceError):
            mgr.container_path(Path("C:/Windows"))

    def test_symlink_workspace_rejected(self, tmp_path, fake_backend, monkeypatch):
        mgr = _manager(tmp_path, fake_backend)
        mgr.workspace = mgr.workspace  # keep
        monkeypatch.setattr(
            "pathlib.Path.is_symlink", lambda self: True, raising=False
        )
        with pytest.raises(SandboxWorkspaceError, match="symlink"):
            mgr._validate_workspace()


class TestLifecycle:
    def test_destroy_idempotent_and_audited(self, tmp_path, fake_backend):
        mgr = _manager(tmp_path, fake_backend)
        mgr.execute("id", target_ip="192.0.2.5")
        r1 = mgr.destroy()
        assert r1["container_removed"] is True
        assert r1["network_removed"] is True
        r2 = mgr.destroy()
        assert r2 == {"container_removed": False, "network_removed": False}
        audit = tmp_path / "ws" / "exploit_audit.jsonl"
        assert audit.exists(), "cleanup must be audited"

    def test_cleanup_stale_only_touches_exited(self, tmp_path, fake_backend, monkeypatch):
        monkeypatch.setattr(
            "tools.sandbox.docker_backend.docker_container_list_stale", lambda *a, **k: ["old-a", "old-b"]
        )
        states = {"old-a": "exited", "old-b": "running"}
        monkeypatch.setattr("tools.sandbox.docker_backend.docker_inspect_state", lambda name, **k: states[name])
        removed: list[str] = []
        monkeypatch.setattr("tools.sandbox.docker_backend.docker_rm", lambda name, **k: removed.append(name) or True)
        monkeypatch.setattr("tools.sandbox.docker_backend.docker_network_list_stale", lambda *a, **k: [])
        mgr = _manager(tmp_path, fake_backend)
        assert mgr.cleanup_stale() == 1
        assert removed == ["old-a"], "RUNNING workers of concurrent sessions must be kept"
        mgr.destroy()

    def test_status_reports_network_lock(self, tmp_path, fake_backend):
        mgr = _manager(tmp_path, fake_backend)
        mgr.execute("id", target_ip="192.0.2.5")
        st = mgr.status()
        assert st["network_locked"] is True
        assert st["enabled"] is True
        assert st["resources"]["pids"] == 512
        mgr.destroy()


class TestAuditTrail:
    def test_execution_writes_sandbox_context(self, tmp_path, fake_backend):
        mgr = _manager(tmp_path, fake_backend, exploit={"allowed_targets": ["192.0.2.5"]})
        mgr.run_id = "auditrun1"
        mgr.execute("id", target_ip="192.0.2.5", tool_name="run_exploit_terminal")
        audit = tmp_path / "ws" / "exploit_audit.jsonl"
        rows = [json.loads(ln) for ln in audit.read_text(encoding="utf-8").splitlines() if ln.strip()]
        sandbox_rows = [r for r in rows if r.get("sandbox")]
        assert sandbox_rows, "sandbox executions must write sandbox-context audit rows"
        row = sandbox_rows[0]
        assert row["sandbox"]["run_id"] == "auditrun1"
        assert row["sandbox"]["image"] == "netattackai-sandbox:latest"
        assert row["sandbox"]["network"]["authorized_destinations"] == ["192.0.2.5/32"]
        assert row["sandbox"]["env_keys"] == sorted(row["sandbox"]["env_keys"])
        mgr.destroy()
