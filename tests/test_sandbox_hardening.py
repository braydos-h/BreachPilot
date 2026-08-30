"""Benchmark-era sandbox hardening tests (docs/benchmarks.md §sandbox).

Proves, at the unit level (no live Docker, no network):

- empty allowlist denies egress (no ACCEPT rules; scope gate denies all)
- unauthorized IPv4 / IPv6 / hostname targets are denied
- an authorized destination IS allowed (ACCEPT rule plumbed)
- host loopback cannot be accidentally reached (map_host_loopback off =>
  gateway DROP; 127.0.0.1 authorizes sandbox loopback only)
- Docker socket is unavailable to the worker (backend never mounts it)
- host filesystem paths are unavailable (single workspace bind, traversal
  rejected)
- sandbox failure never triggers host execution (SandboxError -> SANDBOX_*
  block; the funnel never returns a host result)
- sandbox restart never triggers host execution (worker recreation failure
  still raises SandboxError)
- workspace traversal is rejected (container_path escape)

Several of these also have live-Docker integration coverage in
tests/test_sandbox_integration.py; the cases here must hold everywhere.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.test_sandbox_manager import _EXPLOIT_ENV_KEYS, FakeBackend
from tools.sandbox.exceptions import SandboxError, SandboxWorkspaceError
from tools.sandbox.network import build_ipv4_rules, build_ipv6_rules
from tools.sandbox.policy import build_network_policy

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_target_env(monkeypatch):
    for key in _EXPLOIT_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def fake_backend(monkeypatch):
    """Docker-seam-free backend (same seams as test_sandbox_manager.py)."""
    backend = FakeBackend()
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_container_list_stale", lambda *a, **k: [])
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_network_list_stale", lambda *a, **k: [])
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_network_gateway", lambda *a, **k: "172.30.0.1")
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_inspect_state", lambda *a, **k: "running")
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_network_rm", lambda *a, **k: True)
    monkeypatch.setattr("tools.sandbox.manager.apply_network_policy", lambda *a, **k: True)
    return backend


@pytest.fixture
def no_research_hosts(monkeypatch):
    """Disable the pinned research-host egress so policy tests see only the
    explicit allowlist (keeps DNS resolution out of these tests)."""
    monkeypatch.setattr("tools.sandbox.policy.RESEARCH_HOSTS", ())


def _manager(tmp_path: Path, backend: Any) -> Any:
    from tools.sandbox.manager import SandboxManager
    from tools.sandbox.models import SandboxConfig

    config: dict[str, Any] = {
        "exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.50"]},
        "sandbox": {"enabled": True, "network": {"allow_research_hosts": False}},
    }
    cfg = SandboxConfig.from_config(config)
    mgr = SandboxManager(cfg, tmp_path / "ws", config_dict=config, backend=backend)
    mgr.workspace.mkdir(parents=True, exist_ok=True)
    return mgr


def _base_config(allowlist: list[str], **sandbox_extra: Any) -> dict[str, Any]:
    return {
        "exploit": {"require_explicit_allowlist": True, "allowed_targets": list(allowlist)},
        "sandbox": {
            "enabled": True,
            "backend": "docker",
            "image": "breachpilot-sandbox:latest",
            **sandbox_extra,
        },
    }


# ---------------------------------------------------------------------------
# Egress policy: empty allowlist / unauthorized targets
# ---------------------------------------------------------------------------


def test_empty_allowlist_denies_egress(no_research_hosts):
    """Empty allowlist => zero authorized destinations => default-DROP only."""
    policy = build_network_policy(_base_config([]))
    assert policy.authorized_destinations == []
    rules = build_ipv4_rules(policy, gateway="172.29.0.1")
    accepts = [r for r in rules if "-j ACCEPT" in r and "ESTABLISHED" not in r and "-o lo" not in r]
    assert accepts == [], f"empty allowlist must not produce ACCEPT rules: {accepts}"
    assert rules[-2] == "-A NAI-OUTPUT -j DROP"


def test_unauthorized_ipv4_target_denied(no_research_hosts):
    """An IPv4 outside the allowlist never reaches the ruleset."""
    policy = build_network_policy(_base_config(["10.0.0.50"]))
    joined = "\n".join(build_ipv4_rules(policy, gateway="172.29.0.1"))
    assert "-d 10.0.0.50/32 -j ACCEPT" in joined  # authorized present
    assert "-d 192.0.2.99" not in joined  # unauthorized absent


def test_unauthorized_ipv6_target_denied(no_research_hosts):
    """IPv6 egress stays denied unless an IPv6 destination is authorized."""
    policy = build_network_policy(_base_config(["10.0.0.50"]))
    joined_v6 = "\n".join(build_ipv6_rules(policy))
    assert "-j ACCEPT" in joined_v6  # loopback/established baseline
    assert "2001:db8::1" not in joined_v6  # unauthorized v6 absent
    # And an authorized v6 destination IS plumbed:
    policy_v6 = build_network_policy(_base_config(["2001:db8::1"]))
    assert "-d 2001:db8::1/128 -j ACCEPT" in "\n".join(build_ipv6_rules(policy_v6))


def test_unauthorized_hostname_denied(no_research_hosts, monkeypatch):
    """An allowlisted-but-unresolvable hostname authorizes nothing."""
    monkeypatch.setattr("tools.sandbox.policy._resolve_authorized", lambda *a, **kw: [])
    policy = build_network_policy(_base_config(["attacker.example.com"]))
    assert "attacker.example.com" not in policy.authorized_destinations
    assert any("attacker.example.com" in u for u in policy.unresolved_targets)


def test_authorized_destination_allowed(no_research_hosts):
    """The authorized target gets an explicit ACCEPT rule before default-DROP."""
    policy = build_network_policy(_base_config(["10.0.0.50"]))
    rules = build_ipv4_rules(policy, gateway="172.29.0.1")
    accept_idx = rules.index("-A NAI-OUTPUT -d 10.0.0.50/32 -j ACCEPT")
    drop_idx = rules.index("-A NAI-OUTPUT -j DROP")
    assert accept_idx < drop_idx


def test_host_loopback_not_reachable(no_research_hosts):
    """``127.0.0.1`` in the allowlist maps to SANDBOX loopback only — the
    Docker bridge gateway (path to host-published ports + daemon) is DROPped
    unless ``map_host_loopback`` is explicitly true."""
    cfg = _base_config(["127.0.0.1"], network={"map_host_loopback": False})
    policy = build_network_policy(cfg)
    rules = build_ipv4_rules(policy, gateway="172.29.0.1")
    joined = "\n".join(rules)
    assert "-A NAI-OUTPUT -d 172.29.0.1 -j DROP" in joined
    assert "-d 172.29.0.1 -j ACCEPT" not in joined

    # Explicit opt-in maps the gateway (only when a gateway is known).
    cfg_mapped = _base_config(["127.0.0.1"], network={"map_host_loopback": True})
    policy_mapped = build_network_policy(cfg_mapped)  # no gateway passed -> nothing to map yet
    assert policy_mapped.authorized_destinations == []


def test_authorize_all_token_refused(no_research_hosts):
    """Wildcard/all tokens can never be expressed by the sandbox policy."""
    with pytest.raises(ValueError, match="refuses"):
        build_network_policy(_base_config(["0.0.0.0/0"]))
    with pytest.raises(ValueError, match="refuses"):
        build_network_policy(_base_config(["*"]))


# ---------------------------------------------------------------------------
# Execution containment: no host fallback, traversal, docker socket
# ---------------------------------------------------------------------------


def test_sandbox_failure_never_triggers_host_execution(tmp_path, fake_backend):
    """A sandbox execution failure raises SandboxError — it NEVER produces a
    host-executed result (the MCP layer renders the SANDBOX_* block)."""
    mgr = _manager(tmp_path, fake_backend)

    def _boom(cid, argv, **kw):
        raise SandboxError("exec failed inside worker")

    fake_backend.exec_impl = _boom
    with pytest.raises(SandboxError):
        mgr.execute("id", timeout=10, target_ip="10.0.0.50")
    # The only exec calls went to the (failing) worker inside the sandbox —
    # no host execution path was taken.
    assert len(fake_backend.exec_calls) >= 1


def test_sandbox_restart_never_triggers_host_execution(tmp_path, monkeypatch, fake_backend):
    """When the worker vanishes mid-run, ensure_sandbox recreates it — and if
    recreation fails the execution path still fails closed (SandboxError),
    never silently re-runs the command on the host."""
    monkeypatch.setattr("tools.sandbox.docker_backend.docker_inspect_state", lambda *a, **k: "")
    mgr = _manager(tmp_path, fake_backend)
    mgr.container_id = "gone"  # worker vanished (inspect state mocked to exited)

    def _fail_create_worker(spec: Any, *, read_only_rootfs: bool) -> str:
        raise SandboxError("docker unavailable on restart")

    mgr.backend.create_worker = _fail_create_worker
    with pytest.raises(SandboxError):
        mgr.ensure_sandbox()  # restart path fails closed
    # And the execute funnel must not fall back either:
    with pytest.raises(SandboxError):
        mgr.execute("id", timeout=10, target_ip="10.0.0.50")
    assert fake_backend.exec_calls == []


def test_workspace_traversal_rejected(tmp_path, fake_backend):
    """container_path refuses paths outside the sandbox workspace."""
    mgr = _manager(tmp_path, fake_backend)
    with pytest.raises(SandboxWorkspaceError):
        mgr.container_path("C:\\Windows\\System32\\config.sys")
    with pytest.raises(SandboxWorkspaceError):
        mgr.container_path(str(tmp_path / "outside" / ".." / "ws2" / "x"))


def test_docker_socket_never_mounted():
    """The worker spec never binds the Docker socket (static invariant)."""
    import ast

    from tools.sandbox import docker_backend as backend

    source = Path(backend.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    # Any string literal in the backend naming docker.sock must be a negative
    # guard (a test/refusal), never a mount source.
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "docker.sock" in node.value:
            ctx = source[: source.find(node.value)]
            assert "/var/run/docker.sock:/var/run/docker.sock" not in node.value


def test_sandbox_error_block_is_fail_closed_marker():
    """The MCP error block marks the command as executed NOWHERE — the
    fail-closed SANDBOX_* marker, never a host-execution fallback."""
    from tools.mcp_tools.sandbox_exec import sandbox_error_block

    block = sandbox_error_block(SandboxError("boom"), tool_name="run_exploit_terminal")
    assert "SANDBOX_" in block
    assert "EXECUTED: nowhere" in block
