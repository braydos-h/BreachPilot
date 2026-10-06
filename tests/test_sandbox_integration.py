"""Docker-gated integration tests for the sandbox network boundary.

These tests run ONLY when the Docker daemon is reachable AND the sandbox
worker image exists (build it: ``docker build -t breachpilot-sandbox:latest
docker/sandbox``) — otherwise they skip cleanly so the mocked suite stays
hermetic and offline.

What they prove (things mocks cannot):

- The netns firewall is REAL: a command whose string contains no destination
  (``python3 egress.py``) still cannot reach an unauthorized IP.
- Obfuscated destinations (hex/decimal-encoded IPs unpacked at runtime) gain
  nothing — enforcement is at the network layer, not the parser.
- Metadata endpoints, arbitrary hostnames, /dev/tcp, and docker.sock access
  all fail inside the worker.
- The worker is non-root, has no docker.sock, cannot write outside
  /workspace (read-only rootfs), and carries the configured resource limits.
- A destroyed sandbox leaves no containers or networks behind.

Unauthorized destinations use a ready local helper on the worker bridge. A
peer helper first proves it reachable, so connection failure cannot be
explained by an absent service or Docker inter-network isolation.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
from typing import Any

import pytest

SANDBOX_IMAGE = "breachpilot-sandbox:latest"
REQUIRED_ENV = "BREACHPILOT_REQUIRE_SANDBOX_INTEGRATION"
METADATA_IP = "169.254.169.254"


def _docker(*args: str, timeout: int = 60) -> tuple[int, str, str]:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _daemon_ok() -> bool:
    try:
        rc, _out, _err = _docker("version", "--format", "{{.Server.Version}}", timeout=20)
        return rc == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _image_ok() -> bool:
    try:
        rc, _out, _err = _docker("image", "inspect", SANDBOX_IMAGE, timeout=20)
        return rc == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.integration


def _require_prerequisites() -> None:
    """Optional locally; the dedicated containment CI job must run, never skip."""
    if _daemon_ok() and _image_ok():
        return
    reason = f"sandbox integration requires Docker and {SANDBOX_IMAGE}; build docker/sandbox"
    if os.environ.get(REQUIRED_ENV) == "1":
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture(scope="module", autouse=True)
def integration_prerequisites() -> None:
    # Probe from a fixture, never during offline collection.
    _require_prerequisites()


def _target_ip_on(network: str, name: str) -> str:
    rc, out, err = _docker(
        "inspect",
        "-f",
        f'{{{{with index .NetworkSettings.Networks "{network}"}}}}{{{{.IPAddress}}}}{{{{end}}}}',
        name,
    )
    assert rc == 0 and out.strip(), f"helper has no IP on {network}: {err[:200]}"
    return out.strip()


def _ensure_target_container(name: str, network: str, *, alias: str = "") -> str:
    # Unique names and ownership recording in it_env avoid reusing user resources.
    argv = [
        "run",
        "-d",
        "--name",
        name,
        "--label",
        "breachpilot=true",
        "--network",
        network,
    ]
    if alias:
        argv += ["--network-alias", alias]
    argv += [SANDBOX_IMAGE, "python3", "-m", "http.server", "8090", "--bind", "0.0.0.0"]
    rc, _, err = _docker(*argv)
    assert rc == 0, f"cannot start integration helper on owned bridge: {err[:200]}"
    ip = _target_ip_on(network, name)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        rc, _, _ = _docker(
            "exec",
            name,
            "python3",
            "-c",
            "import socket;socket.create_connection(('127.0.0.1',8090),1).close()",
        )
        if rc == 0:
            return ip
        time.sleep(0.25)
    pytest.fail(f"integration helper {name} did not become ready on :8090")


def _verify_helper_reachable(source: str, destination: str) -> None:
    """Positive control: same-bridge path works before worker-only denial."""
    rc, _, err = _docker(
        "exec",
        source,
        "python3",
        "-c",
        f"import socket;socket.create_connection(('{destination}',8090),5).close()",
    )
    assert rc == 0, f"unauthorized helper is not reachable from its bridge peer: {err[:200]}"


@pytest.fixture(scope="module")
def it_env(tmp_path_factory) -> dict[str, Any]:
    """Own every partial resource through setup, execution and teardown."""
    from tools.sandbox import resolve_manager

    ws = tmp_path_factory.mktemp("sandbox_it") / "ws"
    ws.mkdir(parents=True)
    telemetry_path = ws.parent / "network-scope.json"
    suffix = secrets.token_hex(6)
    target_name = f"breachpilot-it-allowed-{suffix}"
    denied_name = f"breachpilot-it-denied-{suffix}"
    denied_alias = f"denied-{suffix}"
    mgr = None
    owned_helpers: list[str] = []
    with pytest.MonkeyPatch.context() as patch:
        for key in (
            "EXPLOIT_TARGET",
            "EXPLOIT_TARGET_IP",
            "EXPLOIT_TARGET_DOMAIN",
            "EXPLOIT_DISCOVERED_TARGETS",
            "EXPLOIT_ALLOWED_TARGETS",
        ):
            patch.delenv(key, raising=False)
        try:
            config: dict[str, Any] = {
                "exploit": {"allowed_targets": ["192.0.2.10"]},
                "sandbox": {
                    "enabled": True,
                    "image": SANDBOX_IMAGE,
                    "resources": {"memory_mb": 1024, "cpus": 1.0, "pids": 256, "timeout_seconds": 60},
                    "network": {"allow_research_hosts": False},
                },
            }
            mgr = resolve_manager(ws, config, network_telemetry_path=telemetry_path)
            assert mgr is not None
            result = mgr.execute("true", timeout=30)
            assert result.status == "completed"
            # Record attempted names before setup so even partial failures clean up.
            owned_helpers.append(target_name)
            target_ip = _ensure_target_container(target_name, mgr.network_name)
            owned_helpers.append(denied_name)
            denied_ip = _ensure_target_container(denied_name, mgr.network_name, alias=denied_alias)
            _verify_helper_reachable(target_name, denied_ip)
            mgr.config_dict["exploit"]["allowed_targets"] = [target_ip]
            # Initialization used a placeholder; install the final policy explicitly
            # rather than depending on the production policy-cache TTL.
            mgr._apply_policy(force=True)
            yield {
                "mgr": mgr,
                "target_ip": target_ip,
                "unauthorized_ip": denied_ip,
                "unauthorized_name": denied_alias,
                "ws": ws,
                "telemetry_path": telemetry_path,
            }
        finally:
            cleanup_errors = []
            try:
                for name in reversed(owned_helpers):
                    try:
                        rc, _, err = _docker("rm", "-f", name)
                        if rc != 0 and "No such container" not in err:
                            cleanup_errors.append(f"helper cleanup failed: {err[:200]}")
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        cleanup_errors.append(f"helper cleanup failed: {exc}")
            finally:
                if mgr is not None:
                    cleanup = mgr.destroy()
                    assert cleanup.get("container_removed") and cleanup.get("network_removed"), cleanup
                    from tools.sandbox.telemetry import read_network_scope_measurement

                    assert isinstance(read_network_scope_measurement(telemetry_path), int), (
                        "Docker integration must produce a complete host-side per-run counter"
                    )
            assert not cleanup_errors, cleanup_errors


def _run(it_env: dict, command: str, timeout: int = 40) -> Any:
    # Firewall tests run with the AUTHORIZED target_ip so the scope gate
    # passes and the netns firewall is what decides (BLOCKED vs REACH_OK).
    # Scope-gate behavior (empty target, unlisted target) is pinned by the
    # mocked unit tests (test_sandbox_manager / test_sandbox_mcp_exec), not
    # here -- direct manager.execute only checks this single target_ip, so
    # hidden destinations (egress.py) still reach the firewall.
    return it_env["mgr"].execute(command, timeout=timeout, target_ip=it_env["target_ip"])


class TestNetworkBoundary:
    def test_packet_socket_capability_is_unavailable(self, it_env):
        result = _run(
            it_env,
            'python3 -c "import socket\n'
            "try:\n  socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))\n"
            "  print('RAW_SOCKET_ALLOWED')\n"
            "except PermissionError:\n  print('RAW_SOCKET_BLOCKED')\"",
        )
        assert "RAW_SOCKET_BLOCKED" in result.stdout
        assert "RAW_SOCKET_ALLOWED" not in result.stdout

    def test_allowed_target_reachable(self, it_env):
        ip = it_env["target_ip"]
        result = _run(
            it_env, f"python3 -c \"import socket;s=socket.create_connection(('{ip}',8090),5);print('REACH_OK')\""
        )
        assert result.exit_code == 0
        assert "REACH_OK" in result.stdout

    def test_unauthorized_ip_blocked(self, it_env):
        result = _run(
            it_env,
            f"python3 -c \"import socket\ntry:\n  socket.create_connection(('{it_env['unauthorized_ip']}',8090),3)\n  print('LEAK')\nexcept Exception as e:\n  print('BLOCKED', type(e).__name__)\"",
        )
        assert "LEAK" not in result.stdout
        assert "BLOCKED" in result.stdout

    def test_blocked_packet_counter_survives_policy_refresh(self, it_env):
        mgr = it_env["mgr"]
        before = mgr.read_network_scope_drop_count()
        assert isinstance(before, int), "trusted sidecar must read both firewall-family counters"

        _run(
            it_env,
            f"python3 -c \"import socket\ntry:\n  socket.create_connection(('{it_env['unauthorized_ip']}',8090),2)\n"
            'except OSError:\n  pass"',
        )
        after_first_drop = mgr.read_network_scope_drop_count()
        assert isinstance(after_first_drop, int) and after_first_drop > before

        # A forced allowlist refresh flushes only NAI-OUTPUT. NAI-DROP lives
        # outside that chain, so the cumulative counter must remain monotonic.
        mgr._apply_policy(force=True)
        after_refresh = mgr.read_network_scope_drop_count()
        assert after_refresh == after_first_drop

        _run(
            it_env,
            f"python3 -c \"import socket\ntry:\n  socket.create_connection(('{it_env['unauthorized_ip']}',8090),2)\n"
            'except OSError:\n  pass"',
        )
        after_second_drop = mgr.read_network_scope_drop_count()
        assert isinstance(after_second_drop, int) and after_second_drop > after_refresh

    def test_destinationless_script_blocked(self, it_env):
        # THE critical case: the command string contains NO destination — the
        # application-layer parser cannot see one — yet the network layer
        # still blocks the egress attempt.
        script = (
            "import socket\n"
            f"try:\n    socket.create_connection(('{it_env['unauthorized_ip']}', 8090), 3)\n"
            "    print('LEAK')\n"
            "except Exception as exc:\n"
            "    print('BLOCKED', type(exc).__name__)\n"
        )
        (it_env["ws"] / "egress.py").write_text(script, encoding="utf-8")
        result = _run(it_env, "python3 /workspace/egress.py")
        assert "LEAK" not in result.stdout
        assert "BLOCKED" in result.stdout

    def test_obfuscated_destination_blocked(self, it_env):
        # Encode the reachable denied helper address; decode only in the worker.
        octets = [f"{int(part):02x}" for part in it_env["unauthorized_ip"].split(".")]
        result = _run(
            it_env,
            f"python3 -c \"import socket;ip='.'.join(str(int(x,16)) for x in {octets!r})\n"
            "try:\n  socket.create_connection((ip,8090),3)\n  print('LEAK')\nexcept Exception as e:\n  print('BLOCKED', type(e).__name__)\"",
        )
        assert "LEAK" not in result.stdout
        assert "BLOCKED" in result.stdout

    def test_unauthorized_hostname_blocked(self, it_env):
        # The local Docker alias refers to the ready denied helper. DNS is
        # independently denied for this IP-only mission; no external host is used.
        result = _run(
            it_env,
            f"curl --max-time 8 -sS -o /dev/null -w '%{{http_code}}' http://{it_env['unauthorized_name']}:8090/ || echo CURL_BLOCKED",
        )
        assert "CURL_BLOCKED" in result.stdout or "000" in result.stdout
        assert "200" not in result.stdout

    def test_dev_tcp_blocked(self, it_env):
        result = _run(
            it_env, f"timeout 8 bash -c 'echo > /dev/tcp/{it_env['unauthorized_ip']}/8090' && echo LEAK || echo BLOCKED"
        )
        assert "LEAK" not in result.stdout
        assert "BLOCKED" in result.stdout

    def test_metadata_endpoint_blocked(self, it_env):
        result = _run(
            it_env,
            f"python3 -c \"import socket\ntry:\n  socket.create_connection(('{METADATA_IP}',80),3)\n  print('LEAK')\nexcept Exception as e:\n  print('BLOCKED', type(e).__name__)\"",
        )
        assert "LEAK" not in result.stdout
        assert "BLOCKED" in result.stdout


class TestHostProtection:
    def test_no_docker_socket(self, it_env):
        result = _run(it_env, "test -S /var/run/docker.sock && echo DOCKER_SOCK || echo CLEAN")
        assert "DOCKER_SOCK" not in result.stdout
        assert "CLEAN" in result.stdout

    def test_default_user_is_non_root(self, it_env):
        result = _run(it_env, "id -u")
        assert result.exit_code == 0
        assert result.stdout.strip() != "0"

    def test_host_root_not_mounted(self, it_env):
        result = _run(it_env, "test -d /host_root -o -d /host && echo HOST_MOUNT || echo CLEAN")
        assert "HOST_MOUNT" not in result.stdout
        assert "CLEAN" in result.stdout

    def test_rootfs_read_only_outside_workspace(self, it_env):
        # /workspace is the ONLY writable persistent path; system dirs are not.
        result = _run(
            it_env,
            "touch /workspace/ok.txt && echo WS_OK; touch /etc/nai-ro-test 2>/dev/null && echo ROOT_WRITABLE || echo ROOT_RO",
        )
        assert "WS_OK" in result.stdout
        assert "ROOT_WRITABLE" not in result.stdout
        assert "ROOT_RO" in result.stdout

    def test_resource_limits_applied(self, it_env):
        mgr = it_env["mgr"]
        rc, out, err = _docker("inspect", mgr.container_id)
        assert rc == 0, err[:200]
        data = json.loads(out)[0]
        hc = data["HostConfig"]
        assert hc["Memory"] == 1024 * 1024 * 1024
        assert int(hc["PidsLimit"]) == 256
        assert hc["Privileged"] is False
        assert hc["ReadonlyRootfs"] is True
        assert "NET_ADMIN" not in (hc.get("CapAdd") or [])
        assert "ALL" in (hc.get("CapDrop") or [])
        assert not (hc.get("Binds") or []) or all("docker.sock" not in b for b in hc["Binds"])


class TestCleanup:
    def test_destroy_removes_container_and_network(self, tmp_path):
        from tools.sandbox import resolve_manager

        ws = tmp_path / "ws"
        ws.mkdir()
        config: dict[str, Any] = {
            "exploit": {"allowed_targets": ["192.0.2.10"]},
            "sandbox": {
                "enabled": True,
                "image": SANDBOX_IMAGE,
                "resources": {"memory_mb": 1024, "cpus": 1.0, "pids": 256, "timeout_seconds": 60},
                "network": {"allow_research_hosts": False},
            },
        }
        mgr = resolve_manager(ws, config)
        assert mgr is not None
        result = mgr.execute("true", timeout=60)
        assert result.status == "completed"
        cid, network = mgr.container_id, mgr.network_name
        assert cid and network
        results = mgr.destroy()
        assert results["container_removed"] is True
        assert results["network_removed"] is True
        rc, _out, _e = _docker("inspect", cid)
        assert rc != 0, "worker container must be gone after destroy"
        rc, _o2, _e2 = _docker("network", "inspect", network)
        assert rc != 0, "worker network must be gone after destroy"

    def test_no_stale_labeled_resources_after_module(self, tmp_path):
        # Function-scope manager, destroyed via yield-finally: assert AFTER
        # destroy (the module it_env worker is still alive at this point, so
        # asserting against the module run_id would always fail).
        from tools.sandbox import resolve_manager

        ws = tmp_path / "ws_stale"
        ws.mkdir()
        config: dict[str, Any] = {
            "exploit": {"allowed_targets": ["192.0.2.10"]},
            "sandbox": {
                "enabled": True,
                "image": SANDBOX_IMAGE,
                "resources": {"memory_mb": 1024, "cpus": 1.0, "pids": 256, "timeout_seconds": 60},
                "network": {"allow_research_hosts": False},
            },
        }
        mgr = resolve_manager(ws, config)
        assert mgr is not None
        try:
            mgr.execute("true", timeout=60)
            run_id = mgr.run_id
        finally:
            mgr.destroy()
        rc, out, _e = _docker(
            "ps",
            "-a",
            "--filter",
            "label=breachpilot=true",
            "--filter",
            f"label=run_id={run_id}",
            "--format",
            "{{.Names}}",
        )
        assert rc == 0
        assert out == ""
