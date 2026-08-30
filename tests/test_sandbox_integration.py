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

Unauthorized destinations use TEST-NET addresses (RFC 5737, 192.0.2.0/24):
the firewall DROPs them, so no packet ever leaves the docker host.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

import pytest

SANDBOX_IMAGE = "breachpilot-sandbox:latest"
TARGET_NAME = "breachpilot-sandbox-it-target"
UNAUTHORIZED_IP = "192.0.2.1"  # TEST-NET-1: reserved, never routed
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


_DAEMON = _daemon_ok()
_IMAGE = _image_ok()

pytestmark = pytest.mark.skipif(
    not (_DAEMON and _IMAGE),
    reason=(
        "sandbox integration requires a reachable Docker daemon and the "
        f"{SANDBOX_IMAGE} image (docker build -t {SANDBOX_IMAGE} docker/sandbox)"
    ),
)


def _target_ip_on(network: str) -> str:
    """IP of the helper target container on ``network`` (empty when detached)."""
    rc, out, _err = _docker(
        "inspect",
        "-f",
        "{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}} {{end}}",
        TARGET_NAME,
    )
    if rc != 0:
        return ""
    for entry in out.split():
        return entry
    return ""


def _ensure_target_container() -> None:
    rc, _out, _err = _docker("inspect", TARGET_NAME)
    if rc != 0:
        rc, _o, err = _docker(
            "run",
            "-d",
            "--name",
            TARGET_NAME,
            "--label",
            "breachpilot=true",
            SANDBOX_IMAGE,
            "python3",
            "-m",
            "http.server",
            "8090",
            "--bind",
            "0.0.0.0",
        )
        if rc != 0:
            pytest.skip(f"cannot start integration target container: {err[:200]}")
    else:
        # Reuse from a previous module run: make sure it is up.
        _docker("start", TARGET_NAME)


@pytest.fixture(scope="module")
def it_env(tmp_path_factory) -> dict[str, Any]:
    """One sandbox worker + one authorized helper target, shared by the module."""
    from tools.sandbox import resolve_manager

    ws = tmp_path_factory.mktemp("sandbox_it") / "ws"
    ws.mkdir(parents=True)
    _ensure_target_container()

    config: dict[str, Any] = {
        "exploit": {"allowed_targets": ["192.0.2.10"]},  # placeholder; real IP set below
        "sandbox": {
            "enabled": True,
            "image": SANDBOX_IMAGE,
            "resources": {"memory_mb": 1024, "cpus": 1.0, "pids": 256, "timeout_seconds": 60},
            "network": {"allow_research_hosts": False},
        },
    }
    mgr = resolve_manager(ws, config)
    assert mgr is not None, "sandbox manager must build when enabled"

    # Bring the worker up once, attach the helper target to ITS network, then
    # authorize the target's concrete IP (worker + target share a bridge, so
    # Docker inter-network isolation never confounds the firewall results).
    mgr.execute("true", timeout=30)
    rc, _o, err = _docker("network", "connect", mgr.network_name, TARGET_NAME)
    if rc != 0:
        mgr.destroy()
        pytest.skip(f"cannot attach target container: {err[:200]}")
    target_ip = _target_ip_on(mgr.network_name)
    if not target_ip:
        mgr.destroy()
        pytest.skip("target container has no IP on the sandbox network")
    mgr.config_dict["exploit"]["allowed_targets"] = [target_ip]

    yield {"mgr": mgr, "target_ip": target_ip, "ws": ws}
    mgr.destroy()
    _docker("rm", "-f", TARGET_NAME)


def _run(it_env: dict, command: str, timeout: int = 40) -> Any:
    return it_env["mgr"].execute(command, timeout=timeout, target_ip="")


class TestNetworkBoundary:
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
            f"python3 -c \"import socket\ntry:\n  socket.create_connection(('{UNAUTHORIZED_IP}',8090),3)\n  print('LEAK')\nexcept Exception as e:\n  print('BLOCKED', type(e).__name__)\"",
        )
        assert "LEAK" not in result.stdout
        assert "BLOCKED" in result.stdout

    def test_destinationless_script_blocked(self, it_env):
        # THE critical case: the command string contains NO destination — the
        # application-layer parser cannot see one — yet the network layer
        # still blocks the egress attempt.
        script = (
            "import socket\n"
            f"try:\n    socket.create_connection(('{UNAUTHORIZED_IP}', 8090), 3)\n"
            "    print('LEAK')\n"
            "except Exception as exc:\n"
            "    print('BLOCKED', type(exc).__name__)\n"
        )
        (it_env["ws"] / "egress.py").write_text(script, encoding="utf-8")
        result = _run(it_env, "python3 /workspace/egress.py")
        assert "LEAK" not in result.stdout
        assert "BLOCKED" in result.stdout

    def test_obfuscated_destination_blocked(self, it_env):
        # Hex-encoded TEST-NET IP (192.0.2.2), decoded at runtime: the parser
        # sees nothing; the firewall still does.
        result = _run(
            it_env,
            "python3 -c \"import socket;ip='.'.join(str(int(x,16)) for x in ['c0','00','02','02'])\n"
            "try:\n  socket.create_connection((ip,8090),3)\n  print('LEAK')\nexcept Exception as e:\n  print('BLOCKED', type(e).__name__)\"",
        )
        assert "LEAK" not in result.stdout
        assert "BLOCKED" in result.stdout

    def test_unauthorized_hostname_blocked(self, it_env):
        # Controlled DNS resolves (docker embedded resolver on loopback), but
        # the resolved foreign IP is not authorized => connect fails.
        result = _run(
            it_env, "curl --max-time 8 -sS -o /dev/null -w '%{http_code}' http://example.com/ || echo CURL_BLOCKED"
        )
        assert "CURL_BLOCKED" in result.stdout or "000" in result.stdout
        assert "200" not in result.stdout

    def test_dev_tcp_blocked(self, it_env):
        result = _run(it_env, f"timeout 8 bash -c 'echo > /dev/tcp/{UNAUTHORIZED_IP}/80' && echo LEAK || echo BLOCKED")
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

    def test_no_stale_labeled_resources_after_module(self, it_env):
        # The module fixture destroyed its manager; nothing labeled with this
        # run_id may remain.
        rc, out, _e = _docker(
            "ps",
            "-a",
            "--filter",
            "label=breachpilot=true",
            "--filter",
            f"label=run_id={it_env['mgr'].run_id}",
            "--format",
            "{{.Names}}",
        )
        assert rc == 0
        assert out == ""
