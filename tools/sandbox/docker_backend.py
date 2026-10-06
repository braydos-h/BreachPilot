"""Docker backend for the disposable worker sandbox.

House convention (mirrors ``tools/snapshots.py``): every Docker CLI call goes
through a NAMED module-level wrapper function; tests monkeypatch the wrappers,
never ``subprocess``. The ``DockerBackend`` class composes the wrappers and is
the only Docker-aware component the rest of the codebase touches -- nothing
outside ``tools/sandbox`` may see raw Docker internals.

Worker hardening is enforced in ``_build_create_args``:

- ``--cap-drop ALL`` with no capability added back (packet sockets could
  bypass the IP firewall; ``NET_ADMIN`` belongs exclusively to the ephemeral
  firewall sidecar in ``tools/sandbox/network.py``)
- ``--security-opt no-new-privileges``, no ``--privileged``
- ``--read-only`` rootfs (when configured) + ``--tmpfs /tmp``
- ``--memory`` / ``--memory-swap`` / ``--cpus`` / ``--pids-limit``
- dedicated per-run bridge network (never ``host``, never a shared network)
- NO docker.sock, NO host mounts other than the validated run workspace,
  no devices, no host pid/ipc namespaces
- labels ``breachpilot=true`` / ``run_id=<id>`` -- stale cleanup and audits
  identify OUR resources only; existing containers are NEVER reused
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any

from tools.sandbox.exceptions import SandboxPolicyError, SandboxUnavailableError
from tools.sandbox.models import SandboxSpec

logger = logging.getLogger(__name__)

__all__ = [
    "_docker",
    "DockerCommandTimeout",
    "docker_version",
    "docker_image_exists",
    "docker_network_create",
    "docker_network_inspect",
    "docker_network_gateway",
    "docker_network_list_stale",
    "docker_container_list_stale",
    "docker_running_containers",
    "docker_inspect_state",
    "docker_rm",
    "docker_network_rm",
    "docker_network_disconnect",
    "run_netns_sidecar",
    "start_netns_counter_keeper",
    "read_netns_counter_keeper",
    "stop_netns_counter_keeper",
    "read_netns_firewall_counter",
    "DockerBackend",
    "_build_create_args",
    "DOCKER_TIMEOUT",
    "host_mapping_argv",
]

DOCKER_TIMEOUT = 60
_DOCKER_OUTPUT_LIMIT = 1024 * 1024
_DOCKER_OUTPUT_TRUNCATION = b"\n...[docker output truncated]"
# Host-side hard stop runs this much beyond the container-inner `timeout` TERM.
EXEC_KILL_GRACE_SECONDS = 10

_HOSTS_MARKER = "# breachpilot-pinned"
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
# Fixed trusted worker administration, never agent-generated code. Docker
# bind-mounts /etc/hosts, so replace(2) is unavailable: serialize updates,
# write+fsync+readback before allowing the next command. Background readers
# may transiently fail resolution; the firewall bounds destinations throughout.
_INSTALL_HOSTS = """import os, pathlib, sys
path = pathlib.Path('/etc/hosts')
marker = '# breachpilot-pinned'
retained = [line for line in path.read_text().splitlines() if not line.endswith(marker)]
content = '\\n'.join(retained + sys.argv[1].splitlines()) + '\\n'
with path.open('r+', encoding='utf-8') as stream:
    stream.seek(0)
    stream.write(content)
    stream.truncate()
    stream.flush()
    os.fsync(stream.fileno())
if path.read_text(encoding='utf-8') != content:
    raise RuntimeError('pinned hosts readback failed')
"""


def host_mapping_argv(mappings: Mapping[str, Sequence[str]]) -> list[str]:
    """Build a fixed worker command from validated host-side DNS results."""
    entries: list[str] = []
    for hostname, addresses in sorted(mappings.items()):
        name = hostname.lower().rstrip(".")
        if len(name) > 253 or not all(_HOST_LABEL.fullmatch(label) for label in name.split(".")):
            raise SandboxPolicyError("invalid hostname in pinned DNS mapping")
        for address in sorted(set(addresses)):
            try:
                ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise SandboxPolicyError("invalid address in pinned DNS mapping") from exc
            if "%" in str(ip):
                raise SandboxPolicyError("scoped address in pinned DNS mapping")
            entries.append(f"{ip} {name} {_HOSTS_MARKER}")
    return ["python3", "-c", _INSTALL_HOSTS, "\n".join(entries)]


class DockerCommandTimeout(SandboxUnavailableError, TimeoutError):
    """``docker`` CLI call exceeded its host-side timeout.

    Dual-typed on purpose: verb wrappers treat it as ``SandboxUnavailableError``
    (fail closed), while ``DockerBackend.exec`` re-raises it as a bare
    ``TimeoutError`` so the manager can report a normal command timeout (the
    agent's command ran long) instead of claiming the sandbox broke.
    """


def _docker(*args: str, timeout: int = DOCKER_TIMEOUT, input_text: str = "") -> tuple[int, str, str]:
    """Named seam: single Docker CLI call. Returns (rc, stdout, stderr).

    All sandbox Docker access MUST go through here (or a verb wrapper below);
    tests monkeypatch this module's wrapper functions, never subprocess.
    Missing CLI / daemon down raise ``SandboxUnavailableError`` so every caller
    fail-closes; a host-side timeout raises ``DockerCommandTimeout``.
    """
    try:
        # Drain both pipes concurrently but retain only bounded prefixes. Docker
        # exec output can be controlled by worker processes; capture_output=True
        # would buffer the entire response in host memory before callers trim it.
        proc = subprocess.Popen(  # noqa: S603 -- fixed binary, args fully constructed
            ["docker", *args],
            stdin=subprocess.PIPE if input_text else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + timeout
        if proc.stdout is None or proc.stderr is None:
            proc.kill()
            raise OSError("Docker CLI output pipes were unavailable")

        captured: dict[str, bytes] = {}
        readers = [
            threading.Thread(target=_read_bounded_pipe, args=("stdout", proc.stdout, captured), daemon=True),
            threading.Thread(target=_read_bounded_pipe, args=("stderr", proc.stderr, captured), daemon=True),
        ]
        for reader in readers:
            reader.start()
        stdin_errors: list[OSError] = []
        writer: threading.Thread | None = None
        stdin = proc.stdin
        if input_text and stdin is not None:

            def _write_stdin() -> None:
                try:
                    stdin.write(input_text.encode("utf-8"))
                except BrokenPipeError as exc:
                    stdin_errors.append(exc)
                except OSError as exc:
                    stdin_errors.append(exc)
                finally:
                    try:
                        stdin.close()
                    except BrokenPipeError as exc:
                        stdin_errors.append(exc)
                    except OSError as exc:
                        stdin_errors.append(exc)

            writer = threading.Thread(target=_write_stdin, daemon=True)
            writer.start()
        try:
            returncode = proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            for reader in readers:
                reader.join()
            if writer is not None:
                writer.join()
            raise DockerCommandTimeout(f"docker {' '.join(args[:2])} timed out after {timeout}s") from None
        for reader in readers:
            reader.join()
        if writer is not None:
            writer.join()
        if stdin_errors:
            raise SandboxUnavailableError(f"docker {' '.join(args[:2])} input failed: {stdin_errors[0]}")
        out = captured.get("stdout", b"").decode("utf-8", errors="replace")
        err = captured.get("stderr", b"").decode("utf-8", errors="replace")
        return returncode, out, err
    except DockerCommandTimeout:
        raise
    except SandboxUnavailableError:
        raise
    except FileNotFoundError:
        raise SandboxUnavailableError(
            "Docker CLI not found on PATH. Install Docker Desktop (Windows/macOS) or "
            "'docker.io'/'docker-ce' (Linux). Agent execution remains blocked until "
            "the sandbox worker is available."
        ) from None
    except OSError as exc:
        raise SandboxUnavailableError(f"docker {' '.join(args[:2])} failed: {exc}") from None


def _read_bounded_pipe(name: str, pipe: Any, captured: dict[str, bytes]) -> None:
    """Drain a subprocess pipe while retaining at most the configured limit."""
    retained = bytearray()
    truncated = False
    while True:
        chunk = pipe.read(64 * 1024)
        if not chunk:
            break
        remaining = _DOCKER_OUTPUT_LIMIT - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
    if truncated:
        retained = retained[: _DOCKER_OUTPUT_LIMIT - len(_DOCKER_OUTPUT_TRUNCATION)]
        retained.extend(_DOCKER_OUTPUT_TRUNCATION)
    captured[name] = bytes(retained)


def docker_version() -> tuple[bool, str]:
    """(daemon_reachable, version_or_error) probe."""
    try:
        rc, out, err = _docker("version", "--format", "{{.Server.Version}}", timeout=20)
    except SandboxUnavailableError as exc:
        return False, str(exc)
    if rc != 0:
        return False, (err or out or "docker daemon unreachable").strip()[:200]
    return True, out.strip()


def docker_image_exists(image: str) -> bool:
    try:
        rc, _out, _err = _docker("image", "inspect", image)
    except SandboxUnavailableError:
        raise
    return rc == 0


def docker_network_create(name: str) -> str:
    rc, _out, err = _docker("network", "create", "--driver", "bridge", name)
    if rc != 0:
        raise SandboxUnavailableError(f"docker network create failed: {err.strip()[:200]}")
    return name


def docker_network_inspect(name: str) -> dict[str, Any] | None:
    rc, out, _err = _docker("network", "inspect", name, "--format", "{{json .}}", timeout=30)
    if rc != 0:
        return None
    try:
        import json

        return dict(json.loads(out))
    except (ValueError, TypeError):
        return None


def docker_network_gateway(name: str) -> str:
    info = docker_network_inspect(name)
    if not info:
        return ""
    ipam = (info.get("IPAM") or {}).get("Config") or []
    for cfg in ipam:
        gw = str(cfg.get("Gateway", "") or "")
        if gw:
            return gw
    return ""


def docker_network_list_stale(*, label: str = "breachpilot=true") -> list[str]:
    rc, out, _err = _docker("network", "ls", "--filter", f"label={label}", "--format", "{{.Name}}", timeout=30)
    if rc != 0:
        return []
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def docker_container_list_stale(*, label: str = "breachpilot=true") -> list[str]:
    rc, out, _err = _docker("ps", "-a", "--filter", f"label={label}", "--format", "{{.Names}}", timeout=30)
    if rc != 0:
        return []
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def docker_running_containers() -> list[str] | None:
    """Return running container IDs, or ``None`` when Docker is unreachable."""
    try:
        rc, out, _err = _docker("ps", "-q", timeout=30)
    except SandboxUnavailableError:
        return None
    if rc != 0:
        return None
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def docker_inspect_state(container_id: str) -> str:
    rc, out, _err = _docker("inspect", "-f", "{{.State.Status}}", container_id, timeout=20)
    return out.strip() if rc == 0 else ""


# ── Idempotent teardown helpers (network-lifecycle false-negative fix) ──────
# ``docker rm`` / ``docker network rm`` report rc != 0 both for real failures
# AND for the benign "already gone" case. Treating every non-zero as failure
# makes a second delete (or a double delete from two teardown layers) report a
# false-negative even though the desired end state (resource gone) holds.
# These matchers distinguish the cases by error text instead of rc alone.
_NOT_FOUND_SUBSTRINGS = (
    "no such network",
    "no such container",
    "no such object",
    "not found",
    "error 404",
    "404 not found",
)
# ``docker network rm`` fails transiently while a just-removed container's
# endpoint is still detaching (async in the daemon): "has active endpoints".
_ACTIVE_ENDPOINTS_SUBSTRINGS = (
    "has active endpoint",
    "active endpoint",
    "has connections",
    "is in use",
    "endpoint is still",
)


def _combined_text(out: str, err: str) -> str:
    return f"{out or ''}\n{err or ''}".lower()


def _is_not_found_error(out: str, err: str) -> bool:
    text = _combined_text(out, err)
    return any(marker in text for marker in _NOT_FOUND_SUBSTRINGS)


def _is_active_endpoints_error(out: str, err: str) -> bool:
    text = _combined_text(out, err)
    return any(marker in text for marker in _ACTIVE_ENDPOINTS_SUBSTRINGS)


def _resolve_network_target(name: str) -> str:
    """Canonical ``network rm`` token: prefer the inspected ID over a name.

    Docker accepts names and IDs interchangeably, but error text and stale
    listings mix the two (name vs ID confusion). Resolving to the daemon's
    canonical ID makes delete + leaked-network scans unambiguous. Returns the
    original token when inspection fails (the caller then lets ``rm`` report
    the authoritative answer, mapping "not found" to success).
    """
    try:
        info = docker_network_inspect(name)
    except SandboxUnavailableError:
        return name
    if isinstance(info, dict):
        nid = str(info.get("Id") or "").strip()
        if nid:
            return nid
    return name


def docker_rm(name: str) -> bool:
    """Remove a container idempotently: missing/empty means already gone (True).

    Query-then-delete: an inspect miss for "no such container" short-circuits
    to success without attempting ``rm``; a post-``rm`` "not found" (lost race
    with a concurrent deleter) also maps to success. Daemon errors stay False
    so the caller can audit incomplete cleanup. Never raises.
    """
    token = str(name or "").strip()
    if not token:
        return True
    try:
        q_rc, q_out, q_err = _docker("inspect", token, timeout=20)
    except SandboxUnavailableError:
        return False
    if q_rc != 0 and _is_not_found_error(q_out, q_err):
        return True
    try:
        rc, out, err = _docker("rm", "-f", token, timeout=90)
    except SandboxUnavailableError:
        return False
    if rc == 0:
        return True
    return _is_not_found_error(out, err)


def docker_network_disconnect(network: str, container: str) -> bool:
    """Best-effort ``network disconnect`` for the detach race. Never raises.

    Called before ``network rm`` when the container is known: after ``rm -f``
    the daemon detaches the endpoint asynchronously, and ``network rm`` in
    that window fails with "has active endpoints". An explicit forced
    disconnect narrows the window; residual races are covered by the retry
    loop in ``docker_network_rm``. Missing resources map to True (idempotent).
    """
    net = str(network or "").strip()
    ctr = str(container or "").strip()
    if not net or not ctr:
        return True
    try:
        rc, out, err = _docker("network", "disconnect", "-f", net, ctr, timeout=30)
    except SandboxUnavailableError:
        return False
    if rc == 0:
        return True
    return _is_not_found_error(out, err)


def docker_network_rm(name: str, *, retries: int = 5, retry_delay: float = 0.5) -> bool:
    """Remove a network idempotently with detach-race retries. Never raises.

    Query-then-delete: ``network inspect`` resolves the canonical ID (name vs
    ID confusion) and short-circuits "no such network" to success. ``rm``
    "not found" (deleted between query and delete) also maps to success.
    "Has active endpoints" (container still detaching) retries with backoff;
    any other error maps to False so teardown audits stay honest. Empty names
    are a no-op success. Fail-closed: daemon-unreachable maps to False, never
    to a host-execution fallback (callers only audit/log the booleans).
    """
    token = str(name or "").strip()
    if not token:
        return True
    try:
        q_rc, q_out, q_err = _docker("network", "inspect", token, "--format", "{{json .}}", timeout=30)
    except SandboxUnavailableError:
        return False
    if q_rc != 0 and _is_not_found_error(q_out, q_err):
        return True
    target = token
    if q_rc == 0:
        try:
            import json

            info = json.loads(q_out)
            nid = str((info or {}).get("Id") or "").strip() if isinstance(info, dict) else ""
            if nid:
                target = nid
        except (ValueError, TypeError, AttributeError):
            target = token
    attempts = max(1, int(retries or 1))
    for attempt in range(attempts):
        try:
            rc, out, err = _docker("network", "rm", target, timeout=60)
        except SandboxUnavailableError:
            return False
        if rc == 0:
            return True
        if _is_not_found_error(out, err):
            return True
        if _is_active_endpoints_error(out, err):
            if attempt < attempts - 1:
                time.sleep(max(0.0, float(retry_delay or 0.0)))
                continue
            return False
        return False
    return False


def run_netns_sidecar(
    container_id: str,
    image: str,
    binary: str,
    rules_text: str,
    args: tuple[str, ...] = (),
) -> tuple[int, str, str]:
    """Named seam: firewall installer.

    Runs an ephemeral sidecar sharing the WORKER's network namespace with a
    temporary ``NET_ADMIN`` grant (docker removes the netns grant when it
    exits). The ruleset arrives on stdin; the sidecar is ``--rm``. The worker
    itself never receives NET_ADMIN, so agent commands cannot undo this.
    """
    if args not in ((), ("--noflush",)):
        raise SandboxPolicyError("unsupported sandbox firewall restore arguments")
    return _docker(
        "run",
        "--rm",
        "-i",
        "--network",
        f"container:{container_id}",
        "--cap-add",
        "NET_ADMIN",
        "--entrypoint",
        binary,
        image,
        *args,
        timeout=90,
        input_text=rules_text,
    )


def start_netns_counter_keeper(container_id: str, image: str) -> str:
    """Start a short-lived, isolated NET_ADMIN sidecar to pin the worker netns.

    It is used only while finalizing telemetry: the worker is stopped first,
    then counters are read from the still-pinned namespace. The sidecar has no
    host mounts, drops every capability except NET_ADMIN, and runs only sleep.
    """
    cid = _validate_container_id(container_id)
    rc, out, err = _docker(
        "run",
        "--detach",
        "--rm",
        "--network",
        f"container:{cid}",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_ADMIN",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--pids-limit",
        "16",
        "--entrypoint",
        "sleep",
        image,
        "infinity",
        timeout=30,
    )
    if rc != 0:
        raise SandboxUnavailableError(f"network counter sidecar failed to start: {(err or out).strip()[:300]}")
    return _validate_container_id(out.strip())


def read_netns_counter_keeper(container_id: str, binary: str) -> tuple[int, str, str]:
    """Read one address-family firewall snapshot from the trusted keeper."""
    cid = _validate_container_id(container_id)
    if binary not in ("iptables-save", "ip6tables-save"):
        raise SandboxPolicyError("unsupported sandbox firewall counter command")
    return _docker("exec", cid, binary, "-c", timeout=15)


def read_netns_firewall_counter(container_id: str, image: str, binary: str) -> tuple[int, str, str]:
    """Read counters using an ephemeral NET_ADMIN sidecar while the worker runs."""
    cid = _validate_container_id(container_id)
    if binary not in ("iptables-save", "ip6tables-save"):
        raise SandboxPolicyError("unsupported sandbox firewall counter command")
    return _docker(
        "run",
        "--rm",
        "--network",
        f"container:{cid}",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_ADMIN",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--entrypoint",
        binary,
        image,
        "-c",
        timeout=20,
    )


def stop_netns_counter_keeper(container_id: str) -> bool:
    """Stop/remove the temporary telemetry sidecar, including error cleanup."""
    cid = _validate_container_id(container_id)
    rc, out, err = _docker("stop", "-t", "1", cid, timeout=15)
    if rc == 0 or _is_not_found_error(out, err):
        return True
    logger.warning("sandbox counter sidecar stop failed: %s", (err or out).strip()[:200])
    return docker_rm(cid)


def _validate_container_id(container_id: str) -> str:
    cid = str(container_id).strip()
    if not cid or any(c in cid for c in " ;|`$\n\r\\\"'"):
        raise SandboxUnavailableError("invalid sandbox container id")
    return cid


def _tmpfs_size_mb(spec: SandboxSpec) -> int:
    """Clamp the /tmp tmpfs size to >=64MB; invalid values fall back to 256 (fail closed)."""
    try:
        size = int(getattr(spec, "tmpfs_size_mb", 256) or 256)
    except (TypeError, ValueError):
        return 256
    return size if size >= 64 else 64


def _build_create_args(spec: SandboxSpec, *, read_only_rootfs: bool) -> list[str]:
    """The hardened ``docker create`` argv. Pure function -- fully unit-tested.

    Host-protection invariants asserted here: no docker.sock, no host root /
    home / arbitrary host dirs, no devices, no privileged/host pid/ipc, only
    the validated run workspace is bound (rw), everything else denied.
    """
    image = str(spec.image or "").strip()
    if not image or any(c in image for c in ";|`$\n\r") or image.startswith("-"):
        raise SandboxUnavailableError(f"invalid sandbox image {image!r}")
    cver = _validate_container_id(spec.sandbox_id)
    user = str(spec.user or "sandbox").strip()
    src = str(spec.workspace_src or "").strip()
    if not src:
        raise SandboxUnavailableError("worker requires a validated workspace bind")
    args = [
        "create",
        "--name",
        cver,
        "--network",
        str(spec.network_name),
        "--label",
        "breachpilot=true",
        "--label",
        f"run_id={spec.labels.get('run_id', '')}",
        # Packet sockets bypass the IP-layer destination firewall, so workers
        # receive no capabilities. NET_ADMIN belongs only to the ephemeral
        # firewall sidecar, never to the worker.
        "--cap-drop",
        "ALL",
    ]
    args += [
        "--security-opt",
        "no-new-privileges",
        "--user",
        user,
        "--memory",
        f"{int(spec.memory_mb)}m",
        "--memory-swap",
        f"{int(spec.memory_mb)}m",
        "--cpus",
        str(spec.cpus),
        "--pids-limit",
        str(int(spec.pids_limit)),
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={_tmpfs_size_mb(spec)}m",
        "-v",
        f"{src}:/workspace:rw",
        "-w",
        "/workspace",
    ]
    if read_only_rootfs:
        args.append("--read-only")
    # Override both ENTRYPOINT and CMD: a configured derived image must not run
    # image-controlled startup code before the manager installs its netns
    # firewall. The base image contract includes this fixed keepalive binary.
    args += ["--entrypoint", "sleep", image, "infinity"]
    return args


class DockerBackend:
    """Composes the wrapper seams; one method per lifecycle step.

    All failures raise ``SandboxUnavailableError`` so the manager fail-closes
    (offensive execution blocked; never a silent host fallback).
    """

    def __init__(self, *, exec_seam: Any = None) -> None:
        # exec_seam allows callers (tests) to swap the docker-exec wrapper.
        self._exec_seam = exec_seam

    def ensure_docker(self) -> None:
        ok, reason = docker_version()
        if not ok:
            raise SandboxUnavailableError(
                f"Docker daemon unreachable: {reason}. Offensive execution is blocked "
                "(fail-closed); start Docker and keep sandbox containment enabled."
            )

    def ensure_image(self, image: str) -> None:
        if not docker_image_exists(image):
            raise SandboxUnavailableError(
                f"sandbox image {image!r} not found. Build it with: 'docker build -t <image> docker/sandbox'."
            )

    def create_network(self, name: str) -> str:
        return docker_network_create(name)

    def create_worker(self, spec: SandboxSpec, *, read_only_rootfs: bool) -> str:
        argv = _build_create_args(spec, read_only_rootfs=read_only_rootfs)
        rc, out, err = _docker(*argv)
        if rc != 0:
            raise SandboxUnavailableError(f"docker create failed: {(err or out).strip()[:300]}")
        container = out.strip()
        rc2, _o2, err2 = _docker("start", container)
        if rc2 != 0:
            docker_rm(container)
            raise SandboxUnavailableError(f"docker start failed: {err2.strip()[:300]}")
        # The worker's keepalive (sleep infinity) must be observed as running
        # before the caller joins its netns. Poll briefly; fail closed if it
        # never reaches running (exited / dead).
        for _ in range(30):
            state = docker_inspect_state(container)
            if state == "running":
                break
            if state in ("exited", "dead"):
                docker_rm(container)
                raise SandboxUnavailableError(f"sandbox worker {container} exited immediately (state={state})")
            time.sleep(0.1)
        else:
            docker_rm(container)
            raise SandboxUnavailableError(f"sandbox worker {container} not running after start")
        return container

    def render_firewall(self, container_id: str, image: str, binary: str, rules_text: str) -> tuple[int, str, str]:
        return run_netns_sidecar(container_id, image, binary, rules_text)

    def exec(
        self,
        container_id: str,
        argv: list[str],
        *,
        timeout: int,
        user: str = "",
        env: dict[str, str] | None = None,
        input_text: str = "",
        workdir: str = "",
    ) -> tuple[int, str, str]:
        """Run a command inside the running worker. Returns (rc, stdout, stderr).

        The container-inner ``timeout`` (TERM→KILL) is the primary bound; the
        host-side timeout is the hard stop. Environment is allowlisted by the
        manager, never a copy of the host environment. ``workdir`` must be an
        absolute container path (the manager maps host workspace paths onto
        ``/workspace``); anything else is rejected.
        """
        cid = _validate_container_id(container_id)
        workdir = str(workdir or "").strip()
        if workdir and (not workdir.startswith("/") or ".." in workdir.split("/")):
            raise SandboxUnavailableError(f"invalid sandbox workdir {workdir!r}")
        docker_argv: list[str] = ["exec"]
        if input_text:
            # Docker exec does not attach/forward stdin unless interactive
            # mode is enabled. Structured worker protocols use stdin instead
            # of argv/environment to keep request bodies out of process lists.
            docker_argv.append("-i")
        if workdir:
            docker_argv += ["-w", workdir]
        if user:
            docker_argv += ["--user", user]
        for key, value in (env or {}).items():
            _validate_env_key(key)
            docker_argv += ["--env", f"{key}={value}"]
        docker_argv += [cid, *argv]
        if self._exec_seam is not None:
            return self._exec_seam(docker_argv, timeout, input_text=input_text)
        try:
            return _docker(*docker_argv, timeout=timeout, input_text=input_text)
        except DockerCommandTimeout as exc:
            # A long-running agent command is a normal timeout, not sandbox breakage.
            raise TimeoutError(str(exc)) from None

    def stop(self, container_id: str) -> None:
        _validate_container_id(container_id)
        try:
            _docker("stop", "-t", "5", container_id, timeout=30)
        except SandboxUnavailableError:
            logger.warning("sandbox stop %s failed", container_id)

    def destroy(self, container_id: str, network_name: str) -> dict[str, bool]:
        """Terminate + remove the worker and its dedicated network (best per-op answer).

        Single owner of the network delete: removes the container idempotently,
        best-effort disconnects its endpoint (narrows the detach race), then
        removes the network with retries. Fail-closed: per-op booleans only,
        never a host-subprocess fallback for agent commands (agent execution
        stays inside ``docker exec``; these booleans only drive audit rows).
        """
        container_removed = docker_rm(container_id)
        if str(network_name or "").strip() and str(container_id or "").strip():
            try:
                docker_network_disconnect(network_name, container_id)
            except Exception:  # noqa: BLE001 -- disconnect is best-effort; rm retries cover residual races
                pass
        network_removed = docker_network_rm(network_name)
        results = {"container_removed": container_removed, "network_removed": network_removed}
        if not all(results.values()):
            logger.warning("sandbox destroy incomplete: %s", results)
        return results


def _validate_env_key(key: str) -> None:
    if not str(key).strip() or any(c in str(key) for c in "= \n\r") or str(key).startswith("-"):
        raise SandboxUnavailableError(f"invalid sandbox env key {key!r}")
