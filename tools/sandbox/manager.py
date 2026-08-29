"""SandboxManager: disposable worker lifecycle, fail-closed execution funnel.

Lifecycle per attack session (one worker container per MCP server process,
i.e. one per attack run):

    ensure (docker checks -> dedicated network -> hardened worker -> netns
    firewall) -> execute every attack command inside -> destroy on normal
    exit / exception / timeout / cancellation / interpreter shutdown (atexit).

FAIL CLOSED contract: any creation, policy, scope, or workspace failure raises
a ``SandboxError`` subclass with a structured ``code``; the MCP tools convert
it into a ``SANDBOX_*`` result block and never fall back to host execution.
``resolve_manager`` returns None when the sandbox is disabled so the
documented legacy host-execution mode stays available as the explicit opt-out.

Audit: every execution writes sandbox-context rows (container id, image,
network-authorization decision, authorized set, exit code, duration, cleanup
result) into ``exploit_audit.jsonl`` through the shared kernel auditor
(secret redaction reused from ``tools/kernel/audit.py``; the sandbox payload
is secret-free by construction -- see ``policy.audit_policy_payload``).
"""

from __future__ import annotations

import atexit
import logging
import secrets
import time
from pathlib import Path
from typing import Any

from tools.sandbox import docker_backend as _db
from tools.sandbox import policy as _policy
from tools.sandbox.exceptions import (
    SandboxError,
    SandboxScopeError,
    SandboxUnavailableError,
    SandboxWorkspaceError,
)
from tools.sandbox.models import NetworkPolicy, SandboxConfig, SandboxResult, SandboxSpec
from tools.sandbox.network import apply_network_policy

logger = logging.getLogger(__name__)

__all__ = ["SandboxManager", "resolve_manager", "status_report", "CONTAINER_WORKSPACE"]

CONTAINER_WORKSPACE = "/workspace"

# Environment the worker may receive: fixed sandbox markers, run-context keys
# the MCP tool layer injects, and operator-configured ``env_passthrough`` names.
# NEVER a copy of the host environment.
_BASE_ENV: dict[str, str] = {
    "EXPLOIT_SANDBOX": "1",
    "EXPLOIT_WORKSPACE": CONTAINER_WORKSPACE,
    "TERM": "dumb",
}
_RUN_ENV_ALLOWLIST = {
    "ACTIVE_CHECK_TARGET",
    "EXPLOIT_TARGET",
    "EXPLOIT_TARGET_IP",
    "EXPLOIT_TARGET_DOMAIN",
    "MCP_EXPLOIT_MODEL",
    "MODEL",
    "OLLAMA_HOST",
}


def resolve_manager(workspace: Path, config: dict[str, Any] | None) -> SandboxManager | None:
    """Build a SandboxManager from config; returns None when the sandbox is disabled.

    A MISSING ``sandbox`` section (tests, partial config dicts) means disabled =>
    documented legacy host-execution mode. A PRESENT-but-broken section returns
    a manager that fail-closes at execution time -- it never silently upgrades
    to host execution.
    """
    cfg = SandboxConfig.from_config(config)
    if not cfg.enabled:
        return None
    # cap_raw honors sandbox.multi_net_raw: NET_RAW is the ONLY capability the
    # worker may receive (raw packet scanning); NET_ADMIN is never granted.
    return SandboxManager(
        cfg,
        workspace,
        config_dict=config,
        backend=_db.DockerBackend(cap_raw=cfg.multi_net_raw),
    )


class SandboxManager:
    """Owns exactly one disposable worker container + its dedicated bridge network."""

    def __init__(
        self,
        config: SandboxConfig,
        workspace: Path,
        *,
        config_dict: dict[str, Any] | None = None,
        backend: Any = None,
        run_id: str = "",
    ) -> None:
        self.cfg = config
        self.workspace = Path(workspace)
        self.config_dict = config_dict
        self.backend = backend if backend is not None else _db.DockerBackend()
        self.run_id = run_id or secrets.token_hex(6)
        self.container_id: str = ""
        self.network_name: str = ""
        self.gateway: str = ""
        self._policy: NetworkPolicy | None = None
        self._destroyed = False
        atexit.register(self._atexit_destroy)

    # ------------------------------------------------------------------ setup

    def ensure_sandbox(self) -> str:
        """Guarantee a running, policy-contained worker. Returns the container id.

        A mid-run vanished worker is recreated fresh (never reused). Any
        failure destroys partial resources and raises ``SandboxError`` -- the
        caller must block execution; there is no host fallback.
        """
        if self.container_id:
            state = self._container_state()
            if state == "running":
                self._apply_policy()
                return self.container_id
            logger.warning("sandbox worker %s vanished (state=%r); recreating", self.container_id, state)
            self._destroy_resources()
        try:
            self.backend.ensure_docker()
            self.backend.ensure_image(self.cfg.image)
            self._validate_workspace()
            if self.cfg.remove_stale_on_startup:
                self.cleanup_stale()
            self.network_name = f"netattack-net-{self.run_id}-{secrets.token_hex(3)}"
            self.backend.create_network(self.network_name)
            self.gateway = _db.docker_network_gateway(self.network_name)
            spec = SandboxSpec(
                sandbox_id=f"netattack-{self.run_id}-{secrets.token_hex(3)}",
                image=self.cfg.image,
                user=self.cfg.user,
                network_name=self.network_name,
                workspace_src=str(self.workspace),
                memory_mb=self.cfg.memory_mb,
                cpus=self.cfg.cpus,
                pids_limit=self.cfg.pids_limit,
                read_only_rootfs=self.cfg.read_only_rootfs,
                labels={"run_id": self.run_id},
            )
            self.container_id = self.backend.create_worker(spec, read_only_rootfs=self.cfg.read_only_rootfs)
            self.container_id = _db._validate_container_id(self.container_id)
            # Firewall BEFORE the first agent command; NET_ADMIN lives only in
            # the ephemeral --rm sidecar, never in the worker itself.
            self._apply_policy(force=True)
            if self._container_state() != "running":
                raise SandboxUnavailableError("sandbox worker is not running after start")
        except SandboxError:
            self._destroy_resources()
            raise
        except Exception as exc:
            self._destroy_resources()
            raise SandboxUnavailableError(f"sandbox creation failed: {exc}") from exc
        return self.container_id

    def _container_state(self) -> str:
        if not self.container_id:
            return ""
        try:
            return _db.docker_inspect_state(self.container_id)
        except SandboxError:
            return ""

    def _validate_workspace(self) -> None:
        ws = self.workspace
        if not ws.exists() or not ws.is_dir():
            raise SandboxWorkspaceError(f"sandbox workspace {ws} is not a directory")
        # Symlink-escape guard: the bound directory must be a real directory.
        if ws.is_symlink():
            raise SandboxWorkspaceError(f"sandbox workspace {ws} must not be a symlink")

    # ------------------------------------------------------- network policy

    def _apply_policy(self, *, force: bool = False) -> NetworkPolicy:
        """Derive the egress policy; install firewall rules when it changed.

        Re-derivation happens at every command boundary so dynamically
        authorized targets (allowlist-validated resolved domains + discovered
        subdomains) are picked up deliberately -- never automatic DNS egress.
        """
        pol = _policy.build_network_policy(self.config_dict, gateway=self.gateway)
        if not force and self._policy is not None and pol.fingerprint() == self._policy.fingerprint():
            return pol
        if self.cfg.network_enforce:
            apply_network_policy(pol, container_id=self.container_id, image=self.cfg.image, gateway=self.gateway)
        else:
            logger.warning(
                "sandbox network.enforce=false: worker runs WITHOUT netns firewall "
                "(Docker bridge isolation only -- this is NOT containment)"
            )
        self._policy = pol
        return pol

    def ensure_network_policy(self) -> NetworkPolicy:
        return self._apply_policy(force=False)

    # ------------------------------------------------------------- execution

    def execute(
        self,
        command: str,
        *,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        user: str = "",
        target_ip: str = "",
        tool_name: str = "run_exploit_terminal",
    ) -> SandboxResult:
        """Run one LLM-generated shell command inside the sandbox.

        Raises ``SandboxError`` subclasses (fail closed) -- NEVER falls back to
        the host. Audit rows carry the sandbox / network-authorization context.
        """
        inner = int(timeout or self.cfg.exec_timeout_seconds)
        grace = _db.EXEC_KILL_GRACE_SECONDS
        argv = ["timeout", "-k", str(grace), str(inner), "bash", "-lc", command]
        return self._execute_argv(
            argv,
            timeout=inner + grace + 10,
            cwd=cwd,
            env=env,
            user=user or self.cfg.user,
            target_ip=target_ip,
            tool_name=tool_name,
            audit_command=command,
        )

    def execute_argv(
        self,
        argv: list[str],
        *,
        timeout: int | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        user: str = "",
        target_ip: str = "",
        tool_name: str = "",
    ) -> SandboxResult:
        """Run an argv-list tool (nmap, impacket, msfvenom, ...) inside the sandbox."""
        inner = int(timeout or self.cfg.exec_timeout_seconds)
        grace = _db.EXEC_KILL_GRACE_SECONDS
        wrapped = ["timeout", "-k", str(grace), str(inner), *argv]
        return self._execute_argv(
            wrapped,
            timeout=inner + grace + 10,
            cwd=cwd,
            env=env,
            user=user or self.cfg.user,
            target_ip=target_ip,
            tool_name=tool_name,
            audit_command="",
        )

    def _execute_argv(
        self,
        argv: list[str],
        *,
        timeout: int,
        cwd: str | None,
        env: dict[str, str] | None,
        user: str,
        target_ip: str,
        tool_name: str,
        audit_command: str,
    ) -> SandboxResult:
        self._enforce_scope(target_ip)
        self._validate_workspace()
        container = self.ensure_sandbox()
        pol = self._apply_policy()
        extra_env = self._build_env(env)
        start = time.monotonic()
        self._audit(
            target_ip=target_ip,
            tool_name=tool_name,
            status="started",
            command=audit_command,
            extra_env=extra_env,
            policy_payload=_policy.audit_policy_payload(pol),
            exit_code=None,
            duration=None,
        )
        try:
            rc, out, err = self.backend.exec(
                container,
                argv,
                timeout=timeout,
                user=user,
                env=extra_env,
                workdir=cwd or "",
            )
        except TimeoutError:
            elapsed = time.monotonic() - start
            self._audit(
                target_ip=target_ip,
                tool_name=tool_name,
                status="timed_out",
                command=audit_command,
                extra_env=extra_env,
                policy_payload=_policy.audit_policy_payload(pol),
                exit_code=None,
                duration=elapsed,
            )
            return SandboxResult.timed_out_result(elapsed, container)
        duration = time.monotonic() - start
        result = SandboxResult(
            exit_code=int(rc),
            stdout=_clamp_output(out, self.cfg.output_max_bytes),
            stderr=_clamp_output(err, self.cfg.output_max_bytes),
            timed_out=False,
            duration_seconds=duration,
            sandbox_id=container,
            status="completed" if int(rc) == 0 else "failed",
        )
        self._audit(
            target_ip=target_ip,
            tool_name=tool_name,
            status=result.status,
            command=audit_command,
            extra_env=extra_env,
            policy_payload=_policy.audit_policy_payload(pol),
            exit_code=result.exit_code,
            duration=duration,
        )
        return result

    def container_path(self, host_path: Path) -> str:
        """Map a host path under the run workspace to its in-container path.

        Only paths inside the validated workspace are mapped; anything else
        raises (traversal / symlink-escape / arbitrary-host-path prevention).
        """
        resolved = Path(host_path).resolve()
        try:
            rel = resolved.relative_to(self.workspace.resolve())
        except ValueError:
            raise SandboxWorkspaceError(f"path {resolved} is outside the sandbox workspace {self.workspace}") from None
        if str(rel) == ".":
            return CONTAINER_WORKSPACE
        return f"{CONTAINER_WORKSPACE}/{rel.as_posix()}"

    # ------------------------------------------------------------ scope gate

    def _enforce_scope(self, target_ip: str) -> None:
        """Empty-allowlist / unauthorized-target fail-closed gate.

        The invariant, enforced independently at this layer (on top of the MCP
        allowlist decorators and the real netns firewall): when
        ``exploit.require_explicit_allowlist`` is true, an execution naming a
        target outside the effective allowlist is DENIED before any container
        work happens; with an EMPTY allowlist, every target-touching execution
        is denied (and the netns policy authorizes nothing, so even a target-
        less command has zero reachable destinations).

        An empty ``target_ip`` (no destinations could be associated with the
        execution) is enforced by the firewall layer instead -- a target-less
        command cannot touch the target, and the netns policy authorizes only
        the (possibly empty) allowlist.
        """
        from tools.kernel.allowlist import _check_allowlist

        require = bool((self.config_dict or {}).get("exploit", {}).get("require_explicit_allowlist", False))
        if not require:
            return
        if not target_ip:
            return
        allowed, reason = _check_allowlist(target_ip, self.config_dict)
        if not allowed and self.cfg.allow_research_hosts and self._is_research_host(target_ip):
            # Pinned exploit-research egress (github/gitlab) is authorized by
            # the fixed RESEARCH_HOSTS set, not by the target allowlist.
            return
        if not allowed:
            raise SandboxScopeError(f"{reason} (sandbox scope gate)")

    @staticmethod
    def _is_research_host(token: str) -> bool:
        from tools.sandbox.policy import RESEARCH_HOSTS

        tok = str(token).strip().lower().rstrip(".")
        return any(tok == h or tok.endswith(f".{h}") for h in RESEARCH_HOSTS)

    def _build_env(self, extra: dict[str, str] | None) -> dict[str, str]:
        env = dict(_BASE_ENV)
        allowed = set(_RUN_ENV_ALLOWLIST) | set(self.cfg.env_passthrough)
        for key, value in (extra or {}).items():
            if key in allowed:
                env[str(key)] = str(value)
        return env

    # ------------------------------------------------------------ audit

    def _audit(
        self,
        *,
        target_ip: str,
        tool_name: str,
        status: str,
        command: str,
        extra_env: dict[str, str],
        policy_payload: dict[str, Any] | None,
        exit_code: int | None,
        duration: float | None,
    ) -> None:
        try:
            from tools.kernel.audit import _audit_log, _mask_secret_content

            extra: dict[str, Any] = {
                "sandbox": {
                    "enabled": self.cfg.enabled,
                    "backend": self.cfg.backend,
                    "run_id": self.run_id,
                    "container_id": self.container_id,
                    "image": self.cfg.image,
                    "user": self.cfg.user,
                    "env_keys": sorted(extra_env.keys()),
                    "network": policy_payload,
                    "exit_code": exit_code,
                    "timeout_seconds": self.cfg.exec_timeout_seconds,
                }
            }
            _audit_log(
                self.workspace / "exploit_audit.jsonl",
                target_ip=target_ip,
                tool_name=f"sandbox.{tool_name}" if tool_name else "sandbox.execute",
                approved=True,
                status=status,
                command=_mask_secret_content(command) if command else "",
                duration_seconds=duration or 0.0,
                extra=extra,
            )
        except Exception as exc:  # noqa: BLE001 -- audit is best-effort, never blocks the attack path
            logger.warning("sandbox audit row failed: %s", exc)

    def audit_cleanup(self, results: dict[str, bool]) -> None:
        self._audit(
            target_ip="",
            tool_name="cleanup",
            status="completed" if all(results.values()) else "failed",
            command="",
            extra_env={},
            policy_payload=None,
            exit_code=None,
            duration=None,
        )

    # -------------------------------------------------------- teardown

    def destroy(self) -> dict[str, bool]:
        """Terminate + remove the worker and its network. Idempotent; audited."""
        if self._destroyed:
            return {"container_removed": False, "network_removed": False}
        results = self._destroy_resources()
        self._destroyed = True
        self.audit_cleanup(results)
        return results

    def _destroy_resources(self) -> dict[str, bool]:
        results = {"container_removed": False, "network_removed": False}
        if self.container_id:
            try:
                self.backend.stop(self.container_id)
            except SandboxError:
                logger.warning("sandbox stop %s failed", self.container_id)
            results["container_removed"] = bool(
                self.backend.destroy(self.container_id, self.network_name)["container_removed"]
            )
        if self.network_name:
            results["network_removed"] = bool(_db.docker_network_rm(self.network_name))
        self.container_id = ""
        self.network_name = ""
        return results

    def _atexit_destroy(self) -> None:
        try:
            self.destroy()
        except Exception:  # noqa: BLE001 -- interpreter shutdown best-effort
            pass

    def cleanup_stale(self) -> int:
        """Remove exited NetAttackAI-labeled containers + empty labeled networks.

        Conservative by design: a RUNNING worker may belong to a concurrent
        session (``api.max_concurrent_runs`` > 1), so only containers that are
        NOT running -- and networks holding no running containers -- are removed.
        This manager's own container/network is always skipped.
        """
        removed = 0
        for name in _db.docker_container_list_stale():
            if name == self.container_id:
                continue
            if _db.docker_inspect_state(name) in ("exited", "created", "dead"):
                removed += 1 if _db.docker_rm(name) else 0
        for name in _db.docker_network_list_stale():
            if name == self.network_name:
                continue
            info = _db.docker_network_inspect(name)
            if not info:
                continue
            if not (info.get("Containers") or {}):
                removed += 1 if _db.docker_network_rm(name) else 0
        return removed

    def status(self) -> dict[str, Any]:
        state = self._container_state()
        return {
            "enabled": self.cfg.enabled,
            "backend": self.cfg.backend,
            "image": self.cfg.image,
            "user": self.cfg.user,
            "run_id": self.run_id,
            "container_id": self.container_id,
            "container_status": state,
            "network": self.network_name,
            "network_locked": bool(self._policy and self._policy.enforced),
            "network_policy_fingerprint": self._policy.fingerprint() if self._policy else "",
            "resources": {
                "memory_mb": self.cfg.memory_mb,
                "cpus": self.cfg.cpus,
                "pids": self.cfg.pids_limit,
                "timeout_seconds": self.cfg.exec_timeout_seconds,
            },
        }


def _clamp_output(text: str, max_bytes: int) -> str:
    """Keep the LAST ``max_bytes`` of one output stream (tails matter for
    debugging); never lets an agent command flood host-process memory."""
    if not text:
        return ""
    data = text.encode("utf-8", errors="replace")
    if len(data) <= max_bytes:
        return text
    return data[-max_bytes:].decode("utf-8", errors="replace") + "\n[output truncated to last N bytes]"


def status_report(config: dict[str, Any] | None) -> dict[str, Any]:
    """Static sandbox status for the WebUI API / doctor (no manager instance).

    Probing is seam-mediated and cheap; a status endpoint never throws --
    any probe failure surfaces as ``docker_error`` text, never an exception.
    """
    cfg = SandboxConfig.from_config(config)
    report: dict[str, Any] = {
        "enabled": cfg.enabled,
        "backend": cfg.backend,
        "image": cfg.image,
        "user": cfg.user,
        "read_only_rootfs": cfg.read_only_rootfs,
        "docker_available": False,
        "docker_error": "",
        "network": {
            "enforce": cfg.network_enforce,
            "fail_closed": cfg.network_fail_closed,
            "allow_dns": cfg.allow_dns,
            "map_host_loopback": cfg.map_host_loopback,
            "extra_allow_cidrs": cfg.extra_allow_cidrs,
        },
        "resources": {
            "memory_mb": cfg.memory_mb,
            "cpus": cfg.cpus,
            "pids": cfg.pids_limit,
            "timeout_seconds": cfg.exec_timeout_seconds,
            "output_max_bytes": cfg.output_max_bytes,
        },
        "cleanup": {"remove_on_exit": cfg.remove_on_exit, "remove_stale_on_startup": cfg.remove_stale_on_startup},
    }
    if not cfg.enabled:
        report["note"] = "sandbox disabled -- documented legacy host-execution mode"
        return report
    try:
        ok, reason = _db.docker_version()
        report["docker_available"] = ok
        if not ok:
            report["docker_error"] = reason
    except SandboxError as exc:
        report["docker_error"] = str(exc)
    return report
