"""Proof-of-execution (PoE) compromise verifier.

A claimed compromise is only trusted once it has been independently verified
against the live target. This module implements the verification primitive used
by the self-verification core (Phase 1.3): given a ``tool_executor`` wired to
the target, it

1. writes a unique canary token to a temp file on the target filesystem,
2. reads the token back (proving real write+read on the target, not a stub),
3. collects identity probes (``id`` / ``whoami`` / ``hostname``) to classify
   the privilege level gained, and
4. returns a structured verdict dict.

The verifier is defensive by design: any executor failure (a ``BLOCKED:`` or
``TOOL_EXECUTION_ERROR:`` result, an exception, a missing token echo) collapses
to ``verified=False`` with the failure reason captured in ``evidence``. It
never raises into the caller -- a verification miss must not abort a campaign.

Executor contract
-----------------
``tool_executor`` is the sync ``Callable[[str, dict[str, Any]], str]`` shape
already used by ``tools.swarm_bridge.SwarmMcpBridge.dispatch`` and the
autonomous orchestrator's ``tool_executor`` callback: ``(tool_name, args) ->
result_text``. The verifier targets the ``run_exploit_terminal`` MCP tool, and
parses the ``OUTPUT:`` section that ``tools/mcp_tools/terminal.run_exploit_terminal``
appends to every successful result. Other result shapes (raw command output,
``TERMINAL_RESULT:`` framing) are tolerated -- the parser just looks for the
canary token anywhere in the returned text.

The async entry point (``verify_compromise``) offloads each sync executor call
to ``asyncio.to_thread`` so a blocking shell call does not stall the event
loop; a ``verify_compromise_sync`` helper is provided for non-async call sites
(the autonomous orchestrator's sync ``AttackModuleExecutor`` path).
"""

from __future__ import annotations

import asyncio
import re
import uuid
from typing import Any, Callable

__all__ = [
    "verify_compromise",
    "verify_compromise_sync",
    "classify_privilege",
    "extract_output",
]

# Executor type: sync (tool_name, args) -> result_text. Kept permissive so both
# the swarm bridge dispatch and bare callables fit.
ToolExecutor = Callable[..., Any]

# Result prefixes the executor may surface. Any result starting with these is
# treated as a verification failure (the command did not actually run on the
# target).
_BLOCK_MARKERS = ("BLOCKED:", "TOOL_EXECUTION_ERROR:", "ERROR:")

# Default per-executor-call timeout (seconds). The executor itself is
# responsible for honoring command timeouts; this is the outer asyncio shield.
_DEFAULT_TIMEOUT = 30

# Output section marker used by tools/mcp_tools/terminal.run_exploit_terminal.
_OUTPUT_MARKER = "OUTPUT:"


def _token_for(target_ip: str) -> tuple[str, str]:
    """Return ``(token, token_file_path)`` for the canary write.

    The token embeds the target IP and a uuid4 hex so it is unique per
    verification attempt and cannot be replayed from a stale shell banner.
    The file path targets ``/tmp`` (the common Kali-vs-Linux-target case);
    Windows-targeted sessions would need a ``%TEMP%`` path, but the verifier
    does not assume a target OS -- a write failure simply collapses to
    ``verified=False``.
    """
    token = f"PoE-{target_ip or 'unknown'}-{uuid.uuid4().hex}"
    filename = f"poe_{uuid.uuid4().hex}.txt"
    path = f"/tmp/{filename}"
    return token, path


def _is_blocked(result: Any) -> bool:
    if not isinstance(result, str):
        return False
    head = result.lstrip().upper()
    return any(head.startswith(m) for m in _BLOCK_MARKERS)


def extract_output(result: Any) -> str:
    """Pull the textual payload out of an executor result.

    Strips the ``OUTPUT:`` framing that ``run_exploit_terminal`` adds; if the
    marker is absent, the whole result text is returned (so the verifier also
    works against plain-shell executors that do not frame their output).
    """
    if result is None:
        return ""
    if not isinstance(result, str):
        # Some executors return dicts/objects; coerce to a string best-effort.
        try:
            return str(result)
        except Exception:
            return ""
    idx = result.find(_OUTPUT_MARKER)
    if idx >= 0:
        return result[idx + len(_OUTPUT_MARKER):]
    return result


def _run_executor(tool_executor: ToolExecutor, command: str, target_ip: str) -> str:
    """Invoke the sync executor once with ``run_exploit_terminal`` semantics.

    The executor contract is ``(tool_name, args_dict) -> result_text`` -- the
    same shape as ``SwarmMcpBridge.dispatch`` and the MCP ``ClientSession``
    surface. Callers whose tool_executor uses a different positional shape
    (e.g. the autonomous orchestrator's raw ``(cmd, {"target": ...})``
    callback) are expected to wrap it; the verifier is consumed by the
    orchestrator/swarm only in Phase 2, which owns that wiring.

    Never raises -- returns a ``TOOL_EXECUTION_ERROR:`` string on any failure
    so the caller can treat it as a blocked result.
    """
    args: dict[str, Any] = {"command": command, "target_ip": target_ip}
    try:
        result = tool_executor("run_exploit_terminal", args)
    except Exception as exc:  # noqa: BLE001 -- defensive, never raise
        return f"TOOL_EXECUTION_ERROR: {exc}"
    if result is None:
        return "TOOL_EXECUTION_ERROR: executor returned None"
    return result if isinstance(result, str) else str(result)


def classify_privilege(id_output: str, whoami_output: str = "") -> str:
    """Classify the privilege level from ``id`` / ``whoami`` output.

    Returns one of ``"root"``, ``"system"``, ``"user"``, or ``"unknown"``.
    Detection is intentionally simple and string-based so it works against
    shell output from either POSIX (``id``) or Windows (``whoami``) targets.
    """
    text = f"{id_output}\n{whoami_output}".strip().lower()
    if not text:
        return "unknown"
    # POSIX root: uid=0(...) or euid=0
    if re.search(r"uid=0\b", text) or "euid=0" in text:
        return "root"
    # Windows SYSTEM / TrustedInstaller
    if "nt authority\\system" in text or "system" == text.strip():
        return "system"
    if "trustedinstaller" in text:
        return "system"
    # Any non-empty identity that is not root/system is a regular user.
    return "user"


def _detect_shell_type(raw_output: str) -> str:
    """Best-effort shell-type hint from the raw probe output.

    The verifier only sees command output, not the session transport, so this
    is a coarse hint (``"shell"`` when commands clearly executed vs
    ``"unknown"``). A real meterpreter/shell distinction is left to the
    caller, which knows the session transport.
    """
    if not raw_output:
        return "unknown"
    # If we got structured POSIX id output, we have a real shell.
    if re.search(r"uid=\d+", raw_output) or re.search(r"\bgroups=\d+", raw_output):
        return "shell"
    return "shell" if raw_output.strip() else "unknown"


def _verify_sync(tool_executor: ToolExecutor, target_ip: str) -> dict[str, Any]:
    """Core sync verification logic shared by the async + sync entry points."""
    token, token_path = _token_for(target_ip)
    evidence: list[str] = []

    # 1. Canary write + immediate read-back in one shell call (atomic check).
    write_cmd = (
        f"echo '{token}' > '{token_path}' 2>/dev/null; "
        f"cat '{token_path}' 2>/dev/null; "
        f"echo '---ID---'; id 2>/dev/null; "
        f"whoami 2>/dev/null; hostname 2>/dev/null"
    )
    write_result = _run_executor(tool_executor, write_cmd, target_ip)
    if _is_blocked(write_result):
        evidence.append(f"canary write blocked: {write_result.strip()[:300]}")
        return {
            "verified": False,
            "evidence": evidence,
            "privilege": "unknown",
            "shell_type": "unknown",
            "token": token,
            "target_ip": target_ip,
        }

    raw_output = extract_output(write_result)
    evidence.append(f"probe output:\n{raw_output[:2000]}")

    # 2. Confirm the canary token echoed back (proves real write+read).
    if token not in raw_output:
        evidence.append(
            f"canary token '{token}' not echoed back -- write/read did not land on target"
        )
        return {
            "verified": False,
            "evidence": evidence,
            "privilege": "unknown",
            "shell_type": "unknown",
            "token": token,
            "target_ip": target_ip,
        }

    # 3. Parse identity probes for privilege classification.
    id_chunk = ""
    whoami_chunk = ""
    if "---ID---" in raw_output:
        _, after = raw_output.split("---ID---", 1)
        # `id` output is the first line after the marker; whoami/hostname follow.
        lines = [ln.strip() for ln in after.splitlines() if ln.strip()]
        if lines:
            id_chunk = lines[0]
        if len(lines) >= 2:
            whoami_chunk = lines[1]

    privilege = classify_privilege(id_chunk, whoami_chunk)
    shell_type = _detect_shell_type(raw_output)
    evidence.append(f"privilege={privilege} shell_type={shell_type}")
    evidence.append(f"id={id_chunk!r} whoami={whoami_chunk!r}")

    return {
        "verified": True,
        "evidence": evidence,
        "privilege": privilege,
        "shell_type": shell_type,
        "token": token,
        "target_ip": target_ip,
    }


def verify_compromise_sync(
    tool_executor: ToolExecutor,
    target_ip: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Synchronous PoE verification.

    Args:
        tool_executor: Sync ``Callable[[str, dict[str, Any]], str]`` -- the
            same shape as ``SwarmMcpBridge.dispatch`` / the orchestrator's
            ``tool_executor`` callback.
        target_ip: The target IP the compromise is claimed against.
        timeout: Advisory outer timeout (seconds). The sync path does not
            enforce it itself (the executor owns command timeouts); it is
            accepted for API symmetry with the async entry point.

    Returns:
        Dict with keys ``verified`` (bool), ``evidence`` (list[str]),
        ``privilege`` (str), ``shell_type`` (str), ``token`` (str),
        ``target_ip`` (str). Never raises.
    """
    if not target_ip or not callable(tool_executor):
        return {
            "verified": False,
            "evidence": ["missing target_ip or tool_executor"],
            "privilege": "unknown",
            "shell_type": "unknown",
            "token": "",
            "target_ip": target_ip or "",
        }
    try:
        return _verify_sync(tool_executor, target_ip)
    except Exception as exc:  # noqa: BLE001 -- never raise into the campaign
        return {
            "verified": False,
            "evidence": [f"verifier error: {exc}"],
            "privilege": "unknown",
            "shell_type": "unknown",
            "token": "",
            "target_ip": target_ip,
        }


async def verify_compromise(
    tool_executor: ToolExecutor,
    target_ip: str,
    *,
    timeout: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Async PoE verification.

    Offloads the blocking sync executor calls to a worker thread and shields
    the whole probe with an asyncio timeout. Returns the same dict shape as
    ``verify_compromise_sync``; never raises.
    """
    if not target_ip or not callable(tool_executor):
        return {
            "verified": False,
            "evidence": ["missing target_ip or tool_executor"],
            "privilege": "unknown",
            "shell_type": "unknown",
            "token": "",
            "target_ip": target_ip or "",
        }
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_verify_sync, tool_executor, target_ip),
            timeout=float(timeout),
        )
    except asyncio.TimeoutError:
        return {
            "verified": False,
            "evidence": [f"verification timed out after {timeout}s"],
            "privilege": "unknown",
            "shell_type": "unknown",
            "token": "",
            "target_ip": target_ip,
        }
    except Exception as exc:  # noqa: BLE001 -- never raise into the campaign
        return {
            "verified": False,
            "evidence": [f"verifier error: {exc}"],
            "privilege": "unknown",
            "shell_type": "unknown",
            "token": "",
            "target_ip": target_ip,
        }
