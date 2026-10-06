"""Typed sandbox recon adapter for the active run-service MCP session."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Protocol

from tools.recon.config import HostReconResult

_RESOLVED_IP = re.compile(r"^RESOLVED_IP:\s*(\S+)\s*$", re.MULTILINE)
_SAVED_JSON = re.compile(r"^SAVED_JSON:\s*(\S+)\s*$", re.MULTILINE)


class _MCPBridge(Protocol):
    async def call_tool_on_loop(self, name: str, args: dict[str, str]) -> Any: ...

    def _extract_text(self, result: Any) -> str: ...


async def sandbox_recon_via_mcp(
    bridge: _MCPBridge,
    target: str,
    *,
    aggression: str = "normal",
) -> HostReconResult:
    """Run the registered sandbox-only recon tool and load its typed artifact.

    `run_full_recon` performs allowlist validation, DNS pinning, worker
    execution, and audit logging inside the MCP server. Its artifact is read
    back only through the workspace-contained file tool. Every malformed or
    unavailable result raises so campaign construction fails closed.
    """
    run_result = await bridge.call_tool_on_loop(
        "run_full_recon",
        {"target_ip": target, "aggression": aggression},
    )
    run_text = bridge._extract_text(run_result)
    if "RECON_RESULT: completed" not in run_text:
        raise RuntimeError(f"sandbox recon did not complete: {run_text[:500]}")
    resolved_match = _RESOLVED_IP.search(run_text)
    artifact_match = _SAVED_JSON.search(run_text)
    if resolved_match is None or artifact_match is None:
        raise RuntimeError("sandbox recon response omitted its resolved target or artifact path")

    try:
        resolved_ip = str(ipaddress.ip_address(resolved_match.group(1)))
    except ValueError as exc:
        raise RuntimeError("sandbox recon returned an invalid resolved address") from exc
    artifact_path = Path(artifact_match.group(1))
    if (
        not artifact_path.is_absolute()
        or artifact_path.name != "recon_result.json"
        or not artifact_path.parent.name.startswith("attempt-")
        or ".." in artifact_path.parts
    ):
        raise RuntimeError("sandbox recon returned an unsafe artifact path")

    artifact_result = await bridge.call_tool_on_loop(
        "read_workspace_file",
        {"filename": str(artifact_path)},
    )
    artifact_text = bridge._extract_text(artifact_result)
    try:
        artifact = json.loads(artifact_text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("sandbox recon artifact was unavailable or invalid JSON") from exc
    if not isinstance(artifact, dict):
        raise RuntimeError("sandbox recon artifact was not a JSON object")
    recon = HostReconResult.from_dict(artifact)
    if recon.target_ip != resolved_ip or recon.scan_tool != "nmap-worker":
        raise RuntimeError("sandbox recon artifact did not match the resolved target and worker scanner")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in recon.open_ports + recon.filtered_ports):
        raise RuntimeError("sandbox recon artifact contained invalid port data")
    return recon
