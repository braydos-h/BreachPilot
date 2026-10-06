"""Flow A campaigns can only obtain recon through the MCP sandbox boundary."""

from __future__ import annotations

import json

import pytest

from tools.recon.config import HostReconResult, ServiceInfo
from tools.run_service.sandbox_recon import sandbox_recon_via_mcp


class FakeBridge:
    def __init__(self, run_result: str, artifact: str) -> None:
        self.run_result = run_result
        self.artifact = artifact
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def call_tool_on_loop(self, name: str, args: dict[str, str]) -> str:
        self.calls.append((name, args))
        return self.run_result if name == "run_full_recon" else self.artifact

    @staticmethod
    def _extract_text(result: str) -> str:
        return result


@pytest.mark.asyncio
async def test_flow_a_sandbox_recon_uses_target_checked_mcp_tool_and_workspace_artifact() -> None:
    expected = HostReconResult(
        target_ip="192.0.2.10",
        open_ports=[443],
        scan_tool="nmap-worker",
        services=[ServiceInfo(port=443, service="https")],
    )
    bridge = FakeBridge(
        "RECON_RESULT: completed\nRESOLVED_IP: 192.0.2.10\n"
        "SAVED_JSON: /run/workspace/attempts/attempt-abc/recon_result.json",
        json.dumps(expected.to_dict()),
    )

    result = await sandbox_recon_via_mcp(bridge, "192.0.2.10", aggression="normal")

    assert result.target_ip == expected.target_ip
    assert result.open_ports == [443]
    assert [service.service for service in result.services] == ["https"]
    assert bridge.calls == [
        ("run_full_recon", {"target_ip": "192.0.2.10", "aggression": "normal"}),
        ("read_workspace_file", {"filename": "/run/workspace/attempts/attempt-abc/recon_result.json"}),
    ]


@pytest.mark.asyncio
async def test_flow_a_sandbox_recon_fails_closed_on_worker_error() -> None:
    bridge = FakeBridge("ERROR: sandbox worker unavailable", "")

    with pytest.raises(RuntimeError, match="did not complete"):
        await sandbox_recon_via_mcp(bridge, "192.0.2.10")

    assert [name for name, _args in bridge.calls] == ["run_full_recon"]


@pytest.mark.asyncio
async def test_flow_a_sandbox_recon_rejects_unsafe_artifact_path() -> None:
    bridge = FakeBridge(
        "RECON_RESULT: completed\nRESOLVED_IP: 192.0.2.10\nSAVED_JSON: /etc/shadow",
        "{}",
    )

    with pytest.raises(RuntimeError, match="unsafe artifact path"):
        await sandbox_recon_via_mcp(bridge, "192.0.2.10")

    assert [name for name, _args in bridge.calls] == ["run_full_recon"]
