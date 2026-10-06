"""Regression test for the broken swarm recon path.

``tools/swarm/agents/recon_agent.py`` Stage 1 used to:
  * pass ``target=``/``ports=`` to ``ReconConfig`` (no such fields -> TypeError),
  * pass a 2nd positional (``tool_router``) to ``ReconPipeline.__init__(config)``
    (TypeError),
  * call ``pipeline.run()`` (only ``async recon_host`` exists -> AttributeError).

So the swarm's recon phase never ran. This test mocks the shared sandbox
adapter and asserts ``ReconAgent.run`` completes and emits the expected
enriched output / blackboard updates.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from tools.recon_pipeline import HostReconResult, ServiceInfo
from tools.swarm.agents.recon_agent import ReconAgent


def _fake_result() -> HostReconResult:
    return HostReconResult(
        target_ip="10.0.0.50",
        os_name="Ubuntu 22.04",
        os_family="linux",
        os_accuracy=95,
        services=[
            ServiceInfo(
                port=22,
                protocol="tcp",
                service="ssh",
                version="OpenSSH 8.9p1",
                banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
            ),
            ServiceInfo(port=445, protocol="tcp", service="microsoft-ds", version="Samba", banner=""),
            ServiceInfo(
                port=80, protocol="tcp", service="http", version="Apache/2.4.52", banner="Apache/2.4.52 (Ubuntu)"
            ),
        ],
        open_ports=[22, 80, 445],
        scan_tool="nmap",
        evidence_refs=["nmap:22", "nmap:80"],
    )


@pytest.mark.asyncio
async def test_recon_agent_uses_sandbox_recon_adapter() -> None:
    """ReconAgent must route through the scoped sandbox worker adapter."""
    agent = ReconAgent()
    task = {"task_id": "R-1", "target": "10.0.0.50"}
    tool_context = SimpleNamespace(sandbox=object())
    context = {"config": {}, "blackboard": {}, "stealth": False, "tool_context": tool_context}

    with patch(
        "tools.mcp_tools.recon.sandbox_recon_host",
        new_callable=AsyncMock,
        return_value=(_fake_result(), None),
    ) as mock_recon:
        result = agent.run(task, context)

    # The adapter receives the pinned worker context and target exactly once.
    assert mock_recon.await_count == 1
    assert mock_recon.await_args.args[:3] == (tool_context, "10.0.0.50", {})

    assert result.error == "", f"recon agent errored: {result.error}"
    out = result.output
    assert out["target"] == "10.0.0.50"
    # OS guess assembled from HostReconResult os_name/os_family/os_accuracy.
    assert out["os_guess"]["family"] == "linux"
    assert out["os_guess"]["name"] == "Ubuntu 22.04"
    # Services enriched from the HostReconResult.services list.
    assert len(out["services"]) == 3
    svc_names = {s["service"] for s in out["services"]}
    assert {"ssh", "microsoft-ds", "http"} == svc_names
    # Risk scoring applied.
    ssh = next(s for s in out["services"] if s["service"] == "ssh")
    assert ssh["risk_score"] >= 70
    # Banner tech fingerprinting populated the technologies list.
    assert any(t["name"] == "Apache" for t in out["technologies"])
    # Evidence refs forwarded.
    assert "nmap:22" in result.evidence_refs
    # Blackboard updated.
    assert context["blackboard"].get("recon_complete") is True
    assert context["blackboard"].get("attack_surface_score", 0) > 0


@pytest.mark.asyncio
async def test_recon_agent_stealth_flag_maps_to_sandbox_profile() -> None:
    """context['stealth']=True must map to the sandbox recon profile."""
    agent = ReconAgent()
    task = {"target": "10.0.0.50"}
    tool_context = SimpleNamespace(sandbox=object())
    context = {"config": {}, "blackboard": {}, "stealth": True, "tool_context": tool_context}

    with patch(
        "tools.mcp_tools.recon.sandbox_recon_host",
        new_callable=AsyncMock,
        return_value=(_fake_result(), None),
    ) as mock_recon:
        agent.run(task, context)

    assert mock_recon.await_args.kwargs["aggression"] == "stealth"


def test_recon_agent_fails_closed_without_sandbox_context() -> None:
    agent = ReconAgent()
    with patch(
        "tools.recon_pipeline.ReconPipeline.recon_host",
        new_callable=AsyncMock,
    ) as host_recon:
        result = agent.run({"target": "10.0.0.50"}, {"config": {}, "blackboard": {}})

    assert result.status.value == "failed"
    assert "refusing host-side reconnaissance" in result.error
    host_recon.assert_not_awaited()
