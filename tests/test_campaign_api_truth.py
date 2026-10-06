"""Campaign reporting must not mistake module names for compromised hosts."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from tools.campaign.orchestrator import AutonomousOrchestrator
from tools.campaign.state import AttackState
from tools.mcp_tools.modules.campaign import _compromised_hosts_for_state, _record_campaign_step_result
from tools.recon.config import HostReconResult


def test_campaign_report_excludes_claimed_success_without_verified_access() -> None:
    state = AttackState(target="example.test", resolved_ip="192.0.2.10")
    state.successful_exploits.append("SelfReportingModule")

    assert _compromised_hosts_for_state(state) == []


def test_campaign_report_uses_resolved_target_for_verified_access() -> None:
    state = AttackState(target="example.test", resolved_ip="192.0.2.10", access_achieved=True)

    assert _compromised_hosts_for_state(state) == ["192.0.2.10"]


def test_campaign_report_does_not_report_empty_target() -> None:
    state = AttackState(target="", resolved_ip="", access_achieved=True)

    assert _compromised_hosts_for_state(state) == []


def test_campaign_ids_are_unique_within_one_second(monkeypatch) -> None:
    import tools.mcp_tools.modules.campaign as campaign_module

    class FixedDatetime:
        @classmethod
        def now(cls, _tz):
            from datetime import datetime, timezone

            return datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(campaign_module, "datetime", FixedDatetime)
    first = campaign_module._new_campaign_id("192.0.2.10")
    second = campaign_module._new_campaign_id("192.0.2.10")

    assert first != second
    assert campaign_module._valid_campaign_id(first)
    assert campaign_module._valid_campaign_id(second)


def test_campaign_state_writer_creates_and_atomically_replaces_initial_state(tmp_path: Path) -> None:
    import tools.mcp_tools.modules.campaign as campaign_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    campaign_id = campaign_module._new_campaign_id("192.0.2.10")
    campaign_dir = campaign_module._create_campaign_dir(workspace, campaign_id)

    campaign_module._write_campaign_state(workspace, campaign_id, {"status": "started"})
    assert json.loads((campaign_dir / "state.json").read_text(encoding="utf-8")) == {"status": "started"}

    campaign_module._write_campaign_state(workspace, campaign_id, {"status": "completed"})
    assert json.loads((campaign_dir / "state.json").read_text(encoding="utf-8")) == {"status": "completed"}
    assert list(campaign_dir.glob(".state.json.*.tmp")) == []


def test_campaign_creation_rejects_symlinked_campaigns_directory(tmp_path: Path) -> None:
    import tools.mcp_tools.modules.campaign as campaign_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (workspace / "campaigns").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    campaign_id = campaign_module._new_campaign_id("192.0.2.10")
    with pytest.raises(OSError):
        campaign_module._create_campaign_dir(workspace, campaign_id)

    assert list(outside.iterdir()) == []


def test_generated_campaign_step_counts_completion_without_claiming_compromise() -> None:
    state = AttackState(target="192.0.2.20")
    state.successful_exploits.append("SelfReportingModule")
    state_data = {"tasks": {"completed": 1, "failed": 0}}

    _record_campaign_step_result(state, state_data, "script_generated")

    assert state_data["tasks"] == {"completed": 2, "failed": 0}
    assert state_data["compromised_hosts"] == []


def test_failed_campaign_step_does_not_add_a_compromised_host() -> None:
    state = AttackState(target="192.0.2.20")
    state_data = {"tasks": {"completed": 0, "failed": 0}}

    _record_campaign_step_result(state, state_data, "failed")

    assert state_data["tasks"] == {"completed": 0, "failed": 1}
    assert state_data["compromised_hosts"] == []


@pytest.mark.asyncio
async def test_campaign_recon_uses_injected_sandbox_provider(tmp_path: Path) -> None:
    recon = HostReconResult(target_ip="192.0.2.10", open_ports=[443], scan_tool="nmap-worker")
    provider = AsyncMock(return_value=recon)
    orchestrator = AutonomousOrchestrator(
        mission_config={"target": "192.0.2.10"},
        workspace_root=tmp_path,
        sandbox_recon_provider=provider,
        require_sandbox_recon=True,
    )
    host_recon = AsyncMock(side_effect=AssertionError("campaign used host ReconPipeline"))
    orchestrator._recon.recon_host = host_recon

    state = orchestrator.get_state("192.0.2.10")
    await orchestrator._phase_reconnaissance(state)

    provider.assert_awaited_once_with("192.0.2.10")
    host_recon.assert_not_awaited()
    assert state.recon_result is recon


@pytest.mark.asyncio
async def test_campaign_recon_fails_closed_without_sandbox_provider(tmp_path: Path) -> None:
    orchestrator = AutonomousOrchestrator(
        mission_config={"target": "192.0.2.10"},
        workspace_root=tmp_path,
        require_sandbox_recon=True,
    )
    host_recon = AsyncMock(side_effect=AssertionError("campaign used host ReconPipeline"))
    orchestrator._recon.recon_host = host_recon

    with pytest.raises(RuntimeError, match="requires the sandbox worker"):
        await orchestrator._phase_reconnaissance(orchestrator.get_state("192.0.2.10"))

    host_recon.assert_not_awaited()


@pytest.mark.asyncio
async def test_flow_context_forces_campaign_recon_provider(tmp_path: Path) -> None:
    from tools.campaign.runtime_context import require_sandbox_recon

    recon = HostReconResult(target_ip="192.0.2.10", open_ports=[443], scan_tool="nmap-worker")
    provider = AsyncMock(return_value=recon)
    with require_sandbox_recon(provider):
        orchestrator = AutonomousOrchestrator(
            mission_config={"target": "192.0.2.10"},
            workspace_root=tmp_path,
        )
    host_recon = AsyncMock(side_effect=AssertionError("Flow A campaign used host ReconPipeline"))
    orchestrator._recon.recon_host = host_recon

    await orchestrator._phase_reconnaissance(orchestrator.get_state("192.0.2.10"))

    provider.assert_awaited_once_with("192.0.2.10")
    host_recon.assert_not_awaited()


@pytest.mark.asyncio
async def test_campaign_provider_uses_shared_sandbox_recon_adapter(monkeypatch) -> None:
    import tools.mcp_tools.recon as recon_module
    from tools.mcp_tools.modules.campaign import _make_sandbox_recon_provider

    tool_context = SimpleNamespace(sandbox=object())
    expected = HostReconResult(target_ip="192.0.2.10", open_ports=[443])
    calls: list[tuple[object, str, dict, str]] = []

    async def fake_adapter(ctx, target, config, *, aggression):
        calls.append((ctx, target, config, aggression))
        return expected, None

    monkeypatch.setattr(recon_module, "sandbox_recon_host", fake_adapter)
    provider = _make_sandbox_recon_provider(tool_context, {"recon": {"timeout_seconds": 20}}, "stealth")

    result = await provider("192.0.2.10")

    assert result is expected
    assert calls == [(tool_context, "192.0.2.10", {"recon": {"timeout_seconds": 20}}, "stealth")]


def _campaign_server(workspace: Path):
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    config = {
        "exploit": {
            "allowed_targets": ["192.0.2.10"],
            "require_explicit_allowlist": True,
        }
    }
    return create_mcp_server(
        ExploitSearch(ExploitSearchSettings(enabled=False)),
        NVDClient(CVESearchSettings(enabled=False)),
        WebResearcher(WebResearcherSettings(enabled=False)),
        workspace,
        config,
    )


def _tool_text(result) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    return "".join(getattr(part, "text", "") for part in content)


@pytest.mark.asyncio
async def test_run_campaign_step_rejects_campaign_id_path_traversal(tmp_path: Path, monkeypatch) -> None:
    import tools.mcp_tools.modules.campaign as campaign_module

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_state = outside_dir / "state.json"
    original = json.dumps({"target": "192.0.2.10", "status": "running"})
    outside_state.write_text(original, encoding="utf-8")

    monkeypatch.setattr(
        campaign_module,
        "_make_sandbox_recon_provider",
        lambda *_args: (_ for _ in ()).throw(AssertionError("path traversal reached recon")),
    )
    mcp = _campaign_server(tmp_path / "workspace")

    result = await mcp.call_tool("run_campaign_step", {"campaign_id": "../../outside"})

    assert _tool_text(result) == "ERROR: Invalid campaign_id or unsafe campaign state path."
    assert outside_state.read_text(encoding="utf-8") == original


@pytest.mark.asyncio
async def test_run_campaign_step_rejects_symlinked_state_file(tmp_path: Path, monkeypatch) -> None:
    import tools.mcp_tools.modules.campaign as campaign_module

    campaign_id = "campaign-20261005_120000-abcdef12"
    campaign_dir = tmp_path / "workspace" / "campaigns" / campaign_id
    campaign_dir.mkdir(parents=True)
    outside_state = tmp_path / "outside-state.json"
    original = json.dumps({"target": "192.0.2.10", "status": "running"})
    outside_state.write_text(original, encoding="utf-8")
    try:
        (campaign_dir / "state.json").symlink_to(outside_state)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    monkeypatch.setattr(
        campaign_module,
        "_make_sandbox_recon_provider",
        lambda *_args: (_ for _ in ()).throw(AssertionError("symlinked state reached recon")),
    )
    mcp = _campaign_server(tmp_path / "workspace")

    result = await mcp.call_tool("run_campaign_step", {"campaign_id": campaign_id})

    assert _tool_text(result) == "ERROR: Invalid campaign_id or unsafe campaign state path."
    assert (campaign_dir / "state.json").is_symlink()
    assert outside_state.read_text(encoding="utf-8") == original


@pytest.mark.asyncio
async def test_run_campaign_step_rejects_symlinked_campaign_directory(tmp_path: Path, monkeypatch) -> None:
    import tools.mcp_tools.modules.campaign as campaign_module

    campaign_id = "campaign-20261005_120000-abcdef12"
    workspace = tmp_path / "workspace"
    (workspace / "campaigns").mkdir(parents=True)
    outside_dir = tmp_path / "outside-campaign"
    outside_dir.mkdir()
    outside_state = outside_dir / "state.json"
    original = json.dumps({"target": "192.0.2.10", "status": "running"})
    outside_state.write_text(original, encoding="utf-8")
    try:
        (workspace / "campaigns" / campaign_id).symlink_to(outside_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    monkeypatch.setattr(
        campaign_module,
        "_make_sandbox_recon_provider",
        lambda *_args: (_ for _ in ()).throw(AssertionError("symlinked campaign directory reached recon")),
    )
    mcp = _campaign_server(workspace)

    result = await mcp.call_tool("run_campaign_step", {"campaign_id": campaign_id})

    assert _tool_text(result) == "ERROR: Invalid campaign_id or unsafe campaign state path."
    assert (workspace / "campaigns" / campaign_id).is_symlink()
    assert outside_state.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("tool_name", ["get_campaign_status", "stop_campaign"])
@pytest.mark.asyncio
async def test_campaign_status_and_stop_reject_path_traversal(tmp_path: Path, tool_name: str) -> None:
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_state = outside_dir / "state.json"
    original = json.dumps({"target": "192.0.2.10", "status": "running"})
    outside_state.write_text(original, encoding="utf-8")
    mcp = _campaign_server(tmp_path / "workspace")

    result = await mcp.call_tool(tool_name, {"campaign_id": "../../outside"})

    assert _tool_text(result) == "ERROR: Invalid campaign_id or unsafe campaign state path."
    assert outside_state.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("tool_name", ["get_campaign_status", "stop_campaign"])
@pytest.mark.asyncio
async def test_campaign_status_and_stop_reject_symlinked_state_file(tmp_path: Path, tool_name: str) -> None:
    campaign_id = "campaign-20261005_120000-abcdef12"
    campaign_dir = tmp_path / "workspace" / "campaigns" / campaign_id
    campaign_dir.mkdir(parents=True)
    outside_state = tmp_path / "outside-state.json"
    original = json.dumps({"target": "192.0.2.10", "status": "running"})
    outside_state.write_text(original, encoding="utf-8")
    try:
        (campaign_dir / "state.json").symlink_to(outside_state)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    mcp = _campaign_server(tmp_path / "workspace")

    result = await mcp.call_tool(tool_name, {"campaign_id": campaign_id})

    assert _tool_text(result) == "ERROR: Invalid campaign_id or unsafe campaign state path."
    assert (campaign_dir / "state.json").is_symlink()
    assert outside_state.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("tool_name", ["get_campaign_status", "stop_campaign"])
@pytest.mark.asyncio
async def test_campaign_status_and_stop_reject_symlinked_campaign_directory(tmp_path: Path, tool_name: str) -> None:
    campaign_id = "campaign-20261005_120000-abcdef12"
    workspace = tmp_path / "workspace"
    (workspace / "campaigns").mkdir(parents=True)
    outside_dir = tmp_path / "outside-campaign"
    outside_dir.mkdir()
    outside_state = outside_dir / "state.json"
    original = json.dumps({"target": "192.0.2.10", "status": "running"})
    outside_state.write_text(original, encoding="utf-8")
    try:
        (workspace / "campaigns" / campaign_id).symlink_to(outside_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    mcp = _campaign_server(workspace)

    result = await mcp.call_tool(tool_name, {"campaign_id": campaign_id})

    assert _tool_text(result) == "ERROR: Invalid campaign_id or unsafe campaign state path."
    assert (workspace / "campaigns" / campaign_id).is_symlink()
    assert outside_state.read_text(encoding="utf-8") == original
