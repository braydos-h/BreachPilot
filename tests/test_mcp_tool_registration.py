from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_exploit_mcp_registers_expected_core_tools(tmp_path: Path) -> None:
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    mcp = create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        {
            "exploit": {"require_explicit_allowlist": False},
            "skills": {"enabled": True, "allow_model_lookup": True},
            "multi_model": {"enabled": True},
            "models": {
                "default_alias": "glm",
                "registry": {
                    "glm": {"provider": "ollama", "model": "glm"},
                    "kimi": {"provider": "ollama", "model": "kimi"},
                },
            },
        },
    )

    names = {tool.name for tool in await mcp.list_tools()}

    expected = {
        "run_exploit_terminal",
        "write_python_file",
        "run_python_file",
        "read_workspace_file",
        "list_workspace",
        "search_exploit_db",
        "search_web_exploit",
        "fetch_webpage",
        "deep_research",
        "search_cve_intel",
        "list_runtime_skills",
        "search_runtime_skills",
        "load_runtime_skill",
        "consult_peer_models",
        "run_msf_module",
        "msfconsole_start",
        "msf_run_exploit",
        "cred_store_add",
        "cred_store_get",
        "cred_store_list",
        "cred_store_confirm",
        "generate_payload",
        "lateral_exec",
        "dump_credentials",
        "kerberoast",
        "run_web_scan",
        "run_hash_crack",
        "check_os",
        "quick_scan",
        "run_full_recon",
        "get_service_fingerprint",
        "list_attack_modules",
        "run_attack_module",
        "create_attack_plan",
        "start_autonomous_campaign",
        "get_campaign_status",
        "run_campaign_step",
        "stop_campaign",
        "start_tmux_session",
        "start_background_job",
        "start_listener",
    }

    assert expected <= names


def test_exploit_server_passes_host_telemetry_path_to_sandbox_manager(tmp_path: Path, monkeypatch) -> None:
    from types import SimpleNamespace

    import tools.sandbox
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    captured: dict[str, object] = {}
    manager = SimpleNamespace(cfg=SimpleNamespace(remove_stale_on_startup=False))

    def _resolve(workspace, config, *, network_telemetry_path=None, audit_path=None):
        captured["path"] = network_telemetry_path
        captured["audit_path"] = audit_path
        return manager, ""

    monkeypatch.setattr(tools.sandbox, "resolve_manager_with_fallback", _resolve)
    telemetry_path = tmp_path / "network-scope.json"
    create_mcp_server(
        ExploitSearch(ExploitSearchSettings(enabled=False)),
        NVDClient(CVESearchSettings(enabled=False)),
        WebResearcher(WebResearcherSettings(enabled=False)),
        tmp_path / "workspace",
        {"exploit": {"require_explicit_allowlist": False}},
        network_telemetry_path=telemetry_path,
    )

    assert captured["path"] == telemetry_path
    assert captured["audit_path"] is not None
    assert captured["audit_path"] != tmp_path / "workspace" / "exploit_audit.jsonl"
    assert captured["audit_path"].parent == tmp_path


@pytest.mark.asyncio
async def test_exploit_server_writes_mcp_audit_outside_worker_workspace(tmp_path: Path, monkeypatch) -> None:
    from types import SimpleNamespace

    import tools.sandbox
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    manager = SimpleNamespace(cfg=SimpleNamespace(remove_stale_on_startup=False))
    monkeypatch.setattr(
        tools.sandbox,
        "resolve_manager_with_fallback",
        lambda workspace, config, **kwargs: (manager, ""),
    )
    workspace = tmp_path / "worker-workspace"
    audit_path = tmp_path / "reports" / "exploit_audit.jsonl"
    mcp = create_mcp_server(
        ExploitSearch(ExploitSearchSettings(enabled=False)),
        NVDClient(CVESearchSettings(enabled=False)),
        WebResearcher(WebResearcherSettings(enabled=False)),
        workspace,
        {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.50"]}},
        audit_path=audit_path,
    )

    assert audit_path.is_file(), "the canonical audit file is prepared before a worker can start"
    assert audit_path != workspace / "exploit_audit.jsonl"
    await mcp.call_tool("get_evidence", {"target_ip": "10.0.0.50"})

    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    assert any(row.get("tool_name") == "get_evidence" for row in rows)
    assert not (workspace / "exploit_audit.jsonl").exists()


def test_invalid_sandbox_network_config_prevents_attack_server_start(tmp_path: Path) -> None:
    """Invalid sandbox policy must fail before attack tools can register."""
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    with pytest.raises(ValueError, match="network.enforce=false is unsafe"):
        create_mcp_server(
            ExploitSearch(ExploitSearchSettings(enabled=False)),
            NVDClient(CVESearchSettings(enabled=False)),
            WebResearcher(WebResearcherSettings(enabled=False)),
            tmp_path,
            {
                "sandbox": {"enabled": True, "network": {"enforce": False}},
                "exploit": {"require_explicit_allowlist": False},
            },
        )
