from __future__ import annotations

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
        "start_tmux_session",
        "start_background_job",
        "start_listener",
    }

    assert expected <= names
