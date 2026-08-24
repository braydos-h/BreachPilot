"""Tests for phase-aware tool catalog narrowing + schema validation."""

from __future__ import annotations

from tools.exploit_agent.tool_catalog import (
    PHASE_TOOL_FAMILIES,
    select_tools_for_phase,
    validate_tool_call,
)


def _schema(name, params=None):
    return {"type": "function", "function": {"name": name, "parameters": params or {}}}


def _tools(*names):
    return [_schema(n) for n in names]


# ── select_tools_for_phase ──────────────────────────────────────────────────


def test_recon_phase_keeps_recon_and_universal_drops_exploit():
    all_tools = _tools(
        "check_os",
        "quick_scan",
        "run_full_recon",  # recon
        "run_exploit_terminal",
        "write_python_file",  # universal
        "run_msf_module",
        "generate_payload",  # exploit
        "dump_credentials",  # post-exploit
    )
    selected = select_tools_for_phase(all_tools, "recon")
    names = {t["function"]["name"] for t in selected}
    assert "quick_scan" in names
    assert "run_exploit_terminal" in names  # universal
    assert "run_msf_module" not in names  # exploit dropped in recon
    assert "dump_credentials" not in names


def test_validation_phase_keeps_exploit_drops_recon():
    all_tools = _tools(
        "check_os",
        "quick_scan",
        "run_full_recon",
        "run_msf_module",
        "generate_payload",
        "run_python_file",
    )
    selected = select_tools_for_phase(all_tools, "validation")
    names = {t["function"]["name"] for t in selected}
    assert "run_msf_module" in names
    assert "run_python_file" in names
    assert "quick_scan" not in names
    assert "run_full_recon" not in names


def test_universal_set_always_kept():
    for phase in PHASE_TOOL_FAMILIES:
        all_tools = _tools("read_workspace_file", "list_workspace")
        selected = select_tools_for_phase(all_tools, phase)
        names = {t["function"]["name"] for t in selected}
        assert "read_workspace_file" in names
        assert "list_workspace" in names


def test_hidden_control_plane_tools_dropped():
    all_tools = _tools(
        "run_exploit_terminal",  # universal
        "create_attack_plan",  # hidden
        "replan",  # hidden
        "start_autonomous_campaign",  # hidden
    )
    for phase in PHASE_TOOL_FAMILIES:
        selected = select_tools_for_phase(all_tools, phase)
        names = {t["function"]["name"] for t in selected}
        assert "create_attack_plan" not in names
        assert "replan" not in names
        assert "start_autonomous_campaign" not in names


def test_available_mcp_names_filter_applied():
    all_tools = _tools("check_os", "quick_scan", "run_full_recon")
    # Only check_os is registered on the live MCP session.
    selected = select_tools_for_phase(all_tools, "recon", available_mcp_names={"check_os"})
    names = {t["function"]["name"] for t in selected}
    assert names == {"check_os"}


def test_empty_filtered_set_falls_back_to_full():
    """Never hand the model an empty tool list."""
    all_tools = _tools("dump_credentials")  # post-exploit only
    selected = select_tools_for_phase(all_tools, "recon")
    assert len(selected) >= 1  # fallback returns the full list


def test_unknown_phase_returns_full():
    all_tools = _tools("check_os", "run_msf_module")
    selected = select_tools_for_phase(all_tools, "unknown_phase")
    assert len(selected) == 2


# ── validate_tool_call ──────────────────────────────────────────────────────


def _schema_with_required(name, required, properties=None):
    params = {"required": required, "type": "object"}
    if properties:
        params["properties"] = properties
    return {"type": "function", "function": {"name": name, "parameters": params}}


def test_missing_required_field_returns_error():
    schema = _schema_with_required("run_exploit_terminal", ["command"])
    err = validate_tool_call("run_exploit_terminal", {}, [schema])
    assert err is not None
    assert "command" in err


def test_present_required_passes():
    schema = _schema_with_required("run_exploit_terminal", ["command"])
    assert validate_tool_call("run_exploit_terminal", {"command": "id"}, [schema]) is None


def test_wrong_type_returns_error():
    schema = _schema_with_required(
        "quick_scan",
        ["target_ip"],
        {"target_ip": {"type": "string"}, "ports": {"type": "string"}},
    )
    err = validate_tool_call("quick_scan", {"target_ip": "10.0.0.5", "ports": 22}, [schema])
    assert err is not None
    assert "ports" in err
    assert "string" in err


def test_enum_violation_returns_error():
    schema = _schema_with_required(
        "run_msf_module",
        ["module"],
        {"module": {"type": "string", "enum": ["exploit/windows/smb/ms17_010", "auxiliary/scanner/smb/smb_version"]}},
    )
    err = validate_tool_call("run_msf_module", {"module": "bogus/module"}, [schema])
    assert err is not None
    assert "enum" in err or "one of" in err


def test_valid_call_returns_none():
    schema = _schema_with_required(
        "quick_scan",
        ["target_ip"],
        {"target_ip": {"type": "string"}, "ports": {"type": "string"}},
    )
    assert validate_tool_call("quick_scan", {"target_ip": "10.0.0.5", "ports": "22,80"}, [schema]) is None


def test_empty_args_with_no_required_passes():
    schema = _schema_with_required("list_workspace", [])
    assert validate_tool_call("list_workspace", {}, [schema]) is None


def test_unknown_schema_returns_none():
    """Can't validate against a missing schema -- accept (don't over-reject)."""
    assert validate_tool_call("nonexistent", {"x": 1}, []) is None
