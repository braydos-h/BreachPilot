"""Tests for the Atomic Red Team plugin (D5).

The plugin generates Atomic Red Team test YAML from a run's findings. It is
``@audit_tool``-decorated (local YAML generation; no target touch, no
execution). Default-off (plugin.yaml ``enabled: false``).
"""

from __future__ import annotations

from plugins.atomic_red_team.plugin import (
    AtomicRedTeamPlugin,
    generate_atomic_yaml,
    map_finding_to_technique,
)

# ── map_finding_to_technique ─────────────────────────────────────────────────


def test_map_sqli():
    t = map_finding_to_technique("sqli")
    assert t is not None
    assert t["technique_id"] == "T1190"


def test_map_xss():
    t = map_finding_to_technique("xss")
    assert t is not None
    assert t["technique_id"].startswith("T1059")


def test_map_weak_credentials():
    t = map_finding_to_technique("weak_credentials")
    assert t is not None
    assert t["technique_id"].startswith("T1110")


def test_map_default_credentials():
    t = map_finding_to_technique("default_credentials")
    assert t is not None
    assert t["technique_id"].startswith("T1078")


def test_map_open_ssh():
    t = map_finding_to_technique("open_ssh")
    assert t is not None
    assert t["technique_id"].startswith("T1021")


def test_map_substring_match():
    """'sql_injection' should match 'sqli' via substring."""
    t = map_finding_to_technique("sql_injection")
    assert t is not None
    assert t["technique_id"] == "T1190"


def test_map_unknown_returns_none():
    assert map_finding_to_technique("unknown_vuln") is None


def test_map_empty_returns_none():
    assert map_finding_to_technique("") is None


def test_map_case_insensitive():
    t = map_finding_to_technique("SQLI")
    assert t is not None
    assert t["technique_id"] == "T1190"


# ── generate_atomic_yaml ─────────────────────────────────────────────────────


def test_generate_yaml_has_atomic_tests_section():
    yaml = generate_atomic_yaml(["sqli", "xss"])
    assert "atomic_tests:" in yaml
    assert "T1190" in yaml
    assert "T1059.007" in yaml


def test_generate_yaml_dedupes_techniques():
    """Two findings that map to the same technique produce one entry."""
    yaml = generate_atomic_yaml(["sqli", "sqli"])
    # Count technique_id: lines (T1190 also appears in atomic_test name).
    technique_lines = [line for line in yaml.splitlines() if "technique_id:" in line]
    assert len(technique_lines) == 1
    assert "T1190" in technique_lines[0]


def test_generate_yaml_unmapped_findings_listed():
    yaml = generate_atomic_yaml(["sqli", "totally_unknown"])
    assert "unmapped_findings:" in yaml
    assert "totally_unknown" in yaml


def test_generate_yaml_totals():
    yaml = generate_atomic_yaml(["sqli", "xss", "unknown1"])
    assert "total_findings: 3" in yaml
    assert "mapped: 2" in yaml
    assert "unmapped: 1" in yaml


def test_generate_yaml_empty_findings():
    yaml = generate_atomic_yaml([])
    assert "total_findings: 0" in yaml
    assert "mapped: 0" in yaml


def test_generate_yaml_includes_source_finding():
    yaml = generate_atomic_yaml(["sqli"])
    assert "source_finding: sqli" in yaml


# ── Plugin manifest + factory ────────────────────────────────────────────────


def test_plugin_factory():
    p = AtomicRedTeamPlugin()
    assert p.manifest.name == "atomic_red_team"
    assert p.manifest.enabled is True  # lab build default


def test_plugin_manifest_has_capabilities():
    p = AtomicRedTeamPlugin()
    assert "mcp_tool" in p.manifest.capabilities


# ── The MCP tool is @audit_tool (no target touch, no execution) ──────────────


def test_generate_atomic_tests_no_execution(tmp_path):
    """The plugin's MCP tool generates YAML text only — no subprocess, no network."""
    from plugins.atomic_red_team.plugin import generate_atomic_yaml as _gen

    yaml = _gen(["sqli", "weak_credentials"])
    # The output is pure YAML text — no command, no subprocess call, no target.
    assert isinstance(yaml, str)
    assert "atomic_tests:" in yaml
    assert "T1190" in yaml
    assert "T1110.001" in yaml
