"""Atomic Red Team plugin — maps discovered weaknesses to MITRE ATT&CK test YAML.

Generates Atomic Red Team test YAML from a run's findings so the operator can
validate their SIEM/IDS/EDR detection coverage. **Local-only YAML generation**
— this plugin does NOT execute the tests. If a future variant executes them
against a live target, it MUST switch to ``@require_allowlist()``.

The single MCP tool ``generate_atomic_tests`` is ``@audit_tool``-decorated
(local YAML generation from the run's findings; no target touch). It takes a
list of findings (CVE / service / vuln strings) and returns Atomic-Red-Team-
formatted YAML referencing the mapped technique + test.

Safety (lab build): plugin is ON by default. Local-only YAML generation
(``@audit_tool`` — no target touch, no execution).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


# Static mapping of common weakness → MITRE ATT&CK technique + Atomic test.
# ponytail: a small static table covers the common cases. A full mapping would
# fetch the Atomic Red Team repo at config time; this vendored subset keeps the
# plugin stdlib-only and testable offline. Add rows as needed.
_TECHNIQUE_MAP: dict[str, dict[str, str]] = {
    "sqli": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "atomic_test": "T1190-1 Web Shell",
        "platform": "linux",
    },
    "xss": {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter - JavaScript",
        "atomic_test": "T1059.007-1 JavaScript execution",
        "platform": "windows",
    },
    "command_injection": {
        "technique_id": "T1059.004",
        "technique_name": "Command and Scripting Interpreter - Unix Shell",
        "atomic_test": "T1059.004-1 Shell command",
        "platform": "linux",
    },
    "weak_credentials": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force - Password Guessing",
        "atomic_test": "T1110.001-1 Password guessing",
        "platform": "linux",
    },
    "default_credentials": {
        "technique_id": "T1078.001",
        "technique_name": "Valid Accounts - Default Accounts",
        "atomic_test": "T1078.001-1 Default account login",
        "platform": "linux",
    },
    "open_smb": {
        "technique_id": "T1021.002",
        "technique_name": "Remote Services - SMB/Windows Admin Shares",
        "atomic_test": "T1021.002-1 SMB exec",
        "platform": "windows",
    },
    "open_ssh": {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services - SSH",
        "atomic_test": "T1021.004-1 SSH login",
        "platform": "linux",
    },
    "exposed_service": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "atomic_test": "T1046-1 Port scan",
        "platform": "linux",
    },
}


def map_finding_to_technique(finding: str) -> dict[str, str] | None:
    """Map a finding string (sqli/xss/weak_credentials/...) to a technique dict.

    Returns None when no mapping exists. Case-insensitive substring match,
    normalizing common separators (``_``/``-``/`` ``) so ``sql_injection``
    matches ``sqli`` and ``command-injection`` matches ``command_injection``.
    """
    f = (finding or "").lower().strip()
    if not f:
        return None
    # Direct key match first.
    if f in _TECHNIQUE_MAP:
        return _TECHNIQUE_MAP[f]
    # Normalized substring match: strip separators so "sql_injection" → "sqlinjection"
    # and "sqli" → "sqli"; then check if the key is a substring of the normalized
    # finding OR the finding is a substring of the key.
    normalized = f.replace("_", "").replace("-", "").replace(" ", "")
    for key, tech in _TECHNIQUE_MAP.items():
        norm_key = key.replace("_", "").replace("-", "").replace(" ", "")
        if norm_key in normalized or normalized in norm_key:
            return tech
    return None


def generate_atomic_yaml(findings: list[str]) -> str:
    """Generate Atomic Red Team test YAML from a list of finding strings.

    Returns a YAML-formatted string mapping each finding to its ATT&CK technique
    + atomic test. Findings with no mapping are listed as ``unmapped``. This is
    local-only generation — the YAML is text, never executed by this plugin.
    """
    lines: list[str] = ["atomic_tests:"]
    unmapped: list[str] = []
    seen_techniques: set[str] = set()
    for finding in findings:
        tech = map_finding_to_technique(finding)
        if tech is None:
            unmapped.append(finding)
            continue
        tid = tech["technique_id"]
        if tid in seen_techniques:
            continue
        seen_techniques.add(tid)
        lines.extend([
            f"  - technique_id: {tid}",
            f"    technique_name: {tech['technique_name']}",
            f"    atomic_test: {tech['atomic_test']}",
            f"    platform: {tech['platform']}",
            f"    source_finding: {finding}",
        ])
    if unmapped:
        lines.append("unmapped_findings:")
        for u in unmapped:
            lines.append(f"  - {u}")
    lines.append(f"total_findings: {len(findings)}")
    lines.append(f"mapped: {len(seen_techniques)}")
    lines.append(f"unmapped: {len(unmapped)}")
    return "\n".join(lines) + "\n"


class AtomicRedTeamPlugin(Plugin):
    """Plugin that registers the ``generate_atomic_tests`` MCP tool."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore
        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        def register_mcp_tools(mcp: Any, ctx: Any) -> None:
            audit_tool = ctx.audit_tool

            @mcp.tool()
            @audit_tool
            def generate_atomic_tests(findings: str) -> str:
                """Generate Atomic Red Team test YAML from a comma-separated list of findings.

                Local-only YAML generation — does NOT execute the tests. Maps
                each finding (sqli, xss, weak_credentials, open_ssh, ...) to its
                MITRE ATT&CK technique + atomic test. Use the output to validate
                detection coverage on the operator's own SIEM/IDS/EDR.
                """
                finding_list = [f.strip() for f in (findings or "").split(",") if f.strip()]
                if not finding_list:
                    return "ERROR: no findings provided. Pass a comma-separated list."
                yaml_text = generate_atomic_yaml(finding_list)
                return f"ATOMIC_TESTS_YAML:\n{yaml_text}"

        registry.register_mcp_tools(register_mcp_tools)


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return AtomicRedTeamPlugin()
