"""Dynamic composition: swarm agents emit milestone-gated, capability-aware
new_tasks.

Regression coverage for the three light touches that wire the existing
``route_parallel`` milestone mechanism onto the agents that actually produce
tasks, plus the capability-metadata handoff:

1. ``recon_agent`` analysis-phase new_tasks carry ``depends_on=[target,"recon"]``
   so route_parallel's milestone gating engages (the mechanism existed but no
   producer set depends_on).
2. ``vuln_agent`` exploit-phase new_tasks carry ``depends_on=[target,"analysis"]``
   and ``vulnerability_hypotheses`` entries include a ``prerequisite`` field
   derived from the matched module's ``requires``.
3. ``reflection_agent`` maps ``FailureClass`` onto the reflection prompt's
   root-cause labels so the LLM reflection can name a structured class when
   one is known.

Plain-dict blackboard, dummy agents, no live targets — mirrors the existing
``test_swarm*.py`` patterns.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

from tools.failure_taxonomy import FailureClass
from tools.recon_pipeline import HostReconResult, ServiceInfo
from tools.swarm.agents.recon_agent import ReconAgent
from tools.swarm.agents.reflection_agent import (
    _FAILURE_CLASS_TO_REFLECTION_LABEL,
    ReflectionAgent,
    _known_failure_classes,
)
from tools.swarm.agents.vuln_agent import VulnAgent

# ── Helpers ───────────────────────────────────────────────────────────────


def _fake_recon_result() -> HostReconResult:
    """High-risk SSH + SMB + an HTTP service so recon emits both a high-risk
    analysis task and a web analysis task."""
    return HostReconResult(
        target_ip="10.0.0.50",
        os_name="Ubuntu 22.04",
        os_family="linux",
        os_accuracy=95,
        services=[
            ServiceInfo(port=22, protocol="tcp", service="ssh", version="OpenSSH 8.9p1",
                        banner="SSH-2.0-OpenSSH_8.9p1"),
            ServiceInfo(port=445, protocol="tcp", service="microsoft-ds", version="Samba",
                        banner=""),
            ServiceInfo(port=80, protocol="tcp", service="http", version="Apache/2.4.52",
                        banner="Apache/2.4.52 (Ubuntu)"),
        ],
        open_ports=[22, 80, 445],
        scan_tool="nmap",
        evidence_refs=[],
    )


class _FakeModule:
    """Minimal stand-in for an AttackModule with declared ``requires``."""

    def __init__(self, name: str, requires: list[str]) -> None:
        self.name = name
        self.requires = requires


# ── recon_agent: depends_on on analysis-phase new_tasks ───────────────────


def test_recon_agent_analysis_tasks_carry_recon_milestone_dep() -> None:
    """Every analysis-phase new_task from recon must depend on
    [target, "recon"] so route_parallel's milestone gating actually engages."""
    agent = ReconAgent()
    task = {"task_id": "R-1", "target": "10.0.0.50"}
    context = {"config": {}, "blackboard": {}, "stealth": False}

    with patch(
        "tools.recon_pipeline.ReconPipeline.recon_host",
        new_callable=AsyncMock,
        return_value=_fake_recon_result(),
    ):
        result = agent.run(task, context)

    assert result.error == "", f"recon agent errored: {result.error}"
    # Both high-risk (ssh, microsoft-ds) and web (http) analysis tasks emitted.
    assert len(result.new_tasks) >= 2
    for nt in result.new_tasks:
        assert nt["phase"] == "analysis"
        # The milestone-gating contract: a 2-list [target, phase].
        assert nt.get("depends_on") == ["10.0.0.50", "recon"], (
            f"analysis task {nt!r} missing depends_on=[target,'recon']"
        )
        # Existing task dict shape preserved.
        assert "target" in nt and "objective" in nt and "allowed_tools" in nt


# ── vuln_agent: depends_on + prerequisite on exploit tasks/hypotheses ─────


def test_vuln_agent_exploit_tasks_carry_analysis_dep_and_prerequisite() -> None:
    """Exploit-phase new_tasks for confidence>=0.7 hypotheses must depend on
    [target, "analysis"], and vulnerability_hypotheses must include a
    ``prerequisite`` field derived from the top matched module's requires."""
    # A service that will score high confidence: force has_exploit + critical
    # cve paths by stubbing the search clients via the vuln agent's module
    # imports. Easier: construct a hypothesis directly by patching cve_client
    # and exploit_search to return populated results.
    agent = VulnAgent()
    target = "10.0.0.50"
    task = {"task_id": "V-1", "target": target, "services": [
        {"service": "microsoft-ds", "version": "Samba 3", "port": 445},
    ]}
    blackboard: dict = {}
    context = {"config": {}, "blackboard": blackboard}

    # Stub NVD + ExploitSearch so the service reaches confidence>=0.7.
    with patch.object(agent, "_llm_analyze", return_value=None), \
         patch(
             "tools.swarm.agents.vuln_agent.NVDClient",
         ) as nvd_cls, \
         patch(
             "tools.swarm.agents.vuln_agent.ExploitSearch",
         ) as es_cls, \
         patch(
             "tools.swarm.agents.vuln_agent.find_modules",
             return_value=[(0.9, _FakeModule("SMBRelay", requires=["credentials"]))],
         ) as _fm, \
         patch(
             "tools.swarm.agents.vuln_agent.get_module",
             return_value=_FakeModule("SMBRelay", requires=["credentials"]),
         ):
        nvd_cls.return_value.search_sync.return_value = [
            {"id": "CVE-2020-1472", "cvss": 10.0},
        ]
        # format_cve_results is real; it produces text containing "critical"
        # for CVSS 10 -> has_critical_cve True.
        es_cls.return_value.search_exploit_db.return_value = [
            {"title": "exploit PoC", "type": "remote"},
        ]
        es_cls.return_value.search_web_exploit.return_value = []
        result = agent.run(task, context)

    assert result.error == "", f"vuln agent errored: {result.error}"

    # Exploit tasks emitted (confidence>=0.7 from exploit+cve).
    exploit_tasks = [nt for nt in result.new_tasks if nt["phase"] == "exploit"]
    assert exploit_tasks, "expected at least one exploit-phase new_task"
    for nt in exploit_tasks:
        assert nt.get("depends_on") == [target, "analysis"], (
            f"exploit task {nt!r} missing depends_on=[target,'analysis']"
        )

    # Hypotheses carry a prerequisite field mirroring the matched module's
    # requires.
    hyps = result.output["hypotheses"]
    assert hyps, "expected at least one hypothesis"
    for h in hyps:
        assert "prerequisite" in h, f"hypothesis missing prerequisite: {h!r}"
        assert h["prerequisite"] == ["credentials"], (
            f"prerequisite not derived from matched module.requires: {h!r}"
        )

    # Blackboard hypotheses also carry the prerequisite field.
    bb_hyps = blackboard.get("vulnerability_hypotheses", [])
    assert bb_hyps and "prerequisite" in bb_hyps[0]


def test_vuln_agent_prerequisite_empty_when_module_has_no_requires() -> None:
    """A matched module with no ``requires`` yields an empty prerequisite list,
    not a missing key."""
    agent = VulnAgent()
    task = {"task_id": "V-2", "target": "10.0.0.99", "services": [
        {"service": "ssh", "version": "OpenSSH 8.9", "port": 22},
    ]}
    context = {"config": {}, "blackboard": {}}

    with patch.object(agent, "_llm_analyze", return_value=None), \
         patch("tools.swarm.agents.vuln_agent.NVDClient") as nvd_cls, \
         patch("tools.swarm.agents.vuln_agent.ExploitSearch") as es_cls, \
         patch(
             "tools.swarm.agents.vuln_agent.find_modules",
             return_value=[(0.8, _FakeModule("SSHBrute", requires=[]))],
         ), \
         patch(
             "tools.swarm.agents.vuln_agent.get_module",
             return_value=_FakeModule("SSHBrute", requires=[]),
         ):
        nvd_cls.return_value.search_sync.return_value = [
            {"id": "CVE-2024-6387", "cvss": 8.1},
        ]
        es_cls.return_value.search_exploit_db.return_value = [
            {"title": "PoC exploit", "type": "remote"},
        ]
        es_cls.return_value.search_web_exploit.return_value = []
        result = agent.run(task, context)

    assert result.error == ""
    hyps = result.output["hypotheses"]
    assert hyps and hyps[0]["prerequisite"] == []


def test_vuln_agent_prerequisite_empty_when_no_module_matched() -> None:
    """No matched module -> prerequisite is an empty list (not an error, not
    a missing key)."""
    agent = VulnAgent()
    task = {"task_id": "V-3", "target": "10.0.0.98", "services": [
        {"service": "ssh", "version": "OpenSSH 8.9", "port": 22},
    ]}
    context = {"config": {}, "blackboard": {}}

    with patch.object(agent, "_llm_analyze", return_value=None), \
         patch("tools.swarm.agents.vuln_agent.NVDClient") as nvd_cls, \
         patch("tools.swarm.agents.vuln_agent.ExploitSearch") as es_cls, \
         patch("tools.swarm.agents.vuln_agent.find_modules", return_value=[]), \
         patch("tools.swarm.agents.vuln_agent.get_module", return_value=None):
        nvd_cls.return_value.search_sync.return_value = [
            {"id": "CVE-2024-6387", "cvss": 8.1},
        ]
        es_cls.return_value.search_exploit_db.return_value = []
        es_cls.return_value.search_web_exploit.return_value = []
        result = agent.run(task, context)

    assert result.error == ""
    hyps = result.output["hypotheses"]
    assert hyps and hyps[0]["prerequisite"] == []


# ── reflection_agent: FailureClass -> reflection label mapping ────────────


def test_failure_class_to_reflection_label_mapping_covers_core_classes() -> None:
    """The mapping covers the failure classes most likely to be surfaced by
    module results, and every value is one of the prompt's nine labels."""
    prompt_labels = {
        "TOOL_MISMATCH", "PROTOCOL_ERROR", "FIREWALL_BLOCK", "PATCHED",
        "WRONG_VERSION", "AUTH_REQUIRED", "NETWORK_ISSUE", "TOOL_MISSING",
        "RATE_LIMITED",
    }
    # Core classes that should have a mapping.
    assert _FAILURE_CLASS_TO_REFLECTION_LABEL[FailureClass.TARGET_UNREACHABLE] == "NETWORK_ISSUE"
    assert _FAILURE_CLASS_TO_REFLECTION_LABEL[FailureClass.AUTH_FAILED] == "AUTH_REQUIRED"
    assert _FAILURE_CLASS_TO_REFLECTION_LABEL[FailureClass.TOOL_UNAVAILABLE] == "TOOL_MISSING"
    assert _FAILURE_CLASS_TO_REFLECTION_LABEL[FailureClass.SCOPE_BLOCKED] == "FIREWALL_BLOCK"
    assert _FAILURE_CLASS_TO_REFLECTION_LABEL[FailureClass.FALSE_POSITIVE] == "PATCHED"
    assert _FAILURE_CLASS_TO_REFLECTION_LABEL[FailureClass.SCHEMA_ERROR] == "PROTOCOL_ERROR"
    # Every mapped label is in the prompt's vocabulary.
    for label in _FAILURE_CLASS_TO_REFLECTION_LABEL.values():
        assert label in prompt_labels


def test_known_failure_classes_surfaces_structured_labels() -> None:
    """Battle-log failures carrying a ``failure_class`` produce labeled lines
    the reflection prompt can reuse; successes and unknown classes are
    skipped."""
    log = [
        {"success": True, "tool": "nmap", "target": "10.0.0.5"},
        {"success": False, "tool": "smb_relay", "failure_class": "auth_failed"},
        {"success": False, "tool": "redis_rce", "failure_class": FailureClass.SCOPE_BLOCKED},
        {"success": False, "tool": "old_tool"},  # no failure_class
        {"success": False, "tool": "mystery", "failure_class": "not_a_real_class"},
    ]
    lines = _known_failure_classes(log)
    # auth_failed -> AUTH_REQUIRED, scope_blocked -> FIREWALL_BLOCK.
    assert any("smb_relay: AUTH_REQUIRED" in l for l in lines)
    assert any("redis_rce: FIREWALL_BLOCK" in l for l in lines)
    # The unmapped-string and no-failure_class entries are skipped.
    assert all("mystery" not in l for l in lines)
    assert all("old_tool" not in l for l in lines)


def test_known_failure_classes_empty_when_no_structured_classes() -> None:
    """No failure_class on any entry -> empty list (free-text path intact)."""
    log = [
        {"success": False, "tool": "nmap", "error": "timeout"},
        {"success": True, "tool": "nmap"},
    ]
    assert _known_failure_classes(log) == []


def test_reflection_agent_run_with_known_failure_class_does_not_break() -> None:
    """ReflectionAgent.run on a battle log with a structured failure_class
    completes (no model_client => heuristic path only), confirming the new
    import + helper don't break the run."""
    agent = ReflectionAgent()
    task = {
        "task_id": "REF-1",
        "battle_log": [
            {"success": False, "tool": "smb_relay", "error": "logon failure",
             "failure_class": FailureClass.AUTH_FAILED},
            {"success": True, "tool": "nmap"},
        ],
        "session_state": {"target_ip": "10.0.0.5"},
    }
    context = {"blackboard": {}}
    result = agent.run(task, context)
    assert result.error == ""
    # The structured class is not required to surface in the heuristic output
    # (it lives in the LLM prompt augmentation), but the run must succeed and
    # the what_failed list should include the failed tool.
    assert any("smb_relay" in w for w in result.output["what_failed"])
