"""B1: Flow A emits an enhanced report JSON with ExploitationChain data.

Flow A's run_exploit_agent does not run an AutonomousOrchestrator campaign,
so EnhancedReportGenerator was Flow B-only. ``_build_campaign_result_from_records``
folds the per-target audit records into the ``{states: {target: AttackState.to_dict()}}``
shape EnhancedReportGenerator consumes. These tests pin the contract.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.enhanced_reporting import EnhancedReportGenerator
from tools.run_service.service import _build_campaign_result_from_records


def _rec(
    action: str,
    status: str,
    *,
    exit_code: int | None = 0,
    detail: str = "",
    command: str | None = None,
    exploit_outcome: str = "none",
    outcome_evidence: list[str] | None = None,
    privilege_level: str = "",
) -> dict:
    return {
        "timestamp": "2026-01-01T00:00:00Z",
        "target_ip": "10.0.0.50",
        "action": action,
        "status": status,
        "exit_code": exit_code,
        "command": command or detail or f"{action} ...",
        "detail": detail or f"{action} output",
        "attempt_id": "att-1",
        "exploit_outcome": exploit_outcome,
        "outcome_evidence": list(outcome_evidence or []),
        "privilege_level": privilege_level,
    }


def test_build_campaign_result_returns_none_when_no_records():
    assert _build_campaign_result_from_records({}, "10.0.0.50") is None
    assert _build_campaign_result_from_records({"records": []}, "10.0.0.50") is None


def test_run_summary_cannot_attribute_success_to_unverified_actions():
    """A run-level success count cannot be copied onto unrelated audit rows."""
    result = {
        "records": [
            _rec("run_exploit_terminal", "completed", detail="whoami; id"),
            _rec("run_msf_module", "completed", detail="module returned"),
            _rec("run_python_file", "executed", exit_code=1, detail="Traceback"),
            _rec("quick_scan", "completed", detail="open ports: 22,80"),
        ],
        "outcome_summary": "compromises: 1; last outcome: compromise; privilege: root",
    }
    campaign = _build_campaign_result_from_records(result, "10.0.0.50")
    assert campaign is not None
    state = campaign["states"]["10.0.0.50"]
    assert state["successful_exploits"] == []
    assert state["exploit_probes"] == {}
    assert state["privilege_level"] == "none"
    assert "run_python_file" in state["failed_attempts"]
    assert len(state["timeline"]) == 4


def test_verified_action_owns_its_success_privilege_and_retest_probe():
    """Only a row carrying classifier evidence supplies its success and probe."""
    result = {
        "records": [
            _rec(
                "run_exploit_terminal",
                "completed",
                command="unrelated first attempt",
                detail="unknown result",
            ),
            _rec(
                "run_exploit_terminal",
                "executed",
                command="verified exploit command",
                detail="uid=0(root)",
                exploit_outcome="compromise",
                outcome_evidence=["shell:uid=0\\("],
                privilege_level="root",
            ),
            _rec(
                "run_msf_module",
                "completed",
                command="unverified module command",
                detail="module returned",
            ),
            _rec("run_python_file", "executed", exit_code=1, detail="Traceback"),
            _rec("quick_scan", "completed", detail="open ports: 22,80"),
        ],
        # The aggregate summary deliberately disagrees with the row metadata;
        # action-local evidence is the authority for attribution.
        "outcome_summary": "compromises: 1; privilege: SYSTEM",
    }
    campaign = _build_campaign_result_from_records(result, "10.0.0.50")
    assert campaign is not None
    state = campaign["states"]["10.0.0.50"]
    assert state["successful_exploits"] == ["run_exploit_terminal"]
    assert state["exploit_probes"] == {
        "run_exploit_terminal": {"type": "shell_command", "exec": "verified exploit command"}
    }
    assert state["privilege_level"] == "root"
    assert "run_python_file" in state["failed_attempts"]
    assert "quick_scan" not in state["successful_exploits"]


def test_build_campaign_result_blocked_records_go_to_failed():
    result = {"records": [_rec("run_exploit_terminal", "blocked", exit_code=None, detail="target not in allowlist")]}
    campaign = _build_campaign_result_from_records(result, "10.0.0.50")
    assert campaign is not None
    state = campaign["states"]["10.0.0.50"]
    assert state["successful_exploits"] == []
    assert "run_exploit_terminal" in state["failed_attempts"]


def test_build_campaign_result_uses_per_action_privilege_evidence():
    result = {
        "records": [
            _rec(
                "run_exploit_terminal",
                "completed",
                detail="uid=0(root) gid=0(root)",
                exploit_outcome="compromise",
                outcome_evidence=["shell:uid=0\\("],
                privilege_level="root",
            )
        ],
        "outcome_summary": "compromises: 1; last outcome: compromise; privilege: SYSTEM",
    }
    campaign = _build_campaign_result_from_records(result, "10.0.0.50")
    assert campaign is not None
    state = campaign["states"]["10.0.0.50"]
    assert state["privilege_level"] == "root"


def test_enhanced_report_generator_produces_chain_from_flow_a_records(tmp_path: Path):
    """End-to-end: records → helper → EnhancedReportGenerator → JSON with a chain."""
    result = {
        "records": [
            _rec(
                "run_exploit_terminal",
                "completed",
                detail="reverse shell: uid=0(root)",
                exploit_outcome="compromise",
                outcome_evidence=["shell:uid=0\\("],
                privilege_level="root",
            ),
            _rec("run_msf_module", "completed", detail="meterpreter session 1"),
        ],
        "outcome_summary": "compromises: 1; privilege: root",
    }
    campaign = _build_campaign_result_from_records(result, "10.0.0.50")
    assert campaign is not None

    generator = EnhancedReportGenerator(db=None, mission_id="M-test", workspace=tmp_path / "reports")
    paths = generator.generate_full_report(campaign, output_format="json")
    json_path = paths["json"]
    assert json_path.exists()

    data = json.loads(json_path.read_text(encoding="utf-8"))
    chains = data.get("exploitation_chains", [])
    assert len(chains) == 1
    chain = chains[0]
    assert chain["target"] == "10.0.0.50"
    assert chain["successful"] is True
    assert chain["final_privilege"] == "root"
    assert len(chain["entries"]) == 1
    assert chain["entries"][0]["module"] == "run_exploit_terminal"
    # Stable-name copy: the WebUI fetches /artifacts/enhanced/enhanced_report.json
    stable = tmp_path / "reports" / "enhanced" / "enhanced_report.json"
    stable.write_bytes(json_path.read_bytes())
    assert json.loads(stable.read_text(encoding="utf-8"))["exploitation_chains"][0]["target"] == "10.0.0.50"
