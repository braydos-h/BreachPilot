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


def _rec(action: str, status: str, *, exit_code: int | None = 0, detail: str = "") -> dict:
    return {
        "timestamp": "2026-01-01T00:00:00Z",
        "target_ip": "10.0.0.50",
        "action": action,
        "status": status,
        "exit_code": exit_code,
        "command": detail or f"{action} ...",
        "detail": detail or f"{action} output",
        "attempt_id": "att-1",
    }


def test_build_campaign_result_returns_none_when_no_records():
    assert _build_campaign_result_from_records({}, "10.0.0.50") is None
    assert _build_campaign_result_from_records({"records": []}, "10.0.0.50") is None


def test_build_campaign_result_separates_successful_from_failed():
    result = {
        "records": [
            _rec("run_exploit_terminal", "completed", detail="whoami; id"),
            _rec("run_msf_module", "completed", detail="meterpreter session 1 opened"),
            _rec("run_python_file", "executed", exit_code=1, detail="Traceback"),
            _rec("quick_scan", "completed", detail="open ports: 22,80"),
        ],
    }
    campaign = _build_campaign_result_from_records(result, "10.0.0.50")
    assert campaign is not None
    state = campaign["states"]["10.0.0.50"]
    # Only exploit-action tools with status=completed count as successful_exploits.
    assert "run_exploit_terminal" in state["successful_exploits"]
    assert "run_msf_module" in state["successful_exploits"]
    # Recon tools never count as exploits even on success.
    assert "quick_scan" not in state["successful_exploits"]
    # Non-zero exit goes to failed_attempts.
    assert "run_python_file" in state["failed_attempts"]
    # Timeline carries every record.
    assert len(state["timeline"]) == 4


def test_build_campaign_result_blocked_records_go_to_failed():
    result = {"records": [_rec("run_exploit_terminal", "blocked", exit_code=None, detail="target not in allowlist")]}
    campaign = _build_campaign_result_from_records(result, "10.0.0.50")
    assert campaign is not None
    state = campaign["states"]["10.0.0.50"]
    assert state["successful_exploits"] == []
    assert "run_exploit_terminal" in state["failed_attempts"]


def test_build_campaign_result_derives_privilege_level_from_summary():
    result = {
        "records": [_rec("run_exploit_terminal", "completed", detail="uid=0(root) gid=0(root)")],
        "outcome_summary": "compromises: 1; last outcome: compromise; privilege: root",
    }
    campaign = _build_campaign_result_from_records(result, "10.0.0.50")
    assert campaign is not None
    state = campaign["states"]["10.0.0.50"]
    assert state["privilege_level"] == "root"


def test_enhanced_report_generator_produces_chain_from_flow_a_records(tmp_path: Path):
    """End-to-end: records → helper → EnhancedReportGenerator → JSON with a chain."""
    result = {
        "records": [
            _rec("run_exploit_terminal", "completed", detail="reverse shell: uid=0(root)"),
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
    assert len(chain["entries"]) == 2
    # Stable-name copy: the WebUI fetches /artifacts/enhanced/enhanced_report.json
    stable = tmp_path / "reports" / "enhanced" / "enhanced_report.json"
    stable.write_bytes(json_path.read_bytes())
    assert json.loads(stable.read_text(encoding="utf-8"))["exploitation_chains"][0]["target"] == "10.0.0.50"
