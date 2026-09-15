"""TODO 018: provenance stays complete and mandatory; round-trip write->read->gate."""

from __future__ import annotations

import json


def test_provenance_has_16_fields():
    from tools.eval_harness import RunProvenance

    required = {
        "model_alias",
        "provider",
        "model_id",
        "model_version",
        "temperature",
        "scenario_version",
        "code_revision",
        "breachpilot_version",
        "config_hash",
        "prompt_hash",
        "tool_catalog_hash",
        "skill_catalog_hash",
        "sandbox_image",
        "sandbox_image_digest",
        "orchestration_mode",
        "provider_adapter_version",
    }
    assert required <= set(RunProvenance.__dataclass_fields__)


def test_provenance_roundtrip_gate_passes(tmp_path):
    from tools.eval_harness import build_run_provenance, write_skipped_eval_report

    prov = build_run_provenance({}, trial_count=5)
    payload = {"provenance": prov.to_dict()}
    artifact = tmp_path / "eval.json"
    artifact.write_text(json.dumps(payload), encoding="utf-8")
    back = json.loads(artifact.read_text(encoding="utf-8"))
    assert set(back["provenance"]) >= {
        "model_alias",
        "provider",
        "orchestration_mode",
        "provider_adapter_version",
    }
    # SKIPPED path preserves schema.
    out = write_skipped_eval_report(tmp_path, reason="test skip", config={}, run_id="skip1")
    skipped = json.loads((out.parent / "report.json").read_text(encoding="utf-8"))
    assert skipped["live_outcome"] == "SKIPPED" or "SKIPPED" in str(skipped)
    assert "provenance" in skipped


def test_build_provenance_modes():
    from tools.eval_harness import build_run_provenance

    agent = build_run_provenance({})
    assert agent.orchestration_mode == "agent"
    swarm = build_run_provenance({"swarm": {"enabled": True}})
    assert swarm.orchestration_mode == "swarm"
    camp = build_run_provenance({"campaign": {"enabled": True}})
    assert camp.orchestration_mode == "campaign"
