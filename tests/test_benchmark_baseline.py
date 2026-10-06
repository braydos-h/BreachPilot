"""Offline evaluation gate contracts and negative controls."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _release_gate():
    spec = importlib.util.spec_from_file_location(
        "benchmark_baseline_release_gate", REPO / "scripts" / "release_gate.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_live_eval_evidence_is_external_without_supplied_reports():
    result = _release_gate()._verify_eval_dir(None)

    assert not result.passed
    assert result.external
    assert "no model backend report supplied" in result.detail


def test_negative_controls_hold():
    from tools.eval_harness import score_against_oracle

    for name in ("secure_web.oracle.json", "impossible_sqli.oracle.json"):
        oracle = json.loads((REPO / "eval_targets" / name).read_text(encoding="utf-8"))
        assert oracle.get("negative_control")
        assert score_against_oracle([], oracle).success
        claimed = score_against_oracle([{"type": "vulnerability", "value": "sqli"}], oracle)
        assert not claimed.success and claimed.false_positives == 1


def test_gate_accepts_complete_synthetic_eval_report(tmp_path: Path):
    report_path = tmp_path / "trial-001" / "report.json"
    report_path.parent.mkdir()
    report_path.write_text(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "live_outcome": "PASS",
                "provenance": {
                    "model_alias": "fixture-model",
                    "provider": "fixture-provider",
                    "model_id": "fixture-model-v1",
                    "model_version": "fixture",
                    "temperature": "0",
                    "scenario_version": "fixture-v1",
                    "code_revision": "a" * 40,
                    "breachpilot_version": "0.69.0",
                    "config_hash": "c" * 64,
                    "prompt_hash": "p" * 64,
                    "tool_catalog_hash": "t" * 64,
                    "skill_catalog_hash": "s" * 64,
                    "sandbox_image": "breachpilot-sandbox:fixture",
                    "sandbox_image_digest": "sha256:" + "d" * 64,
                    "orchestration_mode": "fixture",
                    "provider_adapter_version": "fixture-v1",
                },
            }
        ),
        encoding="utf-8",
    )

    result = _release_gate()._verify_eval_dir(tmp_path)

    assert result.passed, result.detail


def test_xben_manifests_exist():
    for name in ("dvwa.json", "juice_shop.json", "metasploitable2.json"):
        assert (REPO / "benchmarks" / "xben" / name).exists()
    text = (REPO / "docs" / "benchmarks.md").read_text(encoding="utf-8")
    assert "bp --config config.loopback-lab.yaml --benchmark xben --trials 5" in text
    assert "sandbox.network.map_host_loopback: true" in text
    assert "Scope violations" in text
