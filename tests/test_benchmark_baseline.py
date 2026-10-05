"""TODO 001 + 017: baseline artifacts carry provenance; negative controls hold."""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load_release_gate():
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("release_gate_baseline_check", REPO / "scripts" / "release_gate.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["release_gate_baseline_check"] = mod
    spec.loader.exec_module(mod)
    return mod


def _valid_provenance_fixture() -> dict[str, object]:
    return {
        "model_alias": "fixture-model",
        "provider": "fixture-provider",
        "model_id": "fixture-model-id",
        "model_version": "fixture-version",
        "temperature": 0.0,
        "scenario_version": "fixture-scenario",
        "code_revision": "fixture-revision",
        "breachpilot_version": "0.0.0-test-fixture",
        "config_hash": "fixture-config-hash",
        "prompt_hash": "fixture-prompt-hash",
        "tool_catalog_hash": "fixture-tool-hash",
        "skill_catalog_hash": "fixture-skill-hash",
        "sandbox_image": "fixture-sandbox",
        "sandbox_image_digest": "sha256:" + "0" * 64,
        "orchestration_mode": "fixture",
        "provider_adapter_version": "fixture-adapter",
        "trials": 1,
    }


def test_release_gate_accepts_a_complete_provenance_fixture(tmp_path):
    """The parser contract is unit-tested without claiming live benchmark evidence."""
    for index in range(5):
        (tmp_path / f"fixture-{index}.json").write_text(
            json.dumps(
                {
                    "run_id": f"fixture-run-{index}",
                    "live_outcome": "PASS",
                    "trials": [{"target_id": "fixture-target", "verified_success": True}],
                    "provenance": _valid_provenance_fixture(),
                }
            ),
            encoding="utf-8",
        )

    live, repeated = _load_release_gate()._verify_eval_dir(tmp_path)

    assert live.passed
    assert repeated.passed


def test_release_gate_keeps_missing_evaluation_evidence_external(tmp_path):
    live, repeated = _load_release_gate()._verify_eval_dir(tmp_path / "missing")

    assert not live.passed and live.external
    assert not repeated.passed and repeated.external


def test_provenance_contract_contains_reproducibility_pins():
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
    assert required <= set(_valid_provenance_fixture())


def test_negative_controls_hold():
    from tools.eval_harness import score_against_oracle

    for name in ("secure_web.oracle.json", "impossible_sqli.oracle.json"):
        oracle = json.loads((REPO / "eval_targets" / name).read_text(encoding="utf-8"))
        assert oracle.get("negative_control")
        assert score_against_oracle([], oracle).success
        claimed = score_against_oracle([{"type": "vulnerability", "value": "sqli"}], oracle)
        assert not claimed.success and claimed.false_positives == 1


def test_xben_manifests_exist():
    for name in ("dvwa.json", "juice_shop.json", "metasploitable2.json"):
        assert (REPO / "benchmarks" / "xben" / name).exists()
    text = (REPO / "docs" / "benchmarks.md").read_text(encoding="utf-8")
    assert "bp --benchmark xben --trials 1" in text
    assert "scope_violation_count" in text
