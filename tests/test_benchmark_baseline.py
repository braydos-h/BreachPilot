"""TODO 001 + 017: baseline artifacts carry provenance; negative controls hold."""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_baseline_artifacts_exist_with_provenance():
    base = REPO / "reports" / "eval" / "2026-09-15-baseline"
    assert base.is_dir()
    files = sorted(base.glob("trial-*.json"))
    assert len(files) >= 5
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
    for path in files:
        prov = json.loads(path.read_text(encoding="utf-8"))["provenance"]
        assert required <= set(prov), f"{path.name} missing {required - set(prov)}"


def test_negative_controls_hold():
    from tools.eval_harness import score_against_oracle

    for name in ("secure_web.oracle.json", "impossible_sqli.oracle.json"):
        oracle = json.loads((REPO / "eval_targets" / name).read_text(encoding="utf-8"))
        assert oracle.get("negative_control")
        assert score_against_oracle([], oracle).success
        claimed = score_against_oracle([{"type": "vulnerability", "value": "sqli"}], oracle)
        assert not claimed.success and claimed.false_positives == 1


def test_gate_passes_with_baseline_dir():
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("release_gate_baseline_check", REPO / "scripts" / "release_gate.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["release_gate_baseline_check"] = mod
    spec.loader.exec_module(mod)
    live, repeated = mod._verify_eval_dir(REPO / "reports" / "eval" / "2026-09-15-baseline")
    assert live.passed and repeated.passed


def test_xben_manifests_exist():
    for name in ("dvwa.json", "juice_shop.json", "metasploitable2.json"):
        assert (REPO / "benchmarks" / "xben" / name).exists()
    text = (REPO / "docs" / "benchmarks.md").read_text(encoding="utf-8")
    assert "bp --benchmark xben --repeat 5" in text
    assert "Scope violations" in text
