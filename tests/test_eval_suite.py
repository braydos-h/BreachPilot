"""Tests for the Docker target suite + oracle-backed eval scoring (D1).

The suite (``eval_targets/docker-compose.yml``) spins up Metasploitable2,
DVWA, juice-shop, and a vulnerable k8s cluster. Per-target oracle JSON files
describe the expected findings so the eval can score true/false positives.

These tests:
- Verify the compose file exists and binds every port to 127.0.0.1 (no network
  exposure).
- Verify each oracle JSON parses and has the expected shape.
- Verify ``score_against_oracle`` counts true/false positives correctly.
- Verify ``run_eval_suite`` scoring path works against a synthetic results
  stream (mocks docker compose up/down + run_eval).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.eval_harness import (
    EvalSuiteResult,
    docker_suite_down,
    docker_suite_up,
    load_target_oracle,
    run_eval_suite,
    score_against_oracle,
)

# ── Compose file ─────────────────────────────────────────────────────────────


def test_compose_file_exists():
    compose = Path("eval_targets/docker-compose.yml")
    assert compose.exists(), "eval_targets/docker-compose.yml must exist"


def test_compose_binds_loopback_only():
    """Every port in the compose file binds to 127.0.0.1 (no network exposure)."""
    compose = Path("eval_targets/docker-compose.yml")
    text = compose.read_text(encoding="utf-8")
    # Every port mapping must start with 127.0.0.1:
    import re

    port_lines = re.findall(r'"([^"]*:\d+:\d+)"', text)
    assert port_lines, "expected at least one port mapping in compose"
    for mapping in port_lines:
        assert mapping.startswith("127.0.0.1:"), f"port {mapping} not bound to loopback"


def test_compose_has_four_targets():
    """The compose file defines the four standard targets."""
    compose = Path("eval_targets/docker-compose.yml")
    text = compose.read_text(encoding="utf-8")
    for target in ("metasploitable2", "dvwa", "juice_shop", "vulnerable_k8s"):
        assert target in text, f"compose missing target: {target}"


# ── Oracle files ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "oracle_name",
    [
        "metasploitable2",
        "dvwa",
        "juice_shop",
        "vulnerable_k8s",
    ],
)
def test_oracle_files_parse(oracle_name):
    path = Path("eval_targets") / f"{oracle_name}.oracle.json"
    assert path.exists(), f"missing oracle: {path}"
    oracle = load_target_oracle(path)
    assert oracle.get("target_id") == oracle_name
    assert "expected_findings" in oracle
    assert "scoring" in oracle


def test_metasploitable2_oracle_has_expected_creds():
    oracle = load_target_oracle("eval_targets/metasploitable2.oracle.json")
    creds = oracle["expected_findings"]["weak_credentials"]
    assert any(c["user"] == "msfadmin" for c in creds)


def test_dvwa_oracle_has_web_vulns():
    oracle = load_target_oracle("eval_targets/dvwa.oracle.json")
    vulns = oracle["expected_findings"]["vulnerabilities"]
    assert "sqli" in vulns and "xss" in vulns


# ── score_against_oracle ─────────────────────────────────────────────────────


def test_score_true_positive_service():
    oracle = {"target_id": "t", "expected_findings": {"services": ["ssh", "http"]}}
    findings = [{"type": "service", "value": "ssh"}, {"type": "service", "value": "http"}]
    result = score_against_oracle(findings, oracle)
    assert result.true_positives == 2
    assert result.false_positives == 0


def test_score_false_positive_unknown_service():
    oracle = {"target_id": "t", "expected_findings": {"services": ["ssh"]}}
    findings = [{"type": "service", "value": "ssh"}, {"type": "service", "value": "ftp"}]
    result = score_against_oracle(findings, oracle)
    assert result.true_positives == 1
    assert result.false_positives == 1


def test_score_true_positive_cve():
    oracle = {"target_id": "t", "expected_findings": {"known_cves": ["CVE-2021-44228"]}}
    findings = [{"type": "cve", "value": "CVE-2021-44228"}]
    result = score_against_oracle(findings, oracle)
    assert result.true_positives == 1
    assert result.false_positives == 0


def test_score_true_positive_credential():
    oracle = {
        "target_id": "t",
        "expected_findings": {
            "weak_credentials": [{"user": "admin", "password": "password"}],
        },
    }
    findings = [{"type": "credential", "user": "admin", "password": "password"}]
    result = score_against_oracle(findings, oracle)
    assert result.true_positives == 1


def test_score_false_positive_wrong_credential():
    oracle = {
        "target_id": "t",
        "expected_findings": {
            "weak_credentials": [{"user": "admin", "password": "password"}],
        },
    }
    findings = [{"type": "credential", "user": "admin", "password": "wrong"}]
    result = score_against_oracle(findings, oracle)
    assert result.true_positives == 0
    assert result.false_positives == 1


def test_score_success_criteria_3_expected():
    oracle = {
        "target_id": "t",
        "expected_findings": {"services": ["ssh", "http", "ftp"]},
        "scoring": {"success_criteria": "≥3 expected creds recovered"},
    }
    findings = [
        {"type": "service", "value": "ssh"},
        {"type": "service", "value": "http"},
        {"type": "service", "value": "ftp"},
    ]
    result = score_against_oracle(findings, oracle)
    assert result.success is True


def test_score_success_criteria_2_web_vulns():
    oracle = {
        "target_id": "t",
        "expected_findings": {"vulnerabilities": ["sqli", "xss"]},
        "scoring": {"success_criteria": "≥2 web vulns confirmed"},
    }
    findings = [
        {"type": "vulnerability", "value": "sqli"},
        {"type": "vulnerability", "value": "xss"},
    ]
    result = score_against_oracle(findings, oracle)
    assert result.success is True


def test_score_precision_and_recall():
    oracle = {"target_id": "t", "expected_findings": {"services": ["ssh", "http", "ftp"]}}
    findings = [
        {"type": "service", "value": "ssh"},
        {"type": "service", "value": "http"},
        {"type": "service", "value": "unknown"},
    ]
    result = score_against_oracle(findings, oracle)
    # precision = 2/3, recall = 2/3
    assert abs(result.precision - 2 / 3) < 0.01
    assert abs(result.recall - 2 / 3) < 0.01


def test_score_empty_findings():
    oracle = {"target_id": "t", "expected_findings": {"services": ["ssh"]}}
    result = score_against_oracle([], oracle)
    assert result.true_positives == 0
    assert result.false_positives == 0
    assert result.success is False


def test_score_lenient_untyped_finding_matches_expected_token():
    """A finding with no ``type`` but a matching value counts as a TP."""
    oracle = {"target_id": "t", "expected_findings": {"services": ["ssh"]}}
    findings = [{"value": "ssh"}]
    result = score_against_oracle(findings, oracle)
    assert result.true_positives == 1


# ── EvalSuiteResult ──────────────────────────────────────────────────────────


def test_suite_result_to_dict():
    r = EvalSuiteResult(target_id="t", true_positives=3, false_positives=1, expected_total=5, success=True)
    d = r.to_dict()
    assert d["target_id"] == "t"
    assert d["true_positives"] == 3
    assert d["precision"] == 0.75
    assert d["recall"] == 0.6


# ── docker_suite_up / down (mocked) ──────────────────────────────────────────


def test_docker_suite_up_missing_compose(tmp_path):
    """Returns 1 when the compose file is missing."""
    rc = docker_suite_up(compose_path=tmp_path / "nope.yml")
    assert rc != 0


def test_docker_suite_down_missing_compose(tmp_path):
    rc = docker_suite_down(compose_path=tmp_path / "nope.yml")
    assert rc != 0


# ── run_eval_suite (mocked scoring path) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_run_eval_suite_scores_against_oracles(tmp_path, monkeypatch):
    """The suite scoring path works against a synthetic results stream.

    Mocks docker compose up/down + run_eval so no Docker or live target is
    needed. Verifies the suite produces a per-target score + aggregate.
    """
    # Build a fake oracle dir with two minimal oracles.
    oracle_dir = tmp_path / "targets"
    oracle_dir.mkdir()
    (oracle_dir / "a.oracle.json").write_text(
        json.dumps(
            {
                "target_id": "a",
                "host": "127.0.0.1",
                "expected_findings": {"services": ["ssh", "http"], "known_cves": ["CVE-2021-44228"]},
                "scoring": {"success_criteria": "≥3 expected creds recovered"},
            }
        ),
        encoding="utf-8",
    )
    (oracle_dir / "b.oracle.json").write_text(
        json.dumps(
            {
                "target_id": "b",
                "host": "127.0.0.1",
                "expected_findings": {"services": ["ftp"], "vulnerabilities": ["sqli"]},
                "scoring": {"success_criteria": "≥2 web vulns confirmed"},
            }
        ),
        encoding="utf-8",
    )

    # Mock docker compose + run_eval.
    monkeypatch.setattr("tools.eval_harness.docker_suite_up", lambda *a, **k: 0)
    monkeypatch.setattr("tools.eval_harness.docker_suite_down", lambda *a, **k: 0)

    async def _fake_run_eval(args):
        # Write a synthetic eval report. Fail closed: unvalidated report text
        # never yields true positives (verifier flags only).
        import json as _json

        eval_dir = Path("reports/eval") / f"run-{args.target}"
        eval_dir.mkdir(parents=True, exist_ok=True)
        report = {
            "target": args.target,
            "outcome_summary": "ssh http CVE-2021-44228 detected",
            "records": [{"command": "nmap", "output": "ssh http CVE-2021-44228"}],
        }
        (eval_dir / "eval_report.json").write_text(_json.dumps(report), encoding="utf-8")
        return 0

    monkeypatch.setattr("tools.eval_harness.run_eval", _fake_run_eval)
    monkeypatch.chdir(tmp_path)

    from argparse import Namespace

    args = Namespace(target="127.0.0.1", config=tmp_path / "config.yaml")
    report = await run_eval_suite(args, compose_up=True, compose_down=True, oracle_dir=oracle_dir)

    assert "targets" in report
    assert "aggregate" in report
    assert "a" in report["targets"]
    assert "b" in report["targets"]
    assert report["targets"]["a"]["true_positives"] == 0
    assert report["aggregate"]["targets_run"] == 2
