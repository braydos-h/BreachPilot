"""Characterization tests for the ``tools.eval`` package split (todo 06).

Pins the post-split contract without running any agent, model, or docker
surface: every test targets pure functions or file-backed helpers with
injected fakes. Nothing here touches the network.

Split map (``tools.eval_harness`` is a thin shim over all of these):

- ``tools.eval.metrics`` — EvalMetrics, compute_metrics, render_*, write_eval_report
- ``tools.eval.single_run`` — run_eval (import surface only; execution is live)
- ``tools.eval.suite`` — EvalSuiteResult, load_target_oracle,
  score_against_oracle, docker_suite_up/down, run_eval_suite (import surface)
- ``tools.eval.graded`` — flag/target scoring, verify, runner, baseline/regression
- ``tools.eval.live`` — outcome taxonomy, provenance, telemetry, thresholds
"""

from __future__ import annotations

import json
from pathlib import Path

import tools.eval_harness as eh
from tools.eval import baseline as _baseline
from tools.eval import graded as _graded
from tools.eval import live as _live
from tools.eval import metrics as _metrics
from tools.eval import suite as _suite


def test_shim_reexports_canonical_objects():
    assert eh.compute_metrics is _metrics.compute_metrics
    assert eh.render_report is _metrics.render_report
    assert eh.write_eval_report is _metrics.write_eval_report
    assert eh.score_against_oracle is _suite.score_against_oracle
    assert eh.run_eval_suite is _suite.run_eval_suite
    assert eh.docker_suite_up is _suite.docker_suite_up
    assert eh.verify_flag_check is _graded.verify_flag_check
    assert eh.run_graded_eval is _graded.run_graded_eval
    assert eh.save_baseline is _baseline.save_baseline
    assert eh.check_regression is _baseline.check_regression
    assert eh.classify_live_outcome is _live.classify_live_outcome
    assert eh.build_run_provenance is _live.build_run_provenance
    assert eh.write_skipped_eval_report is _graded.write_skipped_eval_report


def test_compute_metrics_empty_input_is_error():
    metrics = eh.compute_metrics(None, run_id="r1", target="127.0.0.1")
    assert metrics.verdict == "error"
    assert metrics.total_actions == 0
    assert metrics.success_rate == 0.0
    assert metrics.run_id == "r1"


def test_compute_metrics_counts_compromises():
    final = {
        "total_actions": 4,
        "outcome_summary": "done | compromises: 2; cred dumps: 1; partials: 3; failures: 0",
        "records": [{"status": "success"}, {"status": "failed"}, {"status": "TIMEOUT"}],
        "audit_path": "/tmp/audit.jsonl",
    }
    metrics = eh.compute_metrics(final, run_id="r2")
    assert metrics.compromise_count == 2
    assert metrics.cred_dump_count == 1
    assert metrics.partial_count == 3
    assert metrics.failure_count == 1
    assert metrics.records_count == 3
    assert metrics.verdict == "compromised"
    assert metrics.success_rate == 0.75


def test_render_variants_share_run_id():
    metrics = eh.compute_metrics({"total_actions": 1, "outcome_summary": "compromises: 0"}, run_id="r3")
    assert eh.render_report(metrics)["run_id"] == "r3"
    assert "r3" in eh.render_markdown(metrics)
    assert "r3" in eh.render_html(metrics)


def test_write_eval_report_roundtrip(tmp_path: Path):
    metrics = eh.compute_metrics({"total_actions": 2}, run_id="r4")
    out_dir = eh.write_eval_report(metrics, reports_root=tmp_path)
    payload = json.loads((out_dir / "eval_report.json").read_text(encoding="utf-8"))
    assert payload["run_id"] == "r4"
    assert (out_dir / "eval_report.md").exists()
    assert (out_dir / "eval_report.html").exists()


def test_score_against_oracle_service_match():
    oracle = {
        "target_id": "t1",
        "expected_findings": {"services": ["http"], "known_cves": ["CVE-2021-44228"]},
    }
    result = eh.score_against_oracle(
        [
            {"type": "service", "value": "http"},
            {"type": "cve", "value": "cve-2021-44228"},
            {"type": "service", "value": "telnet"},
        ],
        oracle,
    )
    assert result.true_positives == 2
    assert result.false_positives == 1
    assert result.expected_total == 2
    assert result.target_id == "t1"


def test_score_against_oracle_negative_control():
    oracle = {"target_id": "hard", "negative_control": True, "expected_findings": {}}
    assert eh.score_against_oracle([], oracle).success is True
    assert eh.score_against_oracle([{"type": "service", "value": "http"}], oracle).success is False


def test_load_target_oracle_missing_is_empty(tmp_path: Path):
    assert eh.load_target_oracle(tmp_path / "nope.json") == {}


def test_docker_suite_up_missing_compose_is_nonzero(tmp_path: Path):
    assert eh.docker_suite_up(tmp_path / "docker-compose.yml") == 1
    assert eh.docker_suite_down(tmp_path / "docker-compose.yml") == 1


def test_classify_live_outcome_precedence():
    assert eh.classify_live_outcome(skipped=True, success=True) == eh.LiveOutcome.SKIPPED
    assert eh.classify_live_outcome(infra_error=True, success=True) == eh.LiveOutcome.INFRA_ERROR
    assert eh.classify_live_outcome(success=True) == eh.LiveOutcome.PASS
    assert eh.classify_live_outcome() == eh.LiveOutcome.FAIL
    assert eh.LiveOutcome.is_valid("PASS")
    assert not eh.LiveOutcome.is_valid("GREEN")


def test_host_owned_when_conditions():
    good = [eh.FlagCheckResult(flag_id="a", passed=True, detail="ok", check={})]
    bad = [eh.FlagCheckResult(flag_id="a", passed=False, detail="no", check={})]
    assert eh._host_owned_when_met(good, "any") is True
    assert eh._host_owned_when_met(bad, "any") is False
    assert eh._host_owned_when_met(good, "all") is True
    assert eh._host_owned_when_met(good + bad, "all") is False
    assert eh._host_owned_when_met(good, ["a"]) is True
    assert eh._host_owned_when_met(good, ["zzz"]) is False


def test_verify_flag_check_uses_executor_truth():
    ok = eh.verify_flag_check({"id": "f1", "check": {"type": "http_request"}}, lambda spec: (True, "200"))
    assert ok.passed is True and ok.flag_id == "f1"
    crashed = eh.verify_flag_check({"type": "http_request"}, lambda spec: (_ for _ in ()).throw(RuntimeError("x")))
    assert crashed.passed is False and "executor error" in crashed.detail


def test_target_score_composite_math():
    oracle = {"target_id": "t9", "host_owned_when": "any"}
    flags = [eh.FlagCheckResult(flag_id="f", passed=True, detail="ok", check={})]
    suite_result = eh.EvalSuiteResult(
        target_id="t9", true_positives=1, false_positives=0, expected_total=1, success=True
    )
    score = _graded._build_target_score("t9", oracle, flags, suite_result, findings_claimed=1)
    assert score.flags_captured == 1 and score.flags_total == 1
    assert score.hosts_owned == 1 and score.success is True
    assert score.score == 1.0


def test_baseline_save_and_regression(tmp_path: Path):
    report = eh.EvalReport(run_id="base", timestamp="t")
    baseline = tmp_path / "baseline.json"
    eh.save_baseline(report, baseline)
    passed, _messages = eh.check_regression(report, baseline)
    assert passed is True
    worse = eh.EvalReport(run_id="worse", timestamp="t")
    worse.targets.append(eh.TargetScore(target_id="t1", score=0.9, flags_total=1, hosts_total=1, findings_claimed=1))
    first = eh.EvalReport(run_id="first", timestamp="t")
    first.targets.append(eh.TargetScore(target_id="t1", score=0.1, flags_total=1, hosts_total=1, findings_claimed=1))
    eh.save_baseline(worse, baseline)
    passed, messages = eh.check_regression(first, baseline)
    assert passed is False
    assert any("REGRESSION" in m for m in messages)
    missing_passed, _ = eh.check_regression(report, tmp_path / "absent.json")
    assert missing_passed is False


def test_eval_report_to_dict_shape():
    report = eh.EvalReport(run_id="r", timestamp="t")
    payload = report.to_dict()
    assert payload["run_id"] == "r"
    assert payload["aggregate"]["targets_run"] == 0
    assert report.overall_score == 0.0


def test_provenance_never_breaks_on_empty_config():
    provenance = eh.build_run_provenance(None, trial_count=0)
    assert provenance.trials == 1  # max(1, ...) guard
    as_dict = provenance.to_dict()
    assert "model_id" in as_dict and "config_hash" in as_dict


def test_heavy_entries_are_importable_not_executed():
    assert callable(eh.run_eval)
    assert callable(eh.run_eval_suite)
    assert callable(eh.run_graded_eval)
    assert callable(eh.default_agent_runner)
    assert isinstance(eh._CONFIG_PATH_KEY, str)
    assert isinstance(eh._WORKSPACE_KEY, str)
