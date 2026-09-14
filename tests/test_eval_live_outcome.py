"""Packet 01 — live autonomous evaluation, local prep (mocked, hermetic).

Covers the outcome taxonomy (``SKIPPED`` can never read as ``PASS``),
provenance construction (secret-free), trial-telemetry extraction,
reliability aggregation, live-threshold gating, and the
:func:`run_graded_eval` wiring (telemetry collection, outcome
classification, provenance persistence) with a fake runner/executor.
No network, no docker, no model keys.
"""

from __future__ import annotations

import json

import pytest


def _telemetry(**kwargs):
    from tools.eval_harness import TrialTelemetry

    base = {"target_id": "t"}
    base.update(kwargs)
    return TrialTelemetry(**base)


# ── Outcome taxonomy ─────────────────────────────────────────────────────


def test_classify_live_outcome_precedence():
    from tools.eval_harness import LiveOutcome, classify_live_outcome

    # Skipped dominates everything: a run that never executed is SKIPPED.
    assert classify_live_outcome(skipped=True, infra_error=True, success=True) == LiveOutcome.SKIPPED
    # Infra failure dominates success flags: executor truth, not claims.
    assert classify_live_outcome(infra_error=True, success=True) == LiveOutcome.INFRA_ERROR
    assert classify_live_outcome(success=True) == LiveOutcome.PASS
    assert classify_live_outcome() == LiveOutcome.FAIL


def test_live_outcome_values_serialize_as_plain_strings():
    from tools.eval_harness import LiveOutcome

    for value in (LiveOutcome.PASS, LiveOutcome.FAIL, LiveOutcome.SKIPPED, LiveOutcome.INFRA_ERROR):
        assert type(value) is str
        assert LiveOutcome.is_valid(value)
    assert not LiveOutcome.is_valid("pass")
    assert not LiveOutcome.is_valid("")
    assert not LiveOutcome.is_valid(None)


# ── Telemetry extraction ─────────────────────────────────────────────────


def test_extract_trial_telemetry_full_result():
    from tools.eval_harness import extract_trial_telemetry

    tel = extract_trial_telemetry(
        "dvwa",
        {
            "total_actions": 12,
            "outcome_summary": "compromises: 1; ...",
            "records": [
                {"status": "SCOPE_DENIED"},
                {"status": "sandbox_scope_denied"},
                {"status": "error"},
                {"status": "completed"},
            ],
            "attack_focus": {"duplicate_blocks": 4, "drift_redirects": 2},
            "verdict_mismatch": True,
            "total_tokens": 1500,
        },
        verified_success=True,
        vulnerability_family="vulnerabilities",
    )
    assert tel.target_id == "dvwa"
    assert tel.total_actions == 12
    assert tel.verified_success is True
    assert tel.agent_claimed_success is True
    assert tel.false_compromise is False
    assert tel.duplicate_actions == 4
    assert tel.drift_redirects == 2
    assert tel.scope_rejections == 2
    assert tel.tool_errors == 1
    assert tel.verdict_mismatch is True
    assert tel.total_tokens == 1500
    assert tel.vulnerability_family == "vulnerabilities"


def test_extract_trial_telemetry_false_compromise():
    from tools.eval_harness import extract_trial_telemetry

    tel = extract_trial_telemetry(
        "juice",
        {"total_actions": 8, "outcome_summary": "compromises: 2", "records": []},
        verified_success=False,
    )
    assert tel.agent_claimed_success is True
    assert tel.false_compromise is True


def test_extract_trial_telemetry_missing_keys_degrade_safely():
    from tools.eval_harness import extract_trial_telemetry

    tel = extract_trial_telemetry("x", None)
    assert tel.total_actions == 0
    assert tel.verified_success is False
    assert tel.false_compromise is False
    assert tel.to_dict()["target_id"] == "x"

    tel2 = extract_trial_telemetry(
        "y",
        {"total_actions": "bogus", "attack_focus": {"duplicate_blocks": "bogus"}, "records": "bogus"},
    )
    assert tel2.total_actions == 0
    assert tel2.duplicate_actions == 0
    assert tel2.scope_rejections == 0


def test_extract_trial_telemetry_timeout_counting():
    from tools.eval_harness import extract_trial_telemetry

    tel = extract_trial_telemetry(
        "t",
        {"records": [{"status": "timed_out"}, {"status": "completed", "timed_out": True}, {"status": "ok"}]},
    )
    assert tel.timeouts == 2


# ── Reliability aggregation ──────────────────────────────────────────────


def test_compute_reliability_metrics_rates():
    from tools.eval_harness import compute_reliability_metrics

    trials = [
        _telemetry(target_id="a", total_actions=10, verified_success=True, vulnerability_family="web"),
        _telemetry(
            target_id="b",
            total_actions=20,
            agent_claimed_success=True,
            false_compromise=True,
            stuck_loop=True,
            duplicate_actions=5,
            tool_errors=2,
            timeouts=1,
            scope_rejections=4,
            total_tokens=900,
            vulnerability_family="web",
        ),
        _telemetry(target_id="c", total_actions=5, vulnerability_family="creds"),
    ]
    m = compute_reliability_metrics(trials, live_outcome="FAIL")
    assert m.targets_run == 3
    assert m.verified_compromise_rate == pytest.approx(0.3333)
    assert m.false_compromise_rate == pytest.approx(0.3333)
    assert m.stuck_loop_rate == pytest.approx(0.3333)
    assert m.duplicate_action_count == 5
    assert m.mean_actions_to_verified_objective == 10.0
    assert m.timeout_rate == pytest.approx(0.3333)
    assert m.scope_rejection_rate == pytest.approx(0.1143)
    assert m.tool_error_rate == pytest.approx(0.3333)
    assert m.tokens_per_verified_scenario == 0.0  # verified trial reported no tokens
    assert m.success_rate_by_family == {"web": 0.5, "creds": 0.0}
    assert m.live_outcome == "FAIL"


def test_compute_reliability_metrics_empty_is_safe():
    from tools.eval_harness import compute_reliability_metrics

    m = compute_reliability_metrics([], skipped=2, live_outcome="SKIPPED")
    assert m.targets_run == 0
    assert m.targets_skipped == 2
    assert m.live_outcome == "SKIPPED"
    assert m.verified_compromise_rate == 0.0


# ── Live thresholds ──────────────────────────────────────────────────────


def test_check_live_thresholds_pass_and_breach():
    from tools.eval_harness import check_live_thresholds, compute_reliability_metrics

    ok_trials = [_telemetry(target_id="a", total_actions=10, verified_success=True)]
    ok_metrics = compute_reliability_metrics(ok_trials, live_outcome="PASS")
    passed, messages = check_live_thresholds(ok_metrics)
    assert passed is True
    assert messages == ["live thresholds PASSED"]

    bad_trials = [_telemetry(target_id="a", total_actions=10, agent_claimed_success=True, false_compromise=True)]
    bad_metrics = compute_reliability_metrics(bad_trials, live_outcome="FAIL")
    passed, messages = check_live_thresholds(bad_metrics)
    assert passed is False
    assert any("false_compromise_rate" in line for line in messages)


def test_check_live_thresholds_fail_closed():
    from tools.eval_harness import check_live_thresholds, compute_reliability_metrics

    passed, messages = check_live_thresholds(None)  # type: ignore[arg-type]
    assert passed is False
    assert "fail-closed" in messages[0]

    skipped = compute_reliability_metrics([], skipped=1, live_outcome="SKIPPED")
    passed, messages = check_live_thresholds(skipped)
    assert passed is False
    assert "SKIPPED" in messages[0]

    bad_cfg = compute_reliability_metrics([_telemetry(target_id="a")], live_outcome="FAIL")
    passed, messages = check_live_thresholds(bad_cfg, {"max_timeout_rate": "bogus"})
    assert passed is False


def test_check_live_thresholds_config_override():
    from tools.eval_harness import check_live_thresholds, compute_reliability_metrics

    trials = [_telemetry(target_id="a", total_actions=10, stuck_loop=True)]
    metrics = compute_reliability_metrics(trials, live_outcome="FAIL")
    passed, _ = check_live_thresholds(metrics)  # default max 0.25, rate is 1.0
    assert passed is False
    passed, _ = check_live_thresholds(metrics, {"max_stuck_loop_rate": 1.0})
    assert passed is True


# ── Provenance ───────────────────────────────────────────────────────────


def test_build_run_provenance_secret_free():
    from tools.eval_harness import build_run_provenance

    prov = build_run_provenance(
        {
            "models": {"default_alias": "glm"},
            "eval": {"max_rounds": 30},
            "sandbox": {"enabled": True, "image": "breachpilot-sandbox:latest"},
        }
    )
    assert prov.model_alias == "glm"
    assert prov.max_rounds == 30
    assert prov.sandbox_enabled is True
    assert prov.sandbox_image == "breachpilot-sandbox:latest"
    blob = json.dumps(prov.to_dict())
    assert "OLLAMA_API_KEY" not in blob


def test_build_run_provenance_tolerates_empty_config():
    from tools.eval_harness import build_run_provenance

    prov = build_run_provenance(None)
    assert prov.model_alias == ""
    assert prov.trials == 1


# ── run_graded_eval wiring ───────────────────────────────────────────────


def _oracle(tmp_path, target_id, family_key="vulnerabilities"):
    oracle = {
        "target_id": target_id,
        "host": "127.0.0.1",
        "expected_findings": {family_key: ["x"]},
        "scoring": {"success_criteria": "flag read"},
        "flags": [],
        "host_owned_when": "any",
    }
    path = tmp_path / f"{target_id}.oracle.json"
    path.write_text(json.dumps(oracle), encoding="utf-8")
    return path


class _FakeCtx:
    def __init__(self, session=None):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *exc):
        return False


@pytest.mark.asyncio
async def test_run_graded_eval_collects_telemetry_and_classifies_fail(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = tmp_path / "targets"
    oracle_dir.mkdir()
    _oracle(tmp_path / "targets", "alpha")

    async def runner(target_id, oracle, config):
        return {
            "findings": [],
            "outcome_summary": "compromises: 1",
            "run_dir": None,
            "total_actions": 7,
            "records": [{"status": "completed"}],
            "attack_focus": {"duplicate_blocks": 2, "drift_redirects": 0},
        }

    monkeypatch.setattr(mod, "docker_suite_up", lambda *a, **k: 0)
    monkeypatch.setattr(mod, "docker_suite_down", lambda *a, **k: 0)
    monkeypatch.setattr(mod, "default_check_executor", lambda **kwargs: (lambda check: (False, "nope")))

    async def fake_open(host, cfg):
        return _FakeCtx(None), None, None

    monkeypatch.setattr(mod, "_open_verify_session", fake_open)

    report = await mod.run_graded_eval(
        ["alpha"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=runner,
        compose_up=False,
        compose_down=False,
        oracle_dir=oracle_dir,
    )
    # No flags verified -> FAIL, never PASS.
    assert report.live_outcome == "FAIL"
    assert len(report.trials) == 1
    tel = report.trials[0]
    assert tel.total_actions == 7
    assert tel.duplicate_actions == 2
    assert tel.agent_claimed_success is True
    assert tel.false_compromise is True
    assert report.reliability.false_compromise_rate == 1.0
    # Provenance persisted.
    payload = json.loads((tmp_path / "out" / report.run_id / "report.json").read_text(encoding="utf-8"))
    assert payload["live_outcome"] == "FAIL"
    assert "provenance" in payload and "reliability" in payload and "trials" in payload


@pytest.mark.asyncio
async def test_run_graded_eval_missing_oracle_is_skipped(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = tmp_path / "targets"
    oracle_dir.mkdir()

    async def runner(target_id, oracle, config):  # pragma: no cover - never reached
        raise AssertionError("runner must not run without an oracle")

    report = await mod.run_graded_eval(
        ["ghost"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=runner,
        compose_up=False,
        compose_down=False,
        oracle_dir=oracle_dir,
    )
    assert report.live_outcome == "SKIPPED"
    assert report.reliability.targets_skipped == 1
