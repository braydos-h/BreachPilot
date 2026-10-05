"""Phase 6.1 — evaluation/benchmark harness tests.

Covers :mod:`tools.eval_harness`:

1. ``compute_metrics`` outcome-summary parsing + verdict matrix + clamping +
   empty/robustness handling.
2. ``render_report`` / ``render_markdown`` / ``render_html`` output shape.
3. ``write_eval_report`` file creation + run-id minting.
4. ``run_eval`` end-to-end with a fully mocked MCP session + exploit session +
   config loader + model router (hermetic — no network, no subprocess).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

# ── compute_metrics ─────────────────────────────────────────────────────────


def _fr(*, outcome_summary="", total_actions=0, records=None, audit_path="", evidence=None, evidence_refs=None):
    """Build a minimal final-result dict shaped like run_exploit_agent's."""
    d: dict = {
        "outcome_summary": outcome_summary,
        "total_actions": total_actions,
        "records": records or [],
        "audit_path": audit_path,
    }
    if evidence is not None:
        d["evidence"] = evidence
    if evidence_refs is not None:
        d["evidence_refs"] = evidence_refs
    return d


def test_compute_metrics_parses_outcome_summary():
    from tools.eval_harness import compute_metrics

    m = compute_metrics(
        _fr(
            outcome_summary=(
                "consecutive blocked/unavailable outcomes: 0; ... | compromises: 2; "
                "cred dumps: 1; partials: 3; last outcome: compromise"
            ),
            total_actions=10,
            records=[],
            audit_path="/tmp/audit.jsonl",
        ),
        run_id="rid",
        target="10.0.0.5",
    )
    assert m.compromise_count == 2
    assert m.cred_dump_count == 1
    assert m.partial_count == 3
    assert m.verdict == "compromised"
    assert m.audit_path == "/tmp/audit.jsonl"
    assert m.records_count == 0
    # success_rate = (2 + 1) / 10 = 0.3
    assert m.success_rate == pytest.approx(0.3)


def test_compute_metrics_verdict_cred_dump():
    from tools.eval_harness import compute_metrics

    m = compute_metrics(_fr(outcome_summary="cred dumps: 2", total_actions=4))
    assert m.cred_dump_count == 2
    assert m.compromise_count == 0
    assert m.verdict == "cred_dump"


def test_compute_metrics_verdict_partial():
    from tools.eval_harness import compute_metrics

    m = compute_metrics(_fr(outcome_summary="partials: 1", total_actions=3))
    assert m.partial_count == 1
    assert m.verdict == "partial"


def test_compute_metrics_verdict_no_access():
    from tools.eval_harness import compute_metrics

    m = compute_metrics(_fr(outcome_summary="", total_actions=5))
    assert m.verdict == "no_access"
    assert m.success_rate == 0.0


def test_compute_metrics_verdict_error():
    from tools.eval_harness import compute_metrics

    m = compute_metrics(_fr(outcome_summary="", total_actions=0))
    assert m.verdict == "error"
    assert m.total_actions == 0
    assert m.success_rate == 0.0


def test_compute_metrics_empty_summary():
    from tools.eval_harness import compute_metrics

    # final_result={} and outcome_summary="" -> all zeros, verdict error.
    m = compute_metrics({}, run_id="r", target="t")
    assert m.compromise_count == 0
    assert m.cred_dump_count == 0
    assert m.partial_count == 0
    assert m.failure_count == 0
    assert m.total_actions == 0
    assert m.records_count == 0
    assert m.success_rate == 0.0
    assert m.verdict == "error"

    # None final_result is also tolerated.
    m2 = compute_metrics(None)
    assert m2.verdict == "error"
    assert m2.total_actions == 0


def test_compute_metrics_total_actions_and_records():
    from tools.eval_harness import compute_metrics

    records = [
        {"status": "completed", "action": "run_exploit_terminal"},
        {"status": "failed", "action": "run_exploit_terminal"},
        {"status": "blocked", "action": "write_python_file"},
    ]
    m = compute_metrics(
        _fr(outcome_summary="compromises: 1", total_actions=4, records=records),
    )
    assert m.total_actions == 4
    assert m.records_count == 3
    assert m.compromise_count == 1
    assert m.success_rate == pytest.approx(0.25)
    # failed + blocked -> 2 failures
    assert m.failure_count == 2


def test_compute_metrics_failure_substring_matching():
    from tools.eval_harness import compute_metrics

    # "error" substring in "errored" should count; "proposed" should not.
    records = [
        {"status": "errored"},
        {"status": "proposed"},
        {"status": "completed"},
    ]
    m = compute_metrics(_fr(total_actions=3, records=records))
    assert m.failure_count == 1


def test_compute_metrics_clamps_success_rate():
    from tools.eval_harness import compute_metrics

    # compromises 5 but total_actions 2 -> raw 2.5, clamp to 1.0
    m = compute_metrics(_fr(outcome_summary="compromises: 5", total_actions=2))
    assert m.compromise_count == 5
    assert m.success_rate == 1.0
    assert m.verdict == "compromised"


def test_compute_metrics_evidence_refs_collected():
    from tools.eval_harness import compute_metrics

    m = compute_metrics(
        _fr(total_actions=1, evidence=["/a/b.txt", "/c/d.txt"], evidence_refs=["/e/f.txt"]),
    )
    assert m.evidence_refs == ["/a/b.txt", "/c/d.txt", "/e/f.txt"]


def test_compute_metrics_timestamp_and_run_id():
    from tools.eval_harness import compute_metrics

    m = compute_metrics({}, run_id="abc123", target="10.0.0.7", duration_seconds=12.5)
    assert m.run_id == "abc123"
    assert m.target == "10.0.0.7"
    assert m.timestamp  # non-empty ISO string
    assert m.duration_seconds == 12.5


# ── render_report / render_markdown / render_html ───────────────────────────


def test_render_report_json_serializable():
    import json as _json

    from tools.eval_harness import compute_metrics, render_report

    m = compute_metrics(_fr(outcome_summary="compromises: 1", total_actions=2))
    out = render_report(m)
    # Must round-trip through json.dumps without raising.
    text = _json.dumps(out, default=str)
    assert _json.loads(text)["verdict"] == "compromised"


def test_render_markdown_contains_verdict_and_target():
    from tools.eval_harness import compute_metrics, render_markdown

    m = compute_metrics(_fr(outcome_summary="compromises: 1", total_actions=2), run_id="r1", target="10.0.0.99")
    md = render_markdown(m)
    assert "10.0.0.99" in md
    assert m.verdict in md
    assert "Eval Report" in md


def test_render_html_contains_target():
    from tools.eval_harness import compute_metrics, render_html

    m = compute_metrics(_fr(total_actions=1), run_id="r2", target="10.0.0.50")
    html = render_html(m)
    assert "10.0.0.50" in html
    assert "<table>" in html
    assert m.verdict in html


# ── write_eval_report ───────────────────────────────────────────────────────


def test_write_eval_report_creates_all_files(tmp_path):
    from tools.eval_harness import compute_metrics, write_eval_report

    m = compute_metrics(
        _fr(outcome_summary="compromises: 1", total_actions=3),
        run_id="writetest",
        target="10.0.0.5",
    )
    out_dir = write_eval_report(m, reports_root=tmp_path / "eval")
    assert out_dir == (tmp_path / "eval" / "writetest")
    assert out_dir.is_dir()
    assert (out_dir / "eval_report.json").is_file()
    assert (out_dir / "eval_report.md").is_file()
    assert (out_dir / "eval_report.html").is_file()

    data = json.loads((out_dir / "eval_report.json").read_text(encoding="utf-8"))
    assert data["verdict"] == "compromised"
    assert data["run_id"] == "writetest"


def test_write_eval_report_respects_flags(tmp_path):
    from tools.eval_harness import compute_metrics, write_eval_report

    m = compute_metrics(_fr(total_actions=1), run_id="flags", target="t")
    out_dir = write_eval_report(
        m,
        reports_root=tmp_path / "eval",
        write_markdown=False,
        write_html=False,
    )
    assert (out_dir / "eval_report.json").is_file()
    assert not (out_dir / "eval_report.md").exists()
    assert not (out_dir / "eval_report.html").exists()


def test_write_eval_report_mints_run_id_when_empty(tmp_path):
    from tools.eval_harness import compute_metrics, write_eval_report

    m = compute_metrics(_fr(total_actions=1), run_id="", target="t")
    assert m.run_id == ""
    out_dir = write_eval_report(m, reports_root=tmp_path / "eval")
    # run_id was minted back onto the metrics object.
    assert m.run_id != ""
    assert out_dir.name == m.run_id
    assert (out_dir / "eval_report.json").is_file()


# ── run_eval (hermetic, fully mocked) ───────────────────────────────────────


class _FakeAsyncCtx:
    """Minimal async context manager yielding a fake MCP session."""

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, exc_type, exc, tb):
        return False


def _fake_config():
    return {
        "ollama": {"host": "http://localhost:11434"},
        "models": {"default_alias": "glm", "registry": {"glm": "glm-5.2:cloud"}},
        "mcp": {"http_port": 8001},
        "eval": {
            "enabled": True,
            "output_dir": "reports/eval",
            "max_rounds": 5,
            "write_markdown": True,
            "write_html": True,
        },
    }


@pytest.mark.asyncio
async def test_run_eval_requires_target(tmp_path):
    from tools.eval_harness import run_eval

    args = SimpleNamespace(target="", config=tmp_path / "config.yaml")
    rc = await run_eval(args)
    assert rc == 2


@pytest.mark.asyncio
async def test_run_eval_writes_report_with_mocked_session(tmp_path, monkeypatch):
    import tools.eval_harness as mod
    from tools.eval import single_run

    # Patch the config loader to return our in-memory config (no file I/O).
    monkeypatch.setattr(single_run, "load_validated_config", lambda _path: _fake_config())

    # Patch the model router so no real Ollama client is built.
    fake_client = MagicMock(name="model_client")
    fake_router = MagicMock(name="router")
    fake_router.get_client.return_value = fake_client
    monkeypatch.setattr(single_run, "build_router", lambda *a, **k: fake_router)

    # Patch the MCP boot probe to yield a fake session (no subprocess).
    fake_session = MagicMock(name="mcp_session")
    fake_session.initialize = AsyncMock()
    fake_session.list_tools = AsyncMock()
    monkeypatch.setattr(
        mod,
        "open_exploit_mcp_session",
        lambda **kwargs: _FakeAsyncCtx(fake_session),
    )

    # Patch run_exploit_session to return a fake final_result dict.
    fake_result = {
        "target_ip": "10.0.0.5",
        "outcome_summary": "compromises: 1; cred dumps: 0; partials: 0",
        "total_actions": 3,
        "records": [],
        "audit_path": str(tmp_path / "audit.jsonl"),
        "workspace": str(tmp_path / "ws"),
        "messages": [],
    }
    fake_session_call = AsyncMock(return_value=fake_result)
    monkeypatch.setattr(single_run, "run_exploit_session", fake_session_call)

    # Redirect eval output into tmp_path by mutating the config's output_dir.
    monkeypatch.setattr(
        single_run,
        "load_validated_config",
        lambda _path: {
            **_fake_config(),
            "eval": {**_fake_config()["eval"], "output_dir": str(tmp_path / "eval")},
        },
    )

    args = SimpleNamespace(target="10.0.0.5", config=tmp_path / "config.yaml")
    rc = await mod.run_eval(args)

    assert rc == 0
    # run_exploit_session was awaited once with the locked target.
    fake_session_call.assert_awaited_once()
    call_kwargs = fake_session_call.await_args.kwargs
    assert call_kwargs["target_ip"] == "10.0.0.5"
    assert call_kwargs["mode"] == "attack"

    # An eval_report.json was written under tmp_path / "eval" / <run_id>.
    eval_root = tmp_path / "eval"
    json_files = list(eval_root.glob("*/eval_report.json"))
    assert len(json_files) == 1
    data = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert data["verdict"] == "compromised"
    assert data["target"] == "10.0.0.5"
    assert data["compromise_count"] == 1
    assert data["total_actions"] == 3
    # md + html written too (write_markdown/write_html both True in config).
    run_dir = json_files[0].parent
    assert (run_dir / "eval_report.md").is_file()
    assert (run_dir / "eval_report.html").is_file()


@pytest.mark.asyncio
async def test_run_eval_degrades_when_mcp_unavailable(tmp_path, monkeypatch):
    import tools.eval_harness as mod
    from tools.eval import single_run

    monkeypatch.setattr(
        single_run,
        "load_validated_config",
        lambda _path: {
            **_fake_config(),
            "eval": {**_fake_config()["eval"], "output_dir": str(tmp_path / "eval")},
        },
    )
    fake_router = MagicMock()
    fake_router.get_client.return_value = MagicMock()
    monkeypatch.setattr(single_run, "build_router", lambda *a, **k: fake_router)

    # MCP probe yields None (soft_fail) -> degrade to error report.
    monkeypatch.setattr(
        mod,
        "open_exploit_mcp_session",
        lambda **kwargs: _FakeAsyncCtx(None),
    )
    # run_exploit_session must NOT be called when the probe failed.
    session_call = AsyncMock()
    monkeypatch.setattr(single_run, "run_exploit_session", session_call)

    args = SimpleNamespace(target="10.0.0.5", config=tmp_path / "config.yaml")
    rc = await mod.run_eval(args)
    assert rc == 1
    session_call.assert_not_awaited()

    eval_root = tmp_path / "eval"
    json_files = list(eval_root.glob("*/eval_report.json"))
    assert len(json_files) == 1
    data = json.loads(json_files[0].read_text(encoding="utf-8"))
    assert data["verdict"] == "error"


# ── Graded eval loop (Feature 1): run_graded_eval ───────────────────────────


_ORACLE_A = {
    "target_id": "alpha",
    "host": "127.0.0.1",
    "expected_findings": {"services": ["ssh", "http"]},
    "scoring": {"success_criteria": "≥2 web vulns confirmed"},
    "flags": [
        {
            "id": "alpha_file_flag",
            "description": "loot file written",
            "check": {"type": "file_contains", "path": "loot://flag.txt", "pattern": "FLAG"},
        },
        {
            "id": "alpha_http_flag",
            "description": "http probe",
            "check": {"type": "http_request", "url": "http://127.0.0.1:8081/"},
        },
    ],
    "host_owned_when": "any",
}

_ORACLE_B = {
    "target_id": "beta",
    "host": "127.0.0.1",
    "expected_findings": {"services": ["ftp"]},
    "scoring": {"success_criteria": "≥2 web vulns confirmed"},
    "flags": [
        {
            "id": "beta_shell_flag",
            "description": "shell executed",
            "check": {"type": "shell_command", "exec": "id", "expect_stdout": ""},
        },
    ],
    "host_owned_when": "any",
}


def _write_oracle_dir(tmp_path):
    oracle_dir = tmp_path / "targets"
    oracle_dir.mkdir()
    (oracle_dir / "alpha.oracle.json").write_text(json.dumps(_ORACLE_A), encoding="utf-8")
    (oracle_dir / "beta.oracle.json").write_text(json.dumps(_ORACLE_B), encoding="utf-8")
    return oracle_dir


def _fake_executor_factory(passed_ids):
    """Factory returning an executor keyed on the check's loot path / exec verb."""

    def factory(session=None, workspace=None, **kwargs):
        def execute(check):
            marker = str(check.get("path", "") or check.get("exec", "") or check.get("url", ""))
            if marker in passed_ids:
                return True, f"fake pass for {marker}"
            return False, f"fake fail for {marker}"

        return execute

    return factory


def _fake_runner_factory(findings_by_target, summary="compromises: 1"):
    async def runner(target_id, oracle, config):
        return {
            "findings": findings_by_target.get(target_id, []),
            "outcome_summary": summary,
            "run_dir": None,
            "runner_completed": True,
        }

    return runner


@pytest.mark.asyncio
async def test_run_graded_eval_full_path(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = _write_oracle_dir(tmp_path)
    monkeypatch.setattr("tools.eval_harness.docker_suite_up", lambda *a, **k: 0)
    monkeypatch.setattr("tools.eval_harness.docker_suite_down", lambda *a, **k: 0)
    # No real MCP session is booted for flag verification.
    monkeypatch.setattr("tools.eval_harness.open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))
    # Executor is the truth source: loot-file flag passes, the rest fail.
    monkeypatch.setattr("tools.eval_harness.default_check_executor", _fake_executor_factory({"loot://flag.txt"}))

    findings = {
        "alpha": [
            {"type": "service", "value": "ssh"},
            {"type": "service", "value": "http"},
            {"type": "service", "value": "bogus"},
        ],
        "beta": [{"type": "service", "value": "ftp"}],
    }
    now_called = []
    report = await mod.run_graded_eval(
        None,
        {"eval": {"output_dir": str(tmp_path / "out"), "write_markdown": True, "write_html": True}},
        runner=_fake_runner_factory(findings),
        oracle_dir=oracle_dir,
        now_fn=lambda: now_called.append(1) or "2026-01-02T03:04:05+00:00",
    )

    assert now_called == [1]
    assert report.run_id != ""
    assert report.timestamp == "2026-01-02T03:04:05+00:00"
    assert report.provenance.trials == 1  # target count is not independent repeat evidence
    # All oracle targets ran, sorted (None -> all stems).
    assert [t.target_id for t in report.targets] == ["alpha", "beta"]

    alpha = report.targets[0]
    assert alpha.flags_total == 2
    assert alpha.flags_captured == 1
    assert alpha.hosts_owned == 1 and alpha.hosts_total == 1
    assert alpha.success is True  # host_owned_when=any, one flag captured
    # findings: 2 TPs (ssh, http), 1 FP (bogus) -> precision 2/3, recall 1.0
    assert alpha.findings_claimed == 3
    assert alpha.findings_verified == 2
    assert alpha.details["findings_false_positives"] == 1
    # score = mean(flags 1/2, host 1/1, F1(2/3, 1.0)=0.8)
    assert alpha.score == round((0.5 + 1.0 + 0.8) / 3, 4)

    beta = report.targets[1]
    assert beta.flags_total == 1
    assert beta.flags_captured == 0
    assert beta.hosts_owned == 0
    assert beta.success is False

    # Aggregate folds across targets.
    assert report.flags_captured_total == 1
    assert report.flags_total_total == 3
    assert report.findings_verified_total == 3
    assert report.targets_succeeded == 1

    # Reports written under output_dir/<run_id>/.
    out_dir = tmp_path / "out" / report.run_id
    data = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert data["targets"][0]["target_id"] == "alpha"
    assert data["aggregate"]["flags_captured"] == 1
    assert (out_dir / "report.md").is_file()
    assert (out_dir / "report.html").is_file()
    assert "alpha" in (out_dir / "report.md").read_text(encoding="utf-8")

    # report.json must round-trip (no non-serializable values).
    text = json.dumps(data, default=str)
    assert json.loads(text)["aggregate"]["targets_run"] == 2


@pytest.mark.asyncio
async def test_run_graded_eval_skips_missing_oracle_with_warning_row(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = _write_oracle_dir(tmp_path)
    monkeypatch.setattr("tools.eval_harness.docker_suite_up", lambda *a, **k: 0)
    monkeypatch.setattr("tools.eval_harness.docker_suite_down", lambda *a, **k: 0)
    monkeypatch.setattr("tools.eval_harness.open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))
    monkeypatch.setattr("tools.eval_harness.default_check_executor", _fake_executor_factory(set()))

    runner = _fake_runner_factory({})
    report = await mod.run_graded_eval(
        ["alpha", "ghost", "beta"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=runner,
        oracle_dir=oracle_dir,
        now_fn=lambda: "t0",
    )
    ghost = report.targets[1]
    assert ghost.target_id == "ghost"
    assert ghost.details.get("skipped")
    assert ghost.flags_total == 0
    assert ghost.success is False
    assert report.full_suite is False
    baseline = tmp_path / "baseline.json"
    with pytest.raises(ValueError, match="filtered graded-eval run"):
        mod.save_baseline(report, baseline)
    assert not baseline.exists()


@pytest.mark.asyncio
async def test_graded_eval_skips_target_without_target_side_verifier(tmp_path):
    import tools.eval_harness as mod

    oracle_dir = tmp_path / "oracles"
    oracle_dir.mkdir()
    (oracle_dir / "unverifiable.oracle.json").write_text(
        json.dumps(
            {
                "target_id": "unverifiable",
                "verification_supported": False,
                "verification_note": "target-side shell proof is unavailable",
                "flags": [],
            }
        ),
        encoding="utf-8",
    )
    runner_calls: list[str] = []

    async def runner(target_id, oracle, config):
        runner_calls.append(target_id)
        return {}

    report = await mod.run_graded_eval(
        ["unverifiable"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=runner,
        compose_up=False,
        compose_down=False,
        oracle_dir=oracle_dir,
        now_fn=lambda: "t0",
    )

    assert runner_calls == []
    assert report.live_outcome == mod.LiveOutcome.SKIPPED
    assert report.targets[0].details["skipped"] == "target-side shell proof is unavailable"


@pytest.mark.asyncio
async def test_negative_control_cannot_pass_after_runner_returns_empty_payload(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = tmp_path / "oracles"
    oracle_dir.mkdir()
    (oracle_dir / "negative.oracle.json").write_text(
        json.dumps(
            {
                "target_id": "negative",
                "host": "127.0.0.1",
                "negative_control": True,
                "host_owned_when": "never",
                "flags": [{"id": "safe-response", "check": {"type": "http_request", "url": "http://127.0.0.1/"}}],
            }
        ),
        encoding="utf-8",
    )

    async def no_op_runner(_target_id, _oracle, _config):
        return {"findings": [], "outcome_summary": ""}

    monkeypatch.setattr("tools.eval_harness.open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))
    monkeypatch.setattr("tools.eval_harness.default_check_executor", _fake_executor_factory({"safe-response"}))
    report = await mod.run_graded_eval(
        ["negative"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=no_op_runner,
        compose_up=False,
        compose_down=False,
        oracle_dir=oracle_dir,
        now_fn=lambda: "t0",
    )

    assert report.live_outcome == mod.LiveOutcome.INFRA_ERROR
    assert report.targets[0].success is False
    assert report.targets[0].details["runner_error"] is True


@pytest.mark.asyncio
async def test_run_graded_eval_compose_seams_called(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = _write_oracle_dir(tmp_path)
    up_mock = MagicMock(return_value=0)
    down_mock = MagicMock(return_value=0)
    monkeypatch.setattr("tools.eval_harness.docker_suite_up", up_mock)
    monkeypatch.setattr("tools.eval_harness.docker_suite_down", down_mock)
    monkeypatch.setattr("tools.eval_harness.open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))
    monkeypatch.setattr("tools.eval_harness.default_check_executor", _fake_executor_factory(set()))

    await mod.run_graded_eval(
        None,
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=_fake_runner_factory({}),
        oracle_dir=oracle_dir,
        now_fn=lambda: "t0",
        compose_up=True,
        compose_down=True,
    )
    up_mock.assert_called_once()
    down_mock.assert_called_once()


# ── verify_flag_check + default_check_executor (per check type) ─────────────


def test_verify_flag_check_wraps_executor_crash():
    from tools.eval_harness import verify_flag_check

    def boom(check):
        raise RuntimeError("kaput")

    result = verify_flag_check({"id": "f", "check": {"type": "file_contains", "path": "x", "pattern": "p"}}, boom)
    assert result.passed is False
    assert "kaput" in result.detail
    assert result.flag_id == "f"
    assert result.check["type"] == "file_contains"


def test_verify_flag_check_accepts_bare_check_spec():
    from tools.eval_harness import verify_flag_check

    executor = lambda check: (True, "ok")  # noqa: E731
    result = verify_flag_check({"type": "http_request", "url": "http://127.0.0.1:9/x"}, executor)
    assert result.passed is True
    # id falls back to the check type when the spec carries none.
    assert result.flag_id == "http_request"


def test_file_contains_check_loot_resolution(tmp_path):
    import tools.eval_checks as ec

    (tmp_path / "loot").mkdir()
    (tmp_path / "loot" / "flag.txt").write_text("FLAG{abc123}", encoding="utf-8")
    executor = ec.default_check_executor(workspace=tmp_path)

    passed, detail = executor({"type": "file_contains", "path": "loot://loot/flag.txt", "pattern": "FLAG"})
    assert passed, detail

    passed, detail = executor({"type": "file_contains", "path": "loot://loot/flag.txt", "pattern": "NOPE"})
    assert not passed

    # Absolute path variant (outside the workspace base).
    passed, detail = executor({"type": "file_contains", "path": str(tmp_path / "loot" / "flag.txt"), "pattern": "abc"})
    assert passed, detail


def test_file_contains_missing_file_and_missing_workspace(tmp_path):
    import tools.eval_checks as ec

    executor = ec.default_check_executor(workspace=tmp_path)
    passed, detail = executor({"type": "file_contains", "path": "loot://missing.txt", "pattern": "x"})
    assert not passed
    assert "not found" in detail

    # loot:// with no workspace at all -> failed, never raised.
    executor_nows = ec.default_check_executor(workspace=None)
    passed, detail = executor_nows({"type": "file_contains", "path": "loot://x.txt", "pattern": "x"})
    assert not passed
    assert "workspace" in detail


def test_http_request_check(monkeypatch):
    import tools.eval_checks as ec

    calls = []

    def fake_fetch(url, *, data=None, headers=None, timeout=10.0):
        calls.append(url)
        return 200, "<html>juice-shop</html>"

    monkeypatch.setattr(ec, "_http_fetch", fake_fetch)
    executor = ec.default_check_executor()

    passed, detail = executor({"type": "http_request", "url": "http://127.0.0.1:3000/"})
    assert passed, detail

    # Status mismatch fails.
    passed, _ = executor({"type": "http_request", "url": "http://127.0.0.1:3000/", "expect_status": 404})
    assert not passed

    # Body-contains mismatch fails.
    passed, _ = executor({"type": "http_request", "url": "http://127.0.0.1:3000/", "expect_body_contains": "nginx"})
    assert not passed
    assert calls == ["http://127.0.0.1:3000/"] * 3


def test_http_login_check_json_then_form(monkeypatch):
    import tools.eval_checks as ec

    seen = []

    def fake_fetch(url, *, data=None, headers=None, timeout=10.0):
        seen.append((url, data, headers))
        # JSON attempt -> 401, form attempt -> 200.
        if seen[-1][1].startswith(b"{"):
            return 401, ""
        return 200, ""

    monkeypatch.setattr(ec, "_http_fetch", fake_fetch)
    executor = ec.default_check_executor()
    passed, detail = executor(
        {"type": "http_login", "url": "http://127.0.0.1:3000/rest/user/login", "user": "a@b.c", "password": "pw"}
    )
    assert passed, detail
    assert len(seen) == 2
    assert seen[0][2]["Content-Type"] == "application/json"
    assert seen[1][2]["Content-Type"] == "application/x-www-form-urlencoded"
    # Credentials travel in every attempt (Basic header + body).
    assert seen[0][2]["Authorization"].startswith("Basic ")
    assert b"a%40b.c" in seen[1][1]  # urlencoded form body carries the user
    assert b"password=pw" in seen[1][1]


def test_http_login_check_both_attempts_fail(monkeypatch):
    import tools.eval_checks as ec

    monkeypatch.setattr(ec, "_http_fetch", lambda url, **k: (401, ""))
    executor = ec.default_check_executor()
    passed, detail = executor(
        {"type": "http_login", "url": "http://127.0.0.1:8081/login.php", "user": "u", "password": "p"}
    )
    assert not passed
    assert "401" in detail


def test_http_checks_refuse_non_loopback(monkeypatch):
    import tools.eval_checks as ec

    def _must_not_fetch(url, **k):
        raise AssertionError("no socket may be opened for a non-loopback URL")

    monkeypatch.setattr(ec, "_http_fetch", _must_not_fetch)
    executor = ec.default_check_executor()
    for check in (
        {"type": "http_request", "url": "http://10.0.0.5/"},
        {"type": "http_login", "url": "http://example.com/login", "user": "u", "password": "p"},
        {"type": "http_request", "url": "http://192.168.1.10:8081/"},
    ):
        passed, detail = executor(check)
        assert not passed
        assert "refused" in detail


def test_shell_command_check_with_sync_callable_session():
    import tools.eval_checks as ec

    def session(tool_name, arguments):
        assert tool_name == "run_exploit_terminal"
        command = arguments["command"]
        return {"output": "0\n" if command == "id -u" else ""}

    executor = ec.default_check_executor(session=session)
    passed, detail = executor({"type": "shell_command", "exec": "id -u", "expect_stdout": "0"})
    assert passed, detail

    # A missing flag file cats nothing: the any-output expect fails even
    # though the command merely exited nonzero (nonzero-exit-tolerant judge).
    passed, detail = executor({"type": "shell_command", "exec": "cat /root/flag.txt", "expect_stdout": ""})
    assert not passed
    assert "no output" in detail

    # Any-output expect with non-empty output passes.
    passed, detail = executor({"type": "shell_command", "exec": "id -u"})
    assert passed, detail


def test_shell_command_exact_stdout_does_not_match_substrings():
    import tools.eval_checks as ec

    executor = ec.default_check_executor(session=lambda *_args: {"output": "1000\n"})
    passed, detail = executor({"type": "shell_command", "exec": "id -u", "expect_stdout_exact": "0"})

    assert passed is False
    assert "exact stdout did not match" in detail


def test_shell_command_checks_use_only_stdout_from_production_terminal_envelope():
    import tools.eval_checks as ec

    outputs = {"id -u": "", "cat /root/flag.txt": "", "id -u-valid": "0\n"}

    def session(_tool_name, arguments):
        output = outputs[arguments["command"]]
        return (
            "TERMINAL_RESULT: completed (exit_code=0, duration=0.1s)\n"
            "ATTEMPT_ID: attempt-1\n"
            "COMMAND_ORIGINAL: id -u\n"
            "OUTPUT:\n"
            f"{output}"
        )

    executor = ec.default_check_executor(session=session)
    passed, detail = executor({"type": "shell_command", "exec": "id -u", "expect_stdout": "0"})
    assert not passed
    assert "not found in output" in detail

    passed, detail = executor({"type": "shell_command", "exec": "cat /root/flag.txt", "expect_stdout": ""})
    assert not passed
    assert "no output" in detail

    passed, detail = executor({"type": "shell_command", "exec": "id -u-valid", "expect_stdout": "0"})
    assert passed, detail


def test_shell_command_check_blocked_terminal_envelope_is_unverified():
    import tools.eval_checks as ec

    def session(_tool_name, _arguments):
        return "TERMINAL_RESULT: blocked (exit_code=None, duration=0.0s)\nOUTPUT:\n"

    executor = ec.default_check_executor(session=session)
    passed, detail = executor({"type": "shell_command", "exec": "id -u", "expect_stdout": "blocked"})
    assert not passed
    assert "UNVERIFIED" in detail


def test_shell_command_check_without_session_is_unverified():
    import tools.eval_checks as ec

    executor = ec.default_check_executor(session=None)
    passed, detail = executor({"type": "shell_command", "exec": "id", "expect_stdout": "0"})
    assert passed is False
    assert "UNVERIFIED" in detail


@pytest.mark.asyncio
async def test_shell_command_check_bridges_async_session_via_bound_loop():
    """An async MCP session is bridged onto its bound loop from the worker thread."""
    import asyncio

    import tools.eval_checks as ec

    class FakeAsyncSession:
        async def call_tool(self, tool_name, arguments):
            return SimpleNamespace(content=[SimpleNamespace(text="uid=0(root)")])

    loop = asyncio.get_running_loop()
    executor = ec.default_check_executor(session=FakeAsyncSession(), loop=loop)
    result = await asyncio.to_thread(
        lambda: executor({"type": "shell_command", "exec": "id", "expect_stdout": "uid=0"})
    )
    passed, detail = result
    assert passed, detail


def test_unsupported_check_type_fails():
    import tools.eval_checks as ec

    executor = ec.default_check_executor()
    passed, detail = executor({"type": "teleport", "url": "http://127.0.0.1/"})
    assert not passed
    assert "unsupported" in detail


# ── host_owned_when semantics ────────────────────────────────────────────────


def _flag_results(passed_ids, all_ids):
    from tools.eval_harness import FlagCheckResult

    return [
        FlagCheckResult(flag_id=fid, passed=fid in passed_ids, detail="", check={"type": "http_request"})
        for fid in all_ids
    ]


def test_host_owned_when_any():
    from tools.eval_harness import _host_owned_when_met

    results = _flag_results({"b"}, ["a", "b", "c"])
    assert _host_owned_when_met(results, "any") is True
    assert _host_owned_when_met(results, "any") is True
    assert _host_owned_when_met(_flag_results(set(), ["a"]), "any") is False
    # Unrecognized / missing values fall back to "any".
    assert _host_owned_when_met(results, "bogus") is True
    assert _host_owned_when_met(results, None) is True


def test_host_owned_when_all():
    from tools.eval_harness import _host_owned_when_met

    all_ids = ["a", "b"]
    assert _host_owned_when_met(_flag_results({"a", "b"}, all_ids), "all") is True
    assert _host_owned_when_met(_flag_results({"a"}, all_ids), "all") is False
    assert _host_owned_when_met(_flag_results(set(), all_ids), "all") is False


def test_host_owned_when_never_supports_negative_controls():
    from tools.eval_harness import _host_owned_when_met

    assert _host_owned_when_met(_flag_results(set(), ["no_owned_state"]), "never") is True
    assert _host_owned_when_met(_flag_results({"no_owned_state"}, ["no_owned_state"]), "never") is False


def test_negative_control_records_no_owned_hosts_and_requires_safe_verification():
    from tools.eval.graded import _build_target_score
    from tools.eval.suite import EvalSuiteResult
    from tools.eval_harness import FlagCheckResult

    oracle = {
        "negative_control": True,
        "host_owned_when": "never",
    }
    safe_check = FlagCheckResult("sqli_not_exploitable", True, "HTTP 401", {"type": "http_login"})
    no_claims = EvalSuiteResult(target_id="impossible_sqli", success=True)

    score = _build_target_score("impossible_sqli", oracle, [safe_check], no_claims, findings_claimed=0)
    failed_check = _build_target_score(
        "impossible_sqli",
        oracle,
        [FlagCheckResult("sqli_not_exploitable", False, "unexpected bypass", {"type": "http_login"})],
        no_claims,
        findings_claimed=0,
    )
    unverified_check = _build_target_score("impossible_sqli", oracle, [], no_claims, findings_claimed=0)

    assert score.hosts_owned == 0
    assert score.success is True
    assert score.details["negative_control_verified"] is True
    assert failed_check.hosts_owned == 0
    assert failed_check.success is False
    assert unverified_check.success is False
    assert unverified_check.details["negative_control_verified"] is False


def test_host_owned_when_list_of_ids():
    from tools.eval_harness import _host_owned_when_met

    all_ids = ["a", "b", "c"]
    required = ["a", "c"]
    assert _host_owned_when_met(_flag_results({"a", "c"}, all_ids), required) is True
    assert _host_owned_when_met(_flag_results({"a", "b"}, all_ids), required) is False
    assert _host_owned_when_met(_flag_results({"a", "b", "c"}, all_ids), required) is True
    # Empty list falls back to any-flag semantics (never vacuously true).
    assert _host_owned_when_met(_flag_results(set(), all_ids), []) is False
    assert _host_owned_when_met(_flag_results({"b"}, all_ids), []) is True


# ── Baseline / regression ────────────────────────────────────────────────────


def _report_with_scores(**scores_by_target):
    from tools.eval_harness import EvalReport, ReliabilityMetrics, RunProvenance, TargetScore

    targets = [
        TargetScore(
            target_id=tid,
            flags_captured=1,
            flags_total=2,
            hosts_owned=1,
            hosts_total=1,
            score=score,
            details={"findings_false_positives": 0},
        )
        for tid, score in scores_by_target.items()
    ]
    return EvalReport(
        run_id="r",
        timestamp="t",
        full_suite=True,
        targets=targets,
        live_outcome="PASS",
        provenance=RunProvenance(
            model_alias="test",
            provider="fake",
            model_id="test-model",
            model_version="1",
            temperature="0",
            seed="42",
            action_budget=30,
            max_rounds=30,
            scenario_version="oracle-sha",
            code_revision="abc1234",
            breachpilot_version="0.68.4",
            config_hash="c" * 16,
            prompt_hash="p" * 16,
            tool_catalog_hash="t" * 16,
            skill_catalog_hash="s" * 16,
            sandbox_enabled=True,
            sandbox_image="worker:sha",
            sandbox_image_digest="sha256:" + "a" * 64,
            orchestration_mode="agent",
            provider_adapter_version="1",
        ),
        reliability=ReliabilityMetrics(live_outcome="PASS", scope_violation_count=0),
    )


def test_save_baseline_and_check_regression_pass(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    report = _report_with_scores(alpha=0.8, beta=0.5)
    baseline_path = save_baseline(report, tmp_path / "baseline.json")
    assert baseline_path.is_file()
    saved = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert saved["run_id"] == "r"
    assert saved["targets"]["alpha"]["score"] == 0.8
    assert saved["targets"]["alpha"]["flags_captured"] == 1

    passed, messages = check_regression(report, baseline_path, tolerance=0.05)
    assert passed is True
    assert any("PASSED" in m for m in messages)


def test_baseline_refuses_failed_runner_or_false_positive_claims(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    baseline_path = save_baseline(_report_with_scores(alpha=0.8), tmp_path / "baseline.json")
    current = _report_with_scores(alpha=0.8)
    current.targets[0].details["findings_false_positives"] = 1
    passed, messages = check_regression(current, baseline_path)
    assert passed is False
    assert any("false-positive findings" in message for message in messages)

    current = _report_with_scores(alpha=0.8)
    current.targets[0].details["runner_error"] = True
    passed, messages = check_regression(current, baseline_path)
    assert passed is False
    assert any("target runners failed" in message for message in messages)


def test_baseline_cannot_be_initialized_from_failed_or_unmeasured_eval(tmp_path):
    from tools.eval_harness import save_baseline

    failed = _report_with_scores(alpha=0.8)
    failed.live_outcome = "FAIL"
    with pytest.raises(ValueError, match="outcome"):
        save_baseline(failed, tmp_path / "failed.json")

    unmeasured = _report_with_scores(alpha=0.8)
    unmeasured.reliability.scope_violation_count = None
    with pytest.raises(ValueError, match="scope-violation telemetry"):
        save_baseline(unmeasured, tmp_path / "unmeasured.json")

    positive = _report_with_scores(alpha=0.8)
    positive.reliability.scope_violation_count = 1
    with pytest.raises(ValueError, match="scope violations"):
        save_baseline(positive, tmp_path / "positive.json")


def test_check_regression_within_tolerance_passes(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    save_baseline(_report_with_scores(alpha=0.80), tmp_path / "baseline.json")
    passed, messages = check_regression(_report_with_scores(alpha=0.76), tmp_path / "baseline.json", tolerance=0.05)
    assert passed is True  # 0.76 >= 0.80 - 0.05
    assert any("[ok]" in m for m in messages)


def test_check_regression_requires_identical_provenance_pins(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    baseline = _report_with_scores(alpha=0.8)
    save_baseline(baseline, tmp_path / "baseline.json")
    current = _report_with_scores(alpha=0.8)
    current.provenance.config_hash = "different-config-hash"
    passed, messages = check_regression(current, tmp_path / "baseline.json")
    assert passed is False
    assert any("provenance pins differ" in message and "config_hash" in message for message in messages)


def test_check_regression_allows_code_revision_change_to_measure_regressions(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    baseline = _report_with_scores(alpha=0.8)
    save_baseline(baseline, tmp_path / "baseline.json")
    current = _report_with_scores(alpha=0.8)
    current.provenance.code_revision = "b" * 40

    passed, messages = check_regression(current, tmp_path / "baseline.json")

    assert passed is True
    assert any("regression check PASSED" in message for message in messages)


def test_check_regression_beyond_tolerance_fails(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    save_baseline(_report_with_scores(alpha=0.80), tmp_path / "baseline.json")
    passed, messages = check_regression(_report_with_scores(alpha=0.70), tmp_path / "baseline.json", tolerance=0.05)
    assert passed is False
    assert any("REGRESSION" in m for m in messages)


def test_check_regression_missing_baseline_fails_closed(tmp_path):
    from tools.eval_harness import check_regression

    passed, messages = check_regression(_report_with_scores(alpha=0.8), tmp_path / "nope.json", tolerance=0.05)
    assert passed is False
    assert any("fail-closed" in m for m in messages)


def test_check_regression_malformed_baseline_fails_closed(tmp_path):
    from tools.eval_harness import check_regression

    (tmp_path / "baseline.json").write_text("{not json", encoding="utf-8")
    passed, messages = check_regression(_report_with_scores(alpha=0.8), tmp_path / "baseline.json", tolerance=0.05)
    assert passed is False
    assert any("fail-closed" in m for m in messages)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"targets": {}},
        {"targets": {"alpha": {}}},
    ],
)
def test_check_regression_empty_or_structurally_invalid_baseline_fails_closed(tmp_path, payload):
    from tools.eval_harness import check_regression

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(payload), encoding="utf-8")
    passed, messages = check_regression(_report_with_scores(alpha=0.8), baseline_path)

    assert passed is False
    assert any("malformed baseline" in message for message in messages)


def test_check_regression_skip_only_report_fails_closed(tmp_path):
    from tools.eval_harness import EvalReport, TargetScore, check_regression, save_baseline

    baseline_path = save_baseline(_report_with_scores(alpha=0.8), tmp_path / "baseline.json")
    report = EvalReport(
        run_id="skipped",
        timestamp="t",
        live_outcome="SKIPPED",
        targets=[TargetScore(target_id="alpha", details={"skipped": "oracle unavailable"})],
    )

    passed, messages = check_regression(report, baseline_path)

    assert passed is False
    assert any("no usable executed-target result" in message for message in messages)


def test_legacy_baseline_still_hard_fails_current_scope_violation(tmp_path):
    from tools.eval_harness import check_regression

    baseline_path = tmp_path / "legacy-baseline.json"
    baseline_path.write_text(json.dumps({"targets": {"alpha": {"score": 0.8}}}), encoding="utf-8")
    report = _report_with_scores(alpha=0.8)
    report.reliability.scope_violation_count = 1

    passed, messages = check_regression(report, baseline_path)

    assert passed is False
    assert any("scope_violation_count 1 > 0" in message for message in messages)


def test_legacy_score_only_baseline_fails_closed_until_full_suite_refresh(tmp_path):
    from tools.eval_harness import check_regression

    baseline_path = tmp_path / "legacy-baseline.json"
    baseline_path.write_text(json.dumps({"targets": {"alpha": {"score": 0.8}}}), encoding="utf-8")

    passed, messages = check_regression(_report_with_scores(alpha=0.8), baseline_path)

    assert passed is False
    assert any("lacks full-suite attestation" in message for message in messages)


def test_check_regression_new_target_and_baseline_only_warning(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    save_baseline(_report_with_scores(alpha=0.8, legacy=0.9), tmp_path / "baseline.json")
    report = _report_with_scores(alpha=0.8, newcomer=0.2)
    passed, messages = check_regression(report, tmp_path / "baseline.json", tolerance=0.05)
    # A full-suite report that omitted an existing baseline target is incomplete.
    assert passed is False
    assert any("baseline target coverage differs" in m and "legacy" in m for m in messages)
    assert any("baseline missing current targets" in m and "newcomer" in m for m in messages)


# ── default_agent_runner (mocked session seam) ──────────────────────────────


@pytest.mark.asyncio
async def test_default_agent_runner_pins_target_and_does_not_mutate_config(tmp_path, monkeypatch):
    import tools.eval_harness as mod
    from tools.eval import graded

    captured = {}

    async def fake_run_exploit_session(**kwargs):
        captured.update(kwargs)
        return {
            "outcome_summary": "compromises: 1",
            "findings": [{"type": "service", "value": "ssh"}],
            "workspace": "/tmp/ws",
        }

    monkeypatch.setattr(graded, "run_exploit_session", fake_run_exploit_session)
    fake_router = MagicMock()
    fake_router.get_client.return_value = MagicMock()
    monkeypatch.setattr(graded, "build_router", lambda *a, **k: fake_router)

    config = {
        "ollama": {"host": "http://localhost:11434"},
        "models": {"default_alias": "glm", "registry": {"glm": "glm-5.2:cloud"}},
        "mcp": {"http_port": 8001},
        "eval": {"max_rounds": 5},
        "exploit": {"allowed_targets": ["127.0.0.1"]},
        mod._CONFIG_PATH_KEY: "/tmp/config.yaml",
        mod._WORKSPACE_KEY: str(tmp_path / "ws"),
        "extra_key": True,
    }
    import copy

    snapshot = copy.deepcopy(config)
    result = await mod.default_agent_runner("dvwa", {"target_id": "dvwa", "host": "127.0.0.1"}, config)

    # Caller's config dict is untouched (deep-copied, in-memory pin only).
    assert config == snapshot
    assert result["findings"] == [{"type": "service", "value": "ssh"}]
    assert result["outcome_summary"] == "compromises: 1"
    assert result["run_dir"] == "/tmp/ws"
    # The exploit session ran against the oracle host with attack settings.
    assert captured["target_ip"] == "127.0.0.1"
    assert captured["mode"] == "attack"
    assert captured["exploit_settings"].attack_max_rounds == 5


# ── Real oracle v2 schema (pins the schema work) ────────────────────────────


_SUPPORTED_CHECK_TYPES = {"http_login", "http_request", "file_contains", "shell_command"}


@pytest.mark.parametrize(
    "target_name",
    ["dvwa", "juice_shop", "metasploitable2", "vulnerable_k8s"],
)
def test_real_oracles_have_v2_flags(target_name):
    from tools.eval_harness import load_target_oracle

    oracle = load_target_oracle(Path("eval_targets") / f"{target_name}.oracle.json")
    assert oracle, f"oracle for {target_name} must parse"
    flags = oracle.get("flags")
    if oracle.get("verification_supported") is False:
        assert flags == []
        assert oracle.get("verification_note")
        return
    assert isinstance(flags, list) and flags, f"{target_name}: flags list must be non-empty"
    assert 2 <= len(flags) <= 4
    assert "host_owned_when" in oracle
    for flag in flags:
        assert isinstance(flag.get("id"), str) and flag["id"]
        assert isinstance(flag.get("description"), str) and flag["description"]
        check = flag["check"]
        assert check["type"] in _SUPPORTED_CHECK_TYPES
        url = check.get("url")
        if url is not None:
            # HTTP checks are loopback-only by design.
            assert str(url).startswith("http://127.0.0.1"), f"{target_name}/{flag['id']} non-loopback url"
