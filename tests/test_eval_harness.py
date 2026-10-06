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


def test_compute_metrics_preserves_unverified_claim_without_promoting_success():
    from tools.eval_harness import compute_metrics

    m = compute_metrics(_fr(outcome_summary="unverified claims: 2", total_actions=4))
    assert m.unverified_claim_count == 2
    assert m.compromise_count == 0
    assert m.cred_dump_count == 0
    assert m.success_rate == 0.0
    assert m.verdict == "unverified_claim"


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

    # Patch the config loader to return our in-memory config (no file I/O).
    monkeypatch.setattr(mod, "load_validated_config", lambda _path: _fake_config())

    # Patch the model router so no real Ollama client is built.
    fake_client = MagicMock(name="model_client")
    fake_router = MagicMock(name="router")
    fake_router.get_client.return_value = fake_client
    monkeypatch.setattr(mod, "build_router", lambda *a, **k: fake_router)

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
    monkeypatch.setattr(mod, "run_exploit_session", fake_session_call)

    # Redirect eval output into tmp_path by mutating the config's output_dir.
    monkeypatch.setattr(
        mod,
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

    monkeypatch.setattr(
        mod,
        "load_validated_config",
        lambda _path: {
            **_fake_config(),
            "eval": {**_fake_config()["eval"], "output_dir": str(tmp_path / "eval")},
        },
    )
    fake_router = MagicMock()
    fake_router.get_client.return_value = MagicMock()
    monkeypatch.setattr(mod, "build_router", lambda *a, **k: fake_router)

    # MCP probe yields None (soft_fail) -> degrade to error report.
    monkeypatch.setattr(
        mod,
        "open_exploit_mcp_session",
        lambda **kwargs: _FakeAsyncCtx(None),
    )
    # run_exploit_session must NOT be called when the probe failed.
    session_call = AsyncMock()
    monkeypatch.setattr(mod, "run_exploit_session", session_call)

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
            {"type": "service", "value": "ssh", "evidence": "test fixture: ssh service observed"},
            {"type": "service", "value": "http", "evidence": "test fixture: HTTP service observed"},
            {"type": "service", "value": "bogus", "evidence": "test fixture: unsupported service claim"},
        ],
        "beta": [{"type": "service", "value": "ftp", "evidence": "test fixture: ftp service observed"}],
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
    # All oracle targets ran, sorted (None -> all stems).
    assert [t.target_id for t in report.targets] == ["alpha", "beta"]

    alpha = report.targets[0]
    assert alpha.flags_total == 2
    assert alpha.flags_captured == 1
    assert alpha.hosts_owned == 1 and alpha.hosts_total == 1
    assert alpha.success is False  # a post-run flag does not attribute positive success to this run
    # The default graded path has no target-bound evidence producer. Agent
    # labels and prose therefore remain unsupported instead of earning TPs.
    assert alpha.findings_claimed == 3
    assert alpha.findings_verified == 0
    assert alpha.details["findings_false_positives"] == 3
    # score = mean(flags 1/2, host 1/1, findings F1 0)
    assert alpha.score == round((0.5 + 1.0 + 0.0) / 3, 4)

    beta = report.targets[1]
    assert beta.flags_total == 1
    assert beta.flags_captured == 0
    assert beta.hosts_owned == 0
    assert beta.success is False

    # Aggregate folds across targets.
    assert report.flags_captured_total == 1
    assert report.flags_total_total == 3
    assert report.findings_verified_total == 0
    assert report.targets_succeeded == 0

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
async def test_run_graded_eval_does_not_attribute_preexisting_flag_to_noop_runner(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = _write_oracle_dir(tmp_path)
    monkeypatch.setattr(mod, "open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))
    monkeypatch.setattr(mod, "default_check_executor", _fake_executor_factory({"loot://flag.txt"}))

    async def no_op_runner(target_id, oracle, config):
        return {"findings": [], "outcome_summary": "", "total_actions": 0, "records": []}

    report = await mod.run_graded_eval(
        ["alpha"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=no_op_runner,
        oracle_dir=oracle_dir,
        compose_up=False,
        compose_down=False,
    )

    target = report.targets[0]
    assert target.flags_captured == 1
    assert target.hosts_owned == 1  # observed target state remains visible
    assert target.details["oracle_target_conditions_met"] is True
    assert target.success is False
    assert report.live_outcome == "FAIL"
    assert report.trials[0].verified_success is None
    assert report.reliability.verified_compromise_rate is None


@pytest.mark.asyncio
async def test_run_graded_eval_counts_negative_control_correct_stop_separately(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = tmp_path / "targets"
    oracle_dir.mkdir()
    oracle = {
        "target_id": "secure_web",
        "host": "127.0.0.1",
        "expected_findings": {},
        "scoring": {"success_criteria": "No verified findings"},
        "negative_control": True,
        "flags": [],
        "host_owned_when": "never",
    }
    (oracle_dir / "secure_web.oracle.json").write_text(json.dumps(oracle), encoding="utf-8")
    monkeypatch.setattr(mod, "open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))

    async def correct_stop_runner(target_id, oracle, config):
        return {
            "findings": [],
            "outcome_summary": "compromises: 0; cred dumps: 0",
            "total_actions": 1,
            "records": [
                {
                    "action": "run_web_scan",
                    "target_ip": "127.0.0.1",
                    "status": "completed",
                    "approved": True,
                    "detail": json.dumps({"target_ip": "127.0.0.1"}),
                },
            ],
        }

    report = await mod.run_graded_eval(
        ["secure_web"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=correct_stop_runner,
        oracle_dir=oracle_dir,
        compose_up=False,
        compose_down=False,
    )

    target = report.targets[0]
    trial = report.trials[0]
    assert target.success is True
    assert target.hosts_owned == 0
    assert target.details["correct_stop"] is True
    assert report.live_outcome == "PASS"
    assert trial.negative_control is True
    assert trial.correct_stop is True
    assert trial.verified_success is False
    assert report.reliability.correct_stop_count == 1
    assert report.reliability.correct_stop_rate == 1.0
    assert report.reliability.verified_compromise_rate == 0.0
    assert "Correct-stop rate (negative controls)**: 1/1 (100.0%)" in report.render_markdown()


@pytest.mark.asyncio
async def test_run_graded_eval_does_not_count_failed_action_as_negative_control_stop(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = tmp_path / "targets"
    oracle_dir.mkdir()
    oracle = {
        "target_id": "secure_web",
        "host": "127.0.0.1",
        "expected_findings": {},
        "scoring": {"success_criteria": "No verified findings"},
        "negative_control": True,
        "flags": [],
        "host_owned_when": "never",
    }
    (oracle_dir / "secure_web.oracle.json").write_text(json.dumps(oracle), encoding="utf-8")
    monkeypatch.setattr(mod, "open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))

    async def failed_action_runner(target_id, oracle, config):
        return {
            "findings": [],
            "outcome_summary": "compromises: 0; cred dumps: 0",
            "total_actions": 1,
            "records": [
                {
                    "action": "run_web_scan",
                    "target_ip": "127.0.0.1",
                    "status": "executed",
                    "approved": True,
                    "exit_code": 1,
                    "detail": json.dumps({"target_ip": "127.0.0.1"}),
                }
            ],
        }

    report = await mod.run_graded_eval(
        ["secure_web"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=failed_action_runner,
        oracle_dir=oracle_dir,
        compose_up=False,
        compose_down=False,
    )

    assert report.targets[0].success is False
    assert report.targets[0].details["correct_stop"] is False
    assert report.live_outcome == "FAIL"


@pytest.mark.asyncio
async def test_run_graded_eval_does_not_count_local_action_as_target_assessment(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = tmp_path / "targets"
    oracle_dir.mkdir()
    oracle = {
        "target_id": "secure_web",
        "host": "127.0.0.1",
        "expected_findings": {},
        "negative_control": True,
        "flags": [],
        "host_owned_when": "never",
    }
    (oracle_dir / "secure_web.oracle.json").write_text(json.dumps(oracle), encoding="utf-8")
    monkeypatch.setattr(mod, "open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))

    async def local_action_runner(target_id, oracle, config):
        return {
            "findings": [],
            "outcome_summary": "",
            "total_actions": 1,
            "records": [
                {
                    "action": "workspace_list",
                    "target_ip": "127.0.0.1",
                    "status": "completed",
                    "approved": True,
                    "detail": json.dumps({"path": "."}),
                }
            ],
        }

    report = await mod.run_graded_eval(
        ["secure_web"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=local_action_runner,
        oracle_dir=oracle_dir,
        compose_up=False,
        compose_down=False,
    )

    assert report.targets[0].details["correct_stop"] is False
    assert report.reliability.correct_stop_count == 0


@pytest.mark.asyncio
async def test_run_graded_eval_does_not_count_negative_control_noop_as_correct_stop(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = tmp_path / "targets"
    oracle_dir.mkdir()
    oracle = {
        "target_id": "secure_web",
        "host": "127.0.0.1",
        "expected_findings": {},
        "scoring": {"success_criteria": "No verified findings"},
        "negative_control": True,
        "flags": [],
        "host_owned_when": "never",
    }
    (oracle_dir / "secure_web.oracle.json").write_text(json.dumps(oracle), encoding="utf-8")
    monkeypatch.setattr(mod, "open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))

    async def no_op_runner(target_id, oracle, config):
        return {"findings": [], "outcome_summary": "", "total_actions": 0, "records": []}

    report = await mod.run_graded_eval(
        ["secure_web"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=no_op_runner,
        oracle_dir=oracle_dir,
        compose_up=False,
        compose_down=False,
    )

    assert report.targets[0].success is False
    assert report.targets[0].details["correct_stop"] is False
    assert report.live_outcome == "FAIL"
    assert report.reliability.negative_control_count == 1
    assert report.reliability.correct_stop_count == 0
    assert report.reliability.correct_stop_rate == 0.0


@pytest.mark.asyncio
async def test_run_graded_eval_negative_control_cannot_mask_positive_failure(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    oracle_dir = _write_oracle_dir(tmp_path)
    (oracle_dir / "secure_web.oracle.json").write_text(
        json.dumps(
            {
                "target_id": "secure_web",
                "host": "127.0.0.1",
                "expected_findings": {},
                "scoring": {"success_criteria": "No verified findings"},
                "negative_control": True,
                "flags": [],
                "host_owned_when": "never",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))
    monkeypatch.setattr(mod, "default_check_executor", _fake_executor_factory({"loot://flag.txt"}))

    async def runner(target_id, oracle, config):
        if target_id == "secure_web":
            return {
                "findings": [],
                "outcome_summary": "",
                "total_actions": 1,
                "records": [
                    {
                        "action": "run_web_scan",
                        "target_ip": "127.0.0.1",
                        "status": "completed",
                        "approved": True,
                        "detail": json.dumps({"target_ip": "127.0.0.1"}),
                    },
                ],
            }
        return {"findings": [], "outcome_summary": "", "total_actions": 0, "records": []}

    report = await mod.run_graded_eval(
        ["alpha", "secure_web"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=runner,
        oracle_dir=oracle_dir,
        compose_up=False,
        compose_down=False,
    )

    assert report.targets[0].details["oracle_target_conditions_met"] is True
    assert report.targets[0].success is False
    assert report.targets[1].success is True
    assert report.reliability.correct_stop_rate == 1.0
    assert report.live_outcome == "FAIL"


@pytest.mark.asyncio
async def test_run_graded_eval_binds_http_checks_to_oracle_scope(tmp_path, monkeypatch):
    import tools.eval_checks as checks
    import tools.eval_harness as mod

    oracle_dir = tmp_path / "targets"
    oracle_dir.mkdir()
    oracle = {
        "target_id": "alpha",
        "host": "127.0.0.1",
        "ports": {"http": 8081},
        "expected_findings": {},
        "scoring": {},
        "flags": [
            {
                "id": "in_scope",
                "check": {
                    "type": "http_request",
                    "url": "http://127.0.0.1:8081/status",
                    "expect_body_contains": "alpha-target",
                },
            },
            {
                "id": "other_local_service",
                "check": {
                    "type": "http_request",
                    "url": "http://127.0.0.1:2375/",
                    "expect_body_contains": "alpha-target",
                },
            },
        ],
        "host_owned_when": "any",
    }
    (oracle_dir / "alpha.oracle.json").write_text(json.dumps(oracle), encoding="utf-8")
    fetched = []

    def fake_fetch(url, **kwargs):
        fetched.append(url)
        return 200, "alpha-target response"

    monkeypatch.setattr(checks, "_http_fetch", fake_fetch)
    monkeypatch.setattr(mod, "docker_suite_up", lambda *a, **k: 0)
    monkeypatch.setattr(mod, "docker_suite_down", lambda *a, **k: 0)
    monkeypatch.setattr(mod, "open_exploit_mcp_session", lambda **kwargs: _FakeAsyncCtx(None))
    monkeypatch.setattr(mod, "default_check_executor", checks.default_check_executor)

    report = await mod.run_graded_eval(
        ["alpha"],
        {"eval": {"output_dir": str(tmp_path / "out")}},
        runner=_fake_runner_factory({}),
        oracle_dir=oracle_dir,
        now_fn=lambda: "t0",
        compose_up=False,
        compose_down=False,
    )

    target = report.targets[0]
    assert target.flags_captured == 1
    assert target.flags_total == 2
    assert fetched == ["http://127.0.0.1:8081/status"]


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
    # The skipped row is excluded from the baseline payload by save_baseline.
    baseline = tmp_path / "baseline.json"
    mod.save_baseline(report, baseline)
    saved = json.loads(baseline.read_text(encoding="utf-8"))
    assert "ghost" not in saved["targets"]
    assert set(saved["targets"]) == {"alpha", "beta"}


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

    passed, detail = executor(
        {
            "type": "http_request",
            "url": "http://127.0.0.1:3000/",
            "expect_body_contains": "juice-shop",
        }
    )
    assert passed, detail

    # Status mismatch fails.
    passed, _ = executor({"type": "http_request", "url": "http://127.0.0.1:3000/", "expect_status": 404})
    assert not passed

    # Body-contains mismatch fails.
    passed, _ = executor({"type": "http_request", "url": "http://127.0.0.1:3000/", "expect_body_contains": "nginx"})
    assert not passed
    assert calls == ["http://127.0.0.1:3000/"] * 3

    # A 2xx status with no target-specific response predicate is ambiguous.
    passed, detail = executor({"type": "http_request", "url": "http://127.0.0.1:3000/"})
    assert not passed
    assert "requires expect_body_contains" in detail
    assert calls == ["http://127.0.0.1:3000/"] * 3


def test_http_request_can_check_expected_rejection_status_without_success_marker(monkeypatch):
    import tools.eval_checks as ec

    monkeypatch.setattr(ec, "_http_fetch", lambda url, **kwargs: (401, "Unauthorized"))
    passed, detail = ec.default_check_executor()(
        {"type": "http_request", "url": "http://127.0.0.1:3000/private", "expect_status": 401}
    )
    assert passed, detail


def test_http_login_check_json_then_form(monkeypatch):
    import tools.eval_checks as ec

    seen = []
    login_page_count = 0

    def fake_fetch(url, *, data=None, headers=None, timeout=10.0, opener=None):
        nonlocal login_page_count
        seen.append((url, data, headers))
        if data is None:
            login_page_count += 1
            return 200, f'<input type="hidden" name="user_token" value="csrf-{login_page_count}">'
        # JSON attempt -> 401, form attempt -> 200.
        if seen[-1][1].startswith(b"{"):
            return 401, ""
        return 200, "welcome token=verified-session"

    monkeypatch.setattr(ec, "_http_fetch", fake_fetch)
    executor = ec.default_check_executor()
    passed, detail = executor(
        {
            "type": "http_login",
            "url": "http://127.0.0.1:3000/rest/user/login",
            "user": "a@b.c",
            "password": "pw",
            "expect_body_contains": "token=",
        }
    )
    assert passed, detail
    assert len(seen) == 4
    assert seen[1][2]["Content-Type"] == "application/json"
    assert seen[3][2]["Content-Type"] == "application/x-www-form-urlencoded"
    # Credentials travel in each POST body without changing the auth scheme.
    assert "Authorization" not in seen[1][2]
    assert seen[0][1] is None and seen[2][1] is None  # login page before each shape
    assert b"a%40b.c" in seen[3][1]  # urlencoded form body carries the user
    assert b"password=pw" in seen[3][1]
    assert b"user_token=csrf-2" in seen[3][1]


def test_http_login_check_both_attempts_fail(monkeypatch):
    import tools.eval_checks as ec

    monkeypatch.setattr(ec, "_http_fetch", lambda url, **k: (401, ""))
    executor = ec.default_check_executor()
    passed, detail = executor(
        {
            "type": "http_login",
            "url": "http://127.0.0.1:8081/login.php",
            "user": "u",
            "password": "p",
            "expect_body_contains": "token",
        }
    )
    assert not passed
    assert "401" in detail


def test_http_login_does_not_accept_ambiguous_200_or_invalid_body(monkeypatch):
    import tools.eval_checks as ec

    calls = []

    def fake_fetch(url, **kwargs):
        calls.append(url)
        return 200, "Invalid credentials"

    monkeypatch.setattr(ec, "_http_fetch", fake_fetch)
    executor = ec.default_check_executor()
    base = {"type": "http_login", "url": "http://127.0.0.1:3000/login", "user": "u", "password": "p"}

    passed, detail = executor(base)
    assert not passed
    assert "requires expect_body_contains" in detail
    assert calls == []

    passed, detail = executor({**base, "expect_body_contains": "Welcome"})
    assert not passed
    assert "body marker not found" in detail
    assert calls == [base["url"], base["url"], base["url"], base["url"]]


def test_http_login_can_verify_expected_auth_rejection_by_status(monkeypatch):
    import tools.eval_checks as ec

    monkeypatch.setattr(ec, "_http_fetch", lambda url, **kwargs: (401, "Invalid credentials"))
    passed, detail = ec.default_check_executor()(
        {
            "type": "http_login",
            "url": "http://127.0.0.1:3000/login",
            "user": "u",
            "password": "p",
            "expect_status": 401,
        }
    )
    assert passed, detail


def test_http_login_ignores_environment_proxy_for_loopback_credentials(monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    import tools.eval_checks as ec

    proxy_requests: list[str] = []
    target_requests: list[str] = []

    class ProxyHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            proxy_requests.append(self.command)
            body = b'{"token":"proxy-fabricated"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            proxy_requests.append(self.command)
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = b'{"token":"proxy-fabricated"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            target_requests.append(self.command)
            body = b"Invalid credentials"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            target_requests.append(self.command)
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = b"Invalid credentials"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    threads = [Thread(target=server.serve_forever, daemon=True) for server in (proxy, target)]
    for thread in threads:
        thread.start()
    try:
        proxy_url = f"http://127.0.0.1:{proxy.server_port}"
        for variable in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
            monkeypatch.setenv(variable, proxy_url)
        monkeypatch.setenv("no_proxy", "")
        monkeypatch.setenv("NO_PROXY", "")

        passed, _detail = ec.default_check_executor()(
            {
                "type": "http_login",
                "url": f"http://127.0.0.1:{target.server_port}/login",
                "user": "u",
                "password": "p",
                "expect_status": 200,
                "expect_body_contains": '"token"',
            }
        )
        assert not passed
        assert proxy_requests == []
        assert target_requests
    finally:
        for server in (proxy, target):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


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
        {"type": "http_request", "url": "http://local/metadata"},
        {"type": "http_request", "url": "http://localhost:8081/"},
    ):
        passed, detail = executor(check)
        assert not passed
        assert "refused" in detail


def test_http_checks_are_bound_to_the_declared_oracle_host_and_ports(monkeypatch):
    import tools.eval_checks as ec

    fetched = []

    def fake_fetch(url, **kwargs):
        fetched.append(url)
        return 200, "target-specific response"

    monkeypatch.setattr(ec, "_http_fetch", fake_fetch)
    execute = ec.default_check_executor(target_host="127.0.0.1", target_ports={8081})

    passed, detail = execute(
        {
            "type": "http_request",
            "url": "http://127.0.0.1:8081/status",
            "expect_body_contains": "target-specific response",
        }
    )
    assert passed, detail
    for url in (
        "http://127.0.0.1:2375/",
        "http://127.0.0.2:8081/",
        "http://localhost:8081/",
    ):
        passed, detail = execute({"type": "http_request", "url": url, "expect_body_contains": "x"})
        assert not passed
        assert "oracle target host/port scope" in detail
    assert fetched == ["http://127.0.0.1:8081/status"]

    no_ports = ec.default_check_executor(target_host="127.0.0.1", target_ports=[])
    passed, detail = no_ports(
        {
            "type": "http_request",
            "url": "http://127.0.0.1:8081/status",
            "expect_body_contains": "target-specific response",
        }
    )
    assert not passed
    assert "oracle target ports are missing" in detail


def test_tcp_connect_is_literal_loopback_and_oracle_port_bound(monkeypatch):
    import socket

    import tools.eval_checks as ec

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        execute = ec.default_check_executor(
            target_host="127.0.0.1",
            target_ports={port},
            http_timeout=0.2,
        )
        passed, detail = execute({"type": "tcp_connect", "host": "127.0.0.1", "port": port})
        assert passed, detail

        monkeypatch.setattr(ec.socket, "create_connection", lambda *_a, **_kw: pytest.fail("out-of-scope connect"))
        for check in (
            {"type": "tcp_connect", "host": "127.0.0.2", "port": port},
            {"type": "tcp_connect", "host": "127.0.0.1", "port": 22},
            {"type": "tcp_connect", "host": "192.0.2.1", "port": port},
            {"type": "tcp_connect", "host": "localhost", "port": port},
        ):
            passed, detail = execute(check)
            assert not passed
            assert "refused" in detail
    finally:
        listener.close()

    unbound = ec.default_check_executor()
    passed, detail = unbound({"type": "tcp_connect", "host": "127.0.0.1", "port": port})
    assert not passed
    assert "target host is missing" in detail


def test_http_fetch_rejects_redirects_outside_loopback():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    import tools.eval_checks as ec

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/metadata")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(OSError, match="outside configured loopback origin"):
            ec._http_fetch(f"http://127.0.0.1:{server.server_port}/redirect")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_fetch_rejects_redirect_to_another_loopback_authority():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    import tools.eval_checks as ec

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.2:{self.server.server_port}/metadata")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(OSError, match="outside configured loopback origin"):
            ec._http_fetch(f"http://127.0.0.1:{server.server_port}/redirect")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_fetch_itself_refuses_non_loopback_urls(monkeypatch):
    import tools.eval_checks as ec

    def _must_not_build_opener(*args, **kwargs):
        raise AssertionError("non-loopback URLs must be rejected before transport setup")

    monkeypatch.setattr(ec._urlrequest, "build_opener", _must_not_build_opener)
    with pytest.raises(OSError, match="refused non-loopback URL"):
        ec._http_fetch("http://example.com/metadata")


def test_http_fetch_refuses_localhost_alias_without_resolution(monkeypatch):
    import tools.eval_checks as ec

    def _must_not_build_opener(*args, **kwargs):
        raise AssertionError("host aliases must be rejected before name resolution")

    monkeypatch.setattr(ec._urlrequest, "build_opener", _must_not_build_opener)
    with pytest.raises(OSError, match="refused non-loopback URL"):
        ec._http_fetch("http://localhost:8081/")


@pytest.mark.parametrize("path", ["/slow-headers", "/slow-body"])
def test_http_fetch_enforces_total_deadline_during_headers_and_body(path):
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    import tools.eval_checks as ec

    class SlowServer(ThreadingHTTPServer):
        daemon_threads = True

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/slow-headers":
                # Each line arrives before the socket's inactivity timeout,
                # but the complete header block exceeds the total deadline.
                for part in (b"HTTP/1.1 200 OK\r\n", b"Content-Length: 0\r\n", b"\r\n"):
                    try:
                        self.wfile.write(part)
                        self.wfile.flush()
                    except OSError:
                        break
                    time.sleep(0.08)
                return

            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.04)
            except OSError:
                pass

        def log_message(self, *_args):
            pass

    server = SlowServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(OSError, match="deadline"):
            ec._http_fetch(f"http://127.0.0.1:{server.server_port}{path}", timeout=0.12)
        elapsed = time.monotonic() - started
        assert elapsed < 0.5
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_http_fetch_does_not_wait_for_redirect_response_body():
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    import tools.eval_checks as ec

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/final")
                self.send_header("Content-Length", "100")
                self.end_headers()
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.8)
                    self.wfile.write(b"x" * 99)
                except OSError:
                    pass
                return

            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        assert ec._http_fetch(f"http://127.0.0.1:{server.server_port}/redirect", timeout=0.5) == (200, "ok")
        assert time.monotonic() - started < 0.4
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_http_fetch_rejects_streamed_oversize_body():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    import tools.eval_checks as ec

    # Exercise the streaming overflow path with a compact local fixture while
    # keeping the production cap unchanged outside this test.
    body_limit = 1024
    body = b"x" * (body_limit + 1)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            # No Content-Length: the client must enforce the cap while reading.
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    old_limit = ec._MAX_HTTP_RESPONSE_BYTES
    ec._MAX_HTTP_RESPONSE_BYTES = body_limit
    try:
        with pytest.raises(OSError, match="response exceeds size limit"):
            ec._http_fetch(f"http://127.0.0.1:{server.server_port}/oversize", timeout=2)
    finally:
        ec._MAX_HTTP_RESPONSE_BYTES = old_limit
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_https_connection_deadline_interrupts_tls_handshake(monkeypatch):
    import socket
    import time

    import tools.eval_checks as ec

    peer, client_sock = socket.socketpair()

    class SlowTLSSocket:
        def __init__(self, sock):
            self._sock = sock

        def shutdown(self, how):
            self._sock.shutdown(how)

        def close(self):
            self._sock.close()

        def do_handshake(self):
            self._sock.recv(1)
            raise TimeoutError("TLS handshake interrupted by request deadline")

    class SlowTLSContext:
        def wrap_socket(self, sock, **kwargs):
            assert kwargs["do_handshake_on_connect"] is False
            return SlowTLSSocket(sock)

    def fake_tcp_connect(connection):
        connection.sock = client_sock

    monkeypatch.setattr(ec._httpclient.HTTPConnection, "connect", fake_tcp_connect)
    deadline = ec._HTTPDeadline()
    connection = ec._DeadlineHTTPSConnection(
        "127.0.0.1",
        timeout=0.12,
        context=SlowTLSContext(),
        deadline=deadline,
    )
    deadline.start(0.12)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="TLS handshake interrupted"):
            connection.connect()
        assert time.monotonic() - started < 0.5
    finally:
        peer.close()
        connection.close()
        with pytest.raises(TimeoutError, match="total deadline"):
            deadline.finish()


@pytest.mark.parametrize(
    "check",
    [
        {"type": "http_request", "url": "http://127.0.0.1:3000/", "expect_body_contains": "{service_marker}"},
        {
            "type": "http_login",
            "url": "http://127.0.0.1:3000/login",
            "user": "u",
            "password": "p",
            "expect_body_contains": "{login_success_marker}",
        },
    ],
)
def test_http_checks_reject_unresolved_success_markers_before_network(check, monkeypatch):
    import tools.eval_checks as ec

    monkeypatch.setattr(ec, "_http_fetch", lambda *_a, **_kw: pytest.fail("unresolved marker reached HTTP"))
    execute = ec.default_check_executor(target_host="127.0.0.1", target_ports={3000})
    passed, detail = execute(check)
    assert not passed
    assert "expect_body_contains must be resolved" in detail


def test_shell_command_check_with_explicit_target_executor():
    import tools.eval_checks as ec

    def target_shell_executor(command):
        return {"output": "0\n" if command == "id -u" else ""}

    executor = ec.default_check_executor(target_shell_executor=target_shell_executor)
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


def test_shell_command_check_without_session_is_unverified():
    import tools.eval_checks as ec

    executor = ec.default_check_executor(session=None)
    passed, detail = executor({"type": "shell_command", "exec": "id", "expect_stdout": "0"})
    assert passed is False
    assert "UNVERIFIED" in detail


@pytest.mark.asyncio
async def test_shell_command_check_bridges_async_target_executor_via_bound_loop():
    """An explicit target-bound async executor is bridged from a worker thread."""
    import asyncio

    import tools.eval_checks as ec

    loop = asyncio.get_running_loop()

    async def target_shell_executor(command):
        return SimpleNamespace(content=[SimpleNamespace(text="uid=0(root)")])

    executor = ec.default_check_executor(target_shell_executor=target_shell_executor, loop=loop)
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
    # Missing condition preserves the documented "any" default; typos fail closed.
    assert _host_owned_when_met(results, None) is True
    with pytest.raises(ValueError, match="host_owned_when"):
        _host_owned_when_met(results, "bogus")


def test_host_owned_when_all():
    from tools.eval_harness import _host_owned_when_met

    all_ids = ["a", "b"]
    assert _host_owned_when_met(_flag_results({"a", "b"}, all_ids), "all") is True
    assert _host_owned_when_met(_flag_results({"a"}, all_ids), "all") is False
    assert _host_owned_when_met(_flag_results(set(), all_ids), "all") is False


def test_host_owned_when_never_never_counts_flags_as_ownership():
    from tools.eval_harness import _host_owned_when_met

    assert _host_owned_when_met(_flag_results({"a"}, ["a"]), "never") is False
    assert _host_owned_when_met(_flag_results(set(), ["a"]), "never") is False


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
    from tools.eval_harness import EvalReport, ReliabilityMetrics, TargetScore

    targets = [
        TargetScore(target_id=tid, flags_captured=1, flags_total=2, hosts_owned=1, hosts_total=1, score=score)
        for tid, score in scores_by_target.items()
    ]
    reliability = ReliabilityMetrics(
        live_outcome="PASS",
        targets_run=len(targets),
        verified_compromise_rate=0.0,
        false_compromise_rate=0.0,
        stuck_loop_rate=0.0,
        scope_violation_count=0,
    )
    return EvalReport(run_id="r", timestamp="t", targets=targets, live_outcome="PASS", reliability=reliability)


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


def test_check_regression_within_tolerance_passes(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    save_baseline(_report_with_scores(alpha=0.80), tmp_path / "baseline.json")
    passed, messages = check_regression(_report_with_scores(alpha=0.76), tmp_path / "baseline.json", tolerance=0.05)
    assert passed is True  # 0.76 >= 0.80 - 0.05
    assert any("[ok]" in m for m in messages)


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


def test_check_regression_new_target_and_baseline_only_warning(tmp_path):
    from tools.eval_harness import check_regression, save_baseline

    save_baseline(_report_with_scores(alpha=0.8, legacy=0.9), tmp_path / "baseline.json")
    report = _report_with_scores(alpha=0.8, newcomer=0.2)
    passed, messages = check_regression(report, tmp_path / "baseline.json", tolerance=0.05)
    # New target is skipped; baseline-only target warns but does not fail.
    assert passed is True
    assert any("[new] newcomer" in m for m in messages)
    assert any("[warn]" in m and "legacy" in m for m in messages)


# ── default_agent_runner (mocked session seam) ──────────────────────────────


@pytest.mark.asyncio
async def test_default_agent_runner_pins_target_and_does_not_mutate_config(tmp_path, monkeypatch):
    import tools.eval_harness as mod

    captured = {}

    async def fake_run_exploit_session(**kwargs):
        captured.update(kwargs)
        return {
            "outcome_summary": "compromises: 1",
            "findings": [{"type": "service", "value": "ssh"}],
            "workspace": "/tmp/ws",
        }

    monkeypatch.setattr(mod, "run_exploit_session", fake_run_exploit_session)
    fake_router = MagicMock()
    fake_router.get_client.return_value = MagicMock()
    monkeypatch.setattr(mod, "build_router", lambda *a, **k: fake_router)

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
