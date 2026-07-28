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
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

# ── compute_metrics ─────────────────────────────────────────────────────────


def _fr(*, outcome_summary="", total_actions=0, records=None, audit_path="",
        evidence=None, evidence_refs=None):
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

    m = compute_metrics(_fr(outcome_summary="compromises: 1", total_actions=2),
                        run_id="r1", target="10.0.0.99")
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
        m, reports_root=tmp_path / "eval", write_markdown=False, write_html=False,
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
        mod, "open_exploit_mcp_session",
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
    monkeypatch.setattr(mod, "load_validated_config", lambda _path: {
        **_fake_config(),
        "eval": {**_fake_config()["eval"], "output_dir": str(tmp_path / "eval")},
    })

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

    monkeypatch.setattr(mod, "load_validated_config", lambda _path: {
        **_fake_config(),
        "eval": {**_fake_config()["eval"], "output_dir": str(tmp_path / "eval")},
    })
    fake_router = MagicMock()
    fake_router.get_client.return_value = MagicMock()
    monkeypatch.setattr(mod, "build_router", lambda *a, **k: fake_router)

    # MCP probe yields None (soft_fail) -> degrade to error report.
    monkeypatch.setattr(
        mod, "open_exploit_mcp_session",
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
