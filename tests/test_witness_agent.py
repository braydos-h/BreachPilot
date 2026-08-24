"""Tests for the witness agent (D2) — advisory audit-stream watcher.

Covers the contract points from the build plan:

1. Feed a synthetic audit stream with one benign record + one anomalous
   record (target not in allowlist) -> the witness flags the anomaly and
   ignores the benign one.
2. The witness does NOT block or modify the run (it only writes flags +
   emits events; it has no authority over the run).
3. Failure-mode coverage:
   - witness disabled -> no flags, no crash.
   - audit stream missing -> no crash, no flags.
   - rate cap -> a flapping detector is throttled.
   - witness crash (malformed record) -> swallowed, recorded as
     ``witness_error``, does not propagate.
4. Each anomaly detector fires on its target signal and stays silent on
   benign records.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tools.swarm.agents.witness_agent import (
    WitnessAgent,
    WitnessConfig,
    WitnessContext,
    _det_allowlist_breach,
    _det_dos_drift,
    _det_permission_escalation,
    _det_poc_escape,
    _det_prompt_injection,
)

# ── Helpers ──────────────────────────────────────────────────────────────


def _write_audit(path: Path, records: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r, default=str) for r in records) + "\n", encoding="utf-8")
    return path


def _config(*, enabled: bool = True, allowed: list[str] | None = None, **kw: Any) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "witness": {"enabled": enabled, "log_path": "reports/witness.jsonl", "poll_interval_seconds": 1, **kw},
        "exploit": {"allowed_targets": allowed or ["127.0.0.1"], "require_explicit_allowlist": True},
    }
    return cfg


# ── D2 contract: benign ignored, anomaly flagged ─────────────────────────


def test_benign_record_ignored_anomaly_flagged(tmp_path: Path):
    """One benign 127.0.0.1 record + one 10.0.0.99 record (not in allowlist).
    The witness flags the anomaly and ignores the benign one."""
    audit = _write_audit(
        tmp_path / "audit.jsonl",
        [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "tool_name": "run_exploit_terminal",
                "target_ip": "127.0.0.1",
                "status": "ok",
                "command": "nmap -sV 127.0.0.1",
                "args": {},
            },
            {
                "timestamp": "2026-01-01T00:00:01Z",
                "tool_name": "run_exploit_terminal",
                "target_ip": "10.0.0.99",
                "status": "ok",
                "command": "nmap -sV 10.0.0.99",
                "args": {},
            },
        ],
    )
    flags_seen: list[dict[str, Any]] = []
    agent = WitnessAgent(
        _config(allowed=["127.0.0.1"]),
        audit_paths=[audit],
        event_callback=lambda _e, p: flags_seen.append(p),
    )
    flags = agent.scan_once()
    # Exactly one allowlist_breach flag, for the 10.0.0.99 record.
    breach = [f for f in flags if f.signal == "allowlist_breach"]
    assert len(breach) == 1, f"expected 1 breach flag, got {len(breach)}: {[f.to_dict() for f in flags]}"
    assert breach[0].record.get("target_ip") == "10.0.0.99"
    # The benign 127.0.0.1 record must NOT have been flagged.
    assert all(f.record.get("target_ip") != "127.0.0.1" for f in flags), (
        "benign 127.0.0.1 record was flagged (false positive)"
    )
    # Event callback was invoked for the flag (escalation enabled by default).
    assert any(p.get("signal") == "allowlist_breach" for p in flags_seen)


def test_witness_writes_flags_to_log(tmp_path: Path):
    """Flags are appended to the witness log JSONL."""
    audit = _write_audit(
        tmp_path / "audit.jsonl",
        [
            {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok", "args": {}},
        ],
    )
    log_path = tmp_path / "witness.jsonl"
    agent = WitnessAgent(
        _config(allowed=["127.0.0.1"], log_path=str(log_path)),
        audit_paths=[audit],
    )
    agent.scan_once()
    assert log_path.exists()
    lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(line.get("signal") == "allowlist_breach" for line in lines)


# ── D2 contract: witness does NOT block or modify the run ────────────────


def test_witness_does_not_block_or_modify_run(tmp_path: Path):
    """The witness has no return value that could block a run; ``scan_once``
    returns flags (advisory) and never raises. A run that the witness is
    watching continues regardless of what the witness flags. We verify this
    by asserting the witness exposes NO blocking API — only ``scan_once``
    (returns flags), ``stop``, and ``seen_count``."""
    audit = _write_audit(
        tmp_path / "audit.jsonl",
        [
            {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok", "args": {}},
        ],
    )
    agent = WitnessAgent(_config(allowed=["127.0.0.1"]), audit_paths=[audit])
    flags = agent.scan_once()
    # The return is advisory flags — there is no "blocked" boolean, no
    # exception, no side effect that could stop a run. The agent object has
    # no ``block``/``kill``/``modify`` method.
    assert isinstance(flags, list)
    assert not hasattr(agent, "block_run")
    assert not hasattr(agent, "kill")
    assert not hasattr(agent, "modify")


# ── Failure modes ────────────────────────────────────────────────────────


def test_witness_disabled_returns_no_flags(tmp_path: Path):
    """``witness.enabled: false`` -> scan_once is a no-op."""
    audit = _write_audit(
        tmp_path / "audit.jsonl",
        [
            {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok", "args": {}},
        ],
    )
    agent = WitnessAgent(_config(enabled=False, allowed=["127.0.0.1"]), audit_paths=[audit])
    assert agent.scan_once() == []


def test_witness_missing_audit_file_no_crash(tmp_path: Path):
    """A missing audit path is treated as "no records yet" — no crash, no flags."""
    agent = WitnessAgent(_config(allowed=["127.0.0.1"]), audit_paths=[tmp_path / "does_not_exist.jsonl"])
    assert agent.scan_once() == []


def test_witness_malformed_record_swallowed(tmp_path: Path):
    """A malformed JSONL line is skipped (not a crash). A witness crash is
    recorded as a ``witness_error`` flag and does NOT propagate."""
    path = tmp_path / "audit.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '{"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok"}\n'
        "NOT VALID JSON\n"
        '{"tool_name": "run_exploit_terminal", "target_ip": "127.0.0.1", "status": "ok"}\n',
        encoding="utf-8",
    )
    agent = WitnessAgent(_config(allowed=["127.0.0.1"]), audit_paths=[path])
    # Should not raise; the malformed line is skipped.
    flags = agent.scan_once()
    # Only the 10.0.0.99 record is a breach; the malformed line is ignored.
    assert len([f for f in flags if f.signal == "allowlist_breach"]) == 1


def test_witness_rate_cap_throttles_flapping_detector(tmp_path: Path):
    """A detector that fires on every record is throttled to
    ``max_flags_per_signal_per_minute`` flags per 60s."""
    # 20 records, all 10.0.0.99 (all would fire allowlist_breach).
    records = [
        {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok", "args": {}} for _ in range(20)
    ]
    audit = _write_audit(tmp_path / "audit.jsonl", records)
    agent = WitnessAgent(
        _config(allowed=["127.0.0.1"], max_flags_per_signal_per_minute=5),
        audit_paths=[audit],
    )
    flags = agent.scan_once()
    breach = [f for f in flags if f.signal == "allowlist_breach"]
    assert len(breach) == 5, f"rate cap should throttle to 5, got {len(breach)}"


def test_witness_sees_only_new_records_per_poll(tmp_path: Path):
    """The witness tracks byte offsets so a second poll only reads records
    appended after the first poll."""
    path = tmp_path / "audit.jsonl"
    _write_audit(
        path,
        [
            {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok", "args": {}},
        ],
    )
    agent = WitnessAgent(_config(allowed=["127.0.0.1"]), audit_paths=[path])
    first = agent.scan_once()
    assert len(first) == 1
    assert agent.seen_count == 1
    # Append a second anomalous record.
    with path.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps({"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.88", "status": "ok", "args": {}})
            + "\n"
        )
    second = agent.scan_once()
    assert len(second) == 1
    assert second[0].record.get("target_ip") == "10.0.0.88"
    assert agent.seen_count == 2


# ── Per-detector tests ───────────────────────────────────────────────────


def test_detector_poc_escape_fires_without_offline_marker():
    ctx = WitnessContext()
    record = {"tool_name": "verify_poc", "args": {"script": "print('hi')"}, "command": ""}
    flag = _det_poc_escape(record, ctx)
    assert flag is not None
    assert flag.signal == "poc_no_network_isolation"


def test_detector_poc_escape_silent_with_network_none():
    ctx = WitnessContext()
    record = {"tool_name": "verify_poc", "args": {"cmd": "docker run --network=none poc"}, "command": ""}
    assert _det_poc_escape(record, ctx) is None


def test_detector_poc_escape_silent_for_non_poc_tool():
    ctx = WitnessContext()
    record = {"tool_name": "run_exploit_terminal", "args": {}, "command": "nmap 10.0.0.5"}
    assert _det_poc_escape(record, ctx) is None


def test_detector_permission_escalation_fires_on_full_access_mid_run():
    ctx = WitnessContext(allowed_targets=["127.0.0.1"])
    # First record: read_only (the starting state). No flag yet.
    assert _det_permission_escalation({"permission": "read_only"}, ctx) is None
    # Later record: full_access. Escalation.
    flag = _det_permission_escalation({"permission": "full_access"}, ctx)
    assert flag is not None
    assert flag.signal == "permission_escalation"


def test_detector_permission_escalation_silent_for_downgrade():
    ctx = WitnessContext(allowed_targets=["127.0.0.1"])
    ctx.highest_permission = "full_access"
    assert _det_permission_escalation({"permission": "read_only"}, ctx) is None


def test_detector_prompt_injection_fires_on_search_then_write():
    ctx = WitnessContext()
    ctx.record_call(1.0, "search_threat_intel", "10.0.0.5", "ok")
    record = {"tool_name": "write_python_file", "args": {}, "target_ip": "10.0.0.5"}
    flag = _det_prompt_injection(record, ctx)
    assert flag is not None
    assert flag.signal == "prompt_injection_pattern"


def test_detector_prompt_injection_silent_with_sanitization_between():
    ctx = WitnessContext()
    ctx.record_call(1.0, "search_threat_intel", "10.0.0.5", "ok")
    ctx.record_call(2.0, "read_workspace_file", "10.0.0.5", "ok")  # sanitization step
    record = {"tool_name": "write_python_file", "args": {}, "target_ip": "10.0.0.5"}
    assert _det_prompt_injection(record, ctx) is None


def test_detector_dos_drift_fires_on_rapid_failures():
    ctx = WitnessContext()
    now = 1000.0
    for i in range(8):
        ctx.record_call(now + i, "run_exploit_terminal", "10.0.0.5", "failed")
    # The detector calls ctx.clock(); inject a fake clock that returns a time
    # after the recorded failures so they all fall in the 60s window.
    ctx.clock = lambda: now + 10
    record = {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "failed", "args": {}}
    flag = _det_dos_drift(record, ctx)
    assert flag is not None
    assert flag.signal == "dos_drift"


def test_detector_dos_drift_silent_below_threshold():
    ctx = WitnessContext()
    now = 1000.0
    for i in range(3):  # below threshold of 8
        ctx.record_call(now + i, "run_exploit_terminal", "10.0.0.5", "failed")
    record = {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.5", "status": "failed", "args": {}}
    assert _det_dos_drift(record, ctx) is None


def test_detector_allowlist_breach_silent_when_allowlist_empty():
    """An empty allowlist means the breach detector stays silent (it only
    fires when a target is NOT in a NON-EMPTY allowlist). This matches
    ``_check_allowlist`` semantics."""
    ctx = WitnessContext(allowed_targets=[])
    record = {"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "args": {}}
    assert _det_allowlist_breach(record, ctx) is None


# ── WitnessConfig parsing ────────────────────────────────────────────────


def test_witness_config_defaults_when_missing():
    cfg = WitnessConfig.from_config(None)
    assert cfg.enabled is False
    assert cfg.poll_interval_seconds == 5.0
    assert cfg.escalate_to_event_broker is True


def test_witness_config_from_config_block():
    cfg = WitnessConfig.from_config(
        {
            "witness": {"enabled": True, "poll_interval_seconds": 2.0, "log_path": "/tmp/w.jsonl"},
        }
    )
    assert cfg.enabled is True
    assert cfg.poll_interval_seconds == 2.0
    assert cfg.log_path == "/tmp/w.jsonl"


# ── demo() self-check ────────────────────────────────────────────────────


def test_demo_runs_clean(capsys: pytest.CaptureFixture[str]):
    """The ``demo()`` self-check feeds a synthetic stream and asserts the
    anomalies fire + the benign record is ignored. Imported + invoked here
    so the validation gate catches any drift in the demo path."""
    from tools.swarm.agents.witness_agent import demo

    demo()
    out = capsys.readouterr().out
    assert "witness demo: OK" in out
