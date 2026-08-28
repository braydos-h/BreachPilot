"""Integration tests: the witness side task wired into the run lifecycle.

Phase 1 issue 6 — WitnessAgent existed but nothing in the run lifecycle
instantiated it. These tests pin the new wiring in
``tools/run_service/execute.py`` (the transport-neutral lifecycle that serves
BOTH the CLI and API transports):

1. ``witness.enabled: true`` -> the run spawns a witness poll task; a
   synthetic allowlist_breach record appended to the wired audit trail
   during the run produces a flag in the witness log file AND (escalate
   enabled) a ``witness_flag`` event through the event sink.
2. The per-attempt exploit audit trail (exposed via the session result's
   ``audit_path``) is registered at teardown and its tail is scanned.
3. ``witness.enabled: false`` (schema default) -> the witness factory is
   NEVER called; run behavior is unchanged.
4. Run termination — success AND the session-error path — stops the witness
   and leaves no pending tasks (teardown never raises into the result path).
5. The produced witness log parses exactly the way
   ``tools/api/routes/runs.py GET /runs/{id}/witness`` expects (JSONL flag
   dicts with signal/severity/message/timestamp).

All subprocess/network surfaces are mocked; the witness factory is exercised
through the ``Callables.witness_agent_factory`` injection seam.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from tools.run_service.models import RunRequest, RunResult
from tools.run_service.providers import CancellationToken
from tools.run_service.service import AssessmentService, Callables
from tools.swarm.agents.witness_agent import WitnessAgent

# ── Helpers ──────────────────────────────────────────────────────────────


class _CaptureSink:
    """Event sink that records every emitted (event_type, payload)."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        self.events.append((event_type, payload))


class _NoDecisionProvider:
    """Fails the test if the run tries to ask the operator anything."""

    async def request(self, decision: Any) -> str:
        raise AssertionError(f"unexpected decision request: {decision.kind}")


class _FakeRouter:
    def __init__(self) -> None:
        self._clients = {"glm": object()}

    def get_client(self, name: str) -> Any:
        return self._clients[name]


def _write_config(tmp_path: Path, *, witness_enabled: bool, escalate: bool = True) -> tuple[Path, Path]:
    """Minimal config.yaml + the witness log path it points at."""
    log_path = tmp_path / "witness.jsonl"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ollama:\n"
        "  host: http://localhost:11434\n"
        "models:\n"
        "  default_alias: glm\n"
        "  registry:\n"
        "    glm: glm-5.2:cloud\n"
        "exploit:\n"
        "  permission: full_access\n"
        "  allowed_targets:\n"
        "    - 10.0.0.50\n"
        "  require_explicit_allowlist: true\n"
        "witness:\n"
        f"  enabled: {'true' if witness_enabled else 'false'}\n"
        f"  log_path: {log_path.as_posix()}\n"
        "  poll_interval_seconds: 0.05\n"
        f"  escalate_to_event_broker: {'true' if escalate else 'false'}\n"
        "api:\n"
        "  host: 127.0.0.1\n"
        "  port: 8765\n",
        encoding="utf-8",
    )
    return config_path, log_path


def _make_service(tmp_path: Path, config_path: Path, factory: Any) -> tuple[AssessmentService, Path]:
    reports_root = tmp_path / "reports"
    callables = Callables(
        build_router=lambda *a, **kw: _FakeRouter(),
        witness_agent_factory=factory,
    )
    service = AssessmentService(callables=callables)
    return service, reports_root


def _run_request(config_path: Path, reports_root: Path) -> RunRequest:
    return RunRequest(
        target="10.0.0.50",
        mode="attack",
        goal_name="recon_only",
        config_path=config_path,
        reports_dir=reports_root,
    )


def _read_witness_log(log_path: Path) -> list[dict[str, Any]]:
    """Parse the witness log exactly the way the API route does
    (tools/api/routes/runs.py GET /runs/{id}/witness)."""
    if not log_path.is_file():
        return []
    flags: list[dict[str, Any]] = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            flags.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return flags


# ── 1. enabled: breach record -> witness log flag + sink event ───────────


def test_enabled_run_flags_breach_and_escalates_event(tmp_path: Path) -> None:
    config_path, log_path = _write_config(tmp_path, witness_enabled=True, escalate=True)
    service, reports_root = _make_service(tmp_path, config_path, WitnessAgent)

    # NOTE: run_session replaced post-construction so each test controls it.
    exploit_audit = tmp_path / "exploit_workspace" / "10.0.0.50" / "attempt-1" / "exploit_audit.jsonl"

    async def _fake_run_session(**kwargs: Any) -> dict[str, Any]:
        # Append one benign + one allowlist-breach record to the per-run
        # activity trail the witness is wired to tail.
        activity = Path(kwargs["reports_dir"]) / "activity.jsonl"
        activity.parent.mkdir(parents=True, exist_ok=True)
        with activity.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.50", "status": "ok"}) + "\n")
            f.write(json.dumps({"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok"}) + "\n")
        # The per-attempt exploit audit trail (a SECOND breach target).
        exploit_audit.parent.mkdir(parents=True, exist_ok=True)
        exploit_audit.write_text(
            json.dumps({"tool_name": "lateral_exec", "target_ip": "10.0.0.77", "status": "ok"}) + "\n",
            encoding="utf-8",
        )
        # Give the witness poll loop (0.05s interval) a chance to scan.
        await asyncio.sleep(0.4)
        return {
            "total_actions": 2,
            "workspace": str(tmp_path),
            "audit_path": str(exploit_audit),
        }

    service._c.run_session = _fake_run_session  # type: ignore[union-attr]
    sink = _CaptureSink()

    async def _main() -> RunResult:
        preview = await service.prepare(_run_request(config_path, reports_root))

        result = await service.execute(
            _run_request(config_path, reports_root),
            preview,
            decision_provider=_NoDecisionProvider(),
            event_sink=sink,
            cancellation=CancellationToken(),
            model_client=object(),
            config=None,
        )
        # No pending witness/ticker tasks may survive execute().
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
        assert pending == [], f"execute() left pending tasks: {pending}"
        return result

    result = asyncio.run(_main())

    assert result.error == ""
    # The witness log exists and flags both breach targets.
    flags = _read_witness_log(log_path)
    breaches = [f for f in flags if f.get("signal") == "allowlist_breach"]
    assert breaches, f"no allowlist_breach flag in witness log: {flags}"
    flagged_targets = {str(f.get("record", {}).get("target_ip")) for f in breaches}
    assert "10.0.0.99" in flagged_targets, f"activity.jsonl breach not flagged: {flagged_targets}"
    assert "10.0.0.77" in flagged_targets, (
        f"per-attempt exploit_audit.jsonl breach not flagged (audit_path wiring + final scan broken): {flagged_targets}"
    )
    # The sink received the escalated witness_flag events.
    witness_events = [p for (evt, p) in sink.events if evt == "witness_flag"]
    assert witness_events, f"no witness_flag event through the sink; events: {[e for e, _ in sink.events]}"
    assert any(p.get("signal") == "allowlist_breach" for p in witness_events)


# ── 2. disabled: factory never called, run unchanged ─────────────────────


def test_disabled_run_never_instantiates_witness(tmp_path: Path) -> None:
    config_path, log_path = _write_config(tmp_path, witness_enabled=False)
    factory_calls: list[Any] = []

    def _counting_factory(config: Any, **kwargs: Any) -> WitnessAgent:
        factory_calls.append(config)
        return WitnessAgent(config, **kwargs)

    service, reports_root = _make_service(tmp_path, config_path, _counting_factory)

    async def _fake_run_session(**kwargs: Any) -> dict[str, Any]:
        activity = Path(kwargs["reports_dir"]) / "activity.jsonl"
        activity.parent.mkdir(parents=True, exist_ok=True)
        with activity.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok"}) + "\n")
        await asyncio.sleep(0.1)
        return {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""}

    service._c.run_session = _fake_run_session  # type: ignore[union-attr]
    sink = _CaptureSink()

    async def _main() -> RunResult:
        preview = await service.prepare(_run_request(config_path, reports_root))

        result = await service.execute(
            _run_request(config_path, reports_root),
            preview,
            decision_provider=_NoDecisionProvider(),
            event_sink=sink,
            cancellation=CancellationToken(),
            model_client=object(),
            config=None,
        )
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
        assert pending == [], f"execute() left pending tasks: {pending}"
        return result

    result = asyncio.run(_main())
    assert result.error == ""
    assert factory_calls == [], "witness factory must not be called when witness.enabled is false"
    assert not log_path.exists(), "no witness log may be written when disabled"
    assert not any(evt == "witness_flag" for evt, _p in sink.events)


# ── 3. session-error path: witness stopped cleanly ───────────────────────


def test_error_path_stops_witness_and_leaves_no_pending_tasks(tmp_path: Path) -> None:
    config_path, log_path = _write_config(tmp_path, witness_enabled=True, escalate=True)
    created: list[WitnessAgent] = []

    def _recording_factory(config: Any, **kwargs: Any) -> WitnessAgent:
        agent = WitnessAgent(config, **kwargs)
        created.append(agent)
        return agent

    service, reports_root = _make_service(tmp_path, config_path, _recording_factory)

    async def _failing_run_session(**kwargs: Any) -> dict[str, Any]:
        activity = Path(kwargs["reports_dir"]) / "activity.jsonl"
        activity.parent.mkdir(parents=True, exist_ok=True)
        with activity.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok"}) + "\n")
        await asyncio.sleep(0.2)
        raise RuntimeError("boom: session died")

    service._c.run_session = _failing_run_session  # type: ignore[union-attr]
    sink = _CaptureSink()

    async def _main() -> RunResult:
        preview = await service.prepare(_run_request(config_path, reports_root))

        result = await service.execute(
            _run_request(config_path, reports_root),
            preview,
            decision_provider=_NoDecisionProvider(),
            event_sink=sink,
            cancellation=CancellationToken(),
            model_client=object(),
            config=None,
        )
        pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]
        assert pending == [], f"error-path execute() left pending tasks: {pending}"
        return result

    result = asyncio.run(_main())
    assert "boom: session died" in result.error
    assert len(created) == 1, "the witness must be constructed on the error path too"
    assert created[0].stopped is True, "witness.stop() must be called when the run fails"
    # The witness still processed what it saw before the session died.
    flags = _read_witness_log(log_path)
    assert any(f.get("signal") == "allowlist_breach" for f in flags), flags


# ── 4. escalate=false: flags logged but no sink events ───────────────────


def test_escalate_false_logs_flags_without_sink_events(tmp_path: Path) -> None:
    config_path, log_path = _write_config(tmp_path, witness_enabled=True, escalate=False)
    service, reports_root = _make_service(tmp_path, config_path, WitnessAgent)

    async def _fake_run_session(**kwargs: Any) -> dict[str, Any]:
        activity = Path(kwargs["reports_dir"]) / "activity.jsonl"
        activity.parent.mkdir(parents=True, exist_ok=True)
        with activity.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok"}) + "\n")
        await asyncio.sleep(0.3)
        return {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""}

    service._c.run_session = _fake_run_session  # type: ignore[union-attr]
    sink = _CaptureSink()

    async def _main() -> RunResult:
        preview = await service.prepare(_run_request(config_path, reports_root))

        return await service.execute(
            _run_request(config_path, reports_root),
            preview,
            decision_provider=_NoDecisionProvider(),
            event_sink=sink,
            cancellation=CancellationToken(),
            model_client=object(),
            config=None,
        )

    result = asyncio.run(_main())
    assert result.error == ""
    flags = _read_witness_log(log_path)
    assert any(f.get("signal") == "allowlist_breach" for f in flags), flags
    assert not any(evt == "witness_flag" for evt, _p in sink.events), (
        "escalate_to_event_broker=false must not emit sink events"
    )


# ── 5. witness log shape matches the API route contract ──────────────────


def test_witness_log_shape_matches_api_route_contract(tmp_path: Path) -> None:
    """GET /runs/{id}/witness (tools/api/routes/runs.py) parses each JSONL
    line and hands the dicts to the WebUI. Pin the field contract here."""
    config_path, log_path = _write_config(tmp_path, witness_enabled=True, escalate=True)
    service, reports_root = _make_service(tmp_path, config_path, WitnessAgent)

    async def _fake_run_session(**kwargs: Any) -> dict[str, Any]:
        activity = Path(kwargs["reports_dir"]) / "activity.jsonl"
        activity.parent.mkdir(parents=True, exist_ok=True)
        with activity.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"tool_name": "run_exploit_terminal", "target_ip": "10.0.0.99", "status": "ok"}) + "\n")
        await asyncio.sleep(0.3)
        return {"total_actions": 0, "workspace": str(tmp_path), "audit_path": ""}

    service._c.run_session = _fake_run_session  # type: ignore[union-attr]

    async def _main() -> None:
        preview = await service.prepare(_run_request(config_path, reports_root))

        await service.execute(
            _run_request(config_path, reports_root),
            preview,
            decision_provider=_NoDecisionProvider(),
            event_sink=_CaptureSink(),
            cancellation=CancellationToken(),
            model_client=object(),
            config=None,
        )

    asyncio.run(_main())
    flags = _read_witness_log(log_path)
    assert flags, "witness log must exist and be parseable"
    for flag in flags:
        assert isinstance(flag, dict)
        assert flag.get("signal"), flag
        assert flag.get("severity"), flag
        assert flag.get("message"), flag
        assert flag.get("timestamp"), flag


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
