"""Advisory witness lifecycle shared by run-service execution paths."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable

from tools.exceptions import _EXC_GROUP_CATCH
from tools.run_service.providers import EventSink


def start_witness(
    *,
    config: dict[str, Any],
    reports_dir: Path,
    event_sink: EventSink,
    agent_factory: Callable[..., Any],
    warn: Callable[[str], Any],
) -> tuple[Any | None, asyncio.Task[None] | None]:
    """Start the optional witness poller without allowing it to gate a run.

    ``agent_factory`` remains injected through ``Callables`` so tests and
    transports can control construction. The event callback bridges the
    witness's synchronous notification API to the async event sink.
    """
    witness_cfg = config.get("witness", {}) or {}
    if not bool(witness_cfg.get("enabled", False)):
        return None, None

    loop = asyncio.get_running_loop()
    escalate = bool(witness_cfg.get("escalate_to_event_broker", True))

    def _on_witness_flag(event: str, payload: dict[str, Any]) -> None:
        try:
            loop.create_task(event_sink.emit(event, payload))
        except _EXC_GROUP_CATCH:
            pass

    try:
        interval = float(witness_cfg.get("poll_interval_seconds", 5.0) or 5.0)
    except (TypeError, ValueError):
        interval = 5.0

    try:
        agent = agent_factory(
            config,
            audit_paths=[reports_dir / "activity.jsonl"],
            event_callback=_on_witness_flag if escalate else None,
        )
    except _EXC_GROUP_CATCH as exc:
        warn(f"Witness watcher unavailable (advisory, run continues): {exc}")
        return None, None

    async def _witness_poll() -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                agent.scan_once()
            except _EXC_GROUP_CATCH:
                pass

    return agent, asyncio.create_task(_witness_poll())


async def stop_witness(
    agent: Any | None,
    task: asyncio.Task[None] | None,
    result: Any,
) -> None:
    """Scan the final attempt audit tail and stop the advisory poller.

    Teardown is best-effort: witness errors must not replace the run result.
    The poller is cancelled only after the session's final audit path receives
    one synchronous scan, so records written after the last poll are covered.
    """
    if agent is not None:
        try:
            audit_path = str(result.get("audit_path", "") or "") if isinstance(result, dict) else ""
            if audit_path and agent.add_audit_path(audit_path):
                agent.scan_once()
        except _EXC_GROUP_CATCH:
            pass
        try:
            agent.stop()
        except _EXC_GROUP_CATCH:
            pass

    if task is not None:
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=0.5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
