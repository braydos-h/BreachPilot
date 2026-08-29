"""BenchmarkService: API-facing owner of benchmark runs.

One service instance is configured by ``create_app`` and shared by the
benchmark routes. It owns the active run's ``asyncio.Task``, fans live events
out to subscriber queues (SSE/WS), and supports cancellation. All business
logic lives in :class:`tools.benchmark.runner.BenchmarkRunner` — this class is
lifecycle plumbing only (no benchmark logic in route handlers).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from tools.benchmark.runner import BenchmarkRunner
from tools.benchmark.storage import BenchmarkStorage

__all__ = ["BenchmarkService"]


class BenchmarkService:
    """Owns at most one active benchmark run (matches RunManager semantics)."""

    def __init__(self, config: dict[str, Any], config_path: Path) -> None:
        self.config = config
        self.config_path = Path(config_path)
        self.storage = BenchmarkStorage(
            str(((config.get("benchmark", {}) or {}).get("output_dir", "")) or "reports/benchmarks")
        )
        self._active_run_id: str | None = None
        self._active_task: asyncio.Task[Any] | None = None
        self._cancel_event: asyncio.Event | None = None
        self._subscribers: set[asyncio.Queue[dict[str, Any] | None]] = set()
        self._status: dict[str, Any] = {"run_id": None, "state": "idle", "error": ""}

    # ------------------------------------------------------------------ state

    @property
    def active_run_id(self) -> str | None:
        return self._active_run_id

    def status(self) -> dict[str, Any]:
        return dict(self._status)

    # ------------------------------------------------------------------- runs

    async def start_run(self, request: dict[str, Any]) -> dict[str, Any]:
        """Start a benchmark run; returns ``{"run_id", "state"}`` or an error.

        ``request`` keys: suite, scenarios, tags, trials, model, sandbox_required,
        timeout_seconds, save_baseline, check_regression.
        """
        if self._active_task is not None and not self._active_task.done():
            return {"error": "a benchmark run is already active", "run_id": self._active_run_id}

        suite = str(request.get("suite", "") or "").strip()
        if not suite:
            return {"error": "suite is required"}

        from tools.benchmark.models import RunConfig

        benchmark_cfg = self.config.get("benchmark", {}) or {}
        run_config = RunConfig(
            suite=suite,
            scenario_ids=[str(s) for s in (request.get("scenarios") or [])],
            tags=[str(t) for t in (request.get("tags") or [])],
            trials=int(request.get("trials") or benchmark_cfg.get("trials", 1) or 1),
            timeout_seconds=int(request.get("timeout_seconds") or benchmark_cfg.get("timeout_seconds", 1800) or 1800),
            model_alias=str(request.get("model", "") or ""),
            reasoning_profile=str(request.get("reasoning", "") or ""),
            sandbox_required=bool(request.get("sandbox_required", benchmark_cfg.get("sandbox_required", True))),
            save_baseline=bool(request.get("save_baseline", False)),
            check_regression=bool(request.get("check_regression", False)),
            output_dir=str(benchmark_cfg.get("output_dir", "reports/benchmarks") or "reports/benchmarks"),
        )
        if run_config.trials < 1 or run_config.trials > 20:
            return {"error": "trials must be between 1 and 20"}

        runner = BenchmarkRunner(self.config, self.config_path, model_alias=run_config.model_alias)
        cancel = asyncio.Event()
        self._cancel_event = cancel
        self._status = {"run_id": None, "state": "starting", "error": ""}
        task = asyncio.create_task(self._execute(runner, run_config, cancel))
        self._active_task = task
        # run_id is minted inside the task; wait briefly for it so callers can
        # address the run immediately (poll-loop avoids ordering hazards).
        for _ in range(100):
            if self._active_run_id is not None:
                break
            if task.done():
                break
            await asyncio.sleep(0.01)
        return {"run_id": self._active_run_id, "state": self._status.get("state", "starting")}

    async def _execute(self, runner: BenchmarkRunner, run_config: Any, cancel: asyncio.Event) -> None:
        loop = asyncio.get_running_loop()

        def _progress(event: dict[str, Any]) -> None:
            if event.get("run_id") and not self._active_run_id:
                self._active_run_id = str(event["run_id"])
                self._status = {"run_id": self._active_run_id, "state": "running", "error": ""}
            self._fanout(event)

        try:
            payload = await runner.run(run_config, cancel=cancel, progress=_progress)
            if payload.get("error"):
                self._status = {"run_id": self._active_run_id, "state": "error", "error": str(payload["error"])}
            else:
                self._status = {"run_id": payload.get("run_id"), "state": "completed", "error": ""}
                self._fanout({"type": "run_end", "run_id": payload.get("run_id"), "summary": payload.get("summary")})
        except asyncio.CancelledError:
            self._status = {"run_id": self._active_run_id, "state": "cancelled", "error": ""}
            raise
        except Exception as exc:  # noqa: BLE001 -- service-level guard for the API surface
            self._status = {"run_id": self._active_run_id, "state": "error", "error": str(exc)[:500]}
            self._fanout({"type": "run_error", "error": str(exc)[:500]})
        finally:
            self._active_task = None
            self._cancel_event = None
            # Keep _active_run_id so the WebUI can open the just-finished run.
            loop.call_later(0, lambda: None)

    async def cancel(self) -> bool:
        """Cancel the active run (if any). Returns True when cancelled."""
        if self._cancel_event is not None:
            self._cancel_event.set()
            self._status = {"run_id": self._active_run_id, "state": "cancelling", "error": ""}
            return True
        return False

    # ------------------------------------------------------------- streaming

    def subscribe(self) -> asyncio.Queue[dict[str, Any] | None]:
        """Register a live-event subscriber queue (caller drains + unsubscribes)."""
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=1000)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any] | None]) -> None:
        self._subscribers.discard(queue)

    def _fanout(self, event: dict[str, Any]) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop the oldest for slow consumers rather than blocking runs.
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except Exception:  # noqa: BLE001
                    pass

    async def shutdown(self) -> None:
        """Cancel the active run and stop subscribers (app lifespan exit)."""
        await self.cancel()
        task = self._active_task
        if task is not None:
            try:
                await asyncio.wait_for(task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
                task.cancel()
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(None)
            except Exception:  # noqa: BLE001
                pass
        self._subscribers.clear()
