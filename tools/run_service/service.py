"""AssessmentService shim — re-exports from prepare/execute/tasks."""

from __future__ import annotations

from typing import Any

from tools.run_service.execute import ExecuteMixin
from tools.run_service.prepare import (
    _COLD_INIT_LOCK,
    _DEFAULT_CALLABLES,
    Callables,
    PrepareMixin,
    _build_campaign_result_from_records,
    _config_cli_load,
    _llm_usage_line_count,
    _read_swarm_snapshot,
    _request_to_args,
    _run_telemetry,
    _TelemetryAccumulator,
)
from tools.run_service.tasks import TasksMixin


class AssessmentService(PrepareMixin, ExecuteMixin, TasksMixin):
    """Transport-neutral run preparation and execution."""

    def __init__(self, *, config: dict[str, Any] | None = None, callables: "Callables | None" = None) -> None:
        self._config = config
        self._c = callables or _DEFAULT_CALLABLES


__all__ = [
    "AssessmentService",
    "Callables",
    "_COLD_INIT_LOCK",
    "_TelemetryAccumulator",
    "_build_campaign_result_from_records",
    "_config_cli_load",
    "_llm_usage_line_count",
    "_read_swarm_snapshot",
    "_request_to_args",
    "_run_telemetry",
]
