# Type-checking migration strategy

BreachPilot is migrating toward strict mypy incrementally. A whole-repo
strict conversion in one PR would be reckless (hundreds of errors across
unrelated subsystems); instead, existing debt is tolerated but **new debt
is rejected**.

## The three gates (CI `types` job)

1. **Permissive check** — `mypy --follow-imports=skip tools` with the
   `disable_error_code` suppressions in `pyproject.toml`. Must pass with
   zero errors. This is the primary gate: no new *unsuppressed* errors.
2. **Debt gate** — `python scripts/mypy_debt.py` runs mypy with *zero*
   suppressions (hermetic temp config, fixed `python_version = 3.12`, fresh
   temp cache dir — the repo's ambient `.mypy_cache` is written by the
   permissive gate with different suppressions and otherwise skews the
   measurement) and
   compares against `mypy-baseline.txt` (total + per-file counts). Fails on
   **any increase** — a higher total, a higher per-file count, or errors in
   a previously clean file. Paying debt down always passes.
3. **Strict subsystems** — per-module overrides in `pyproject.toml` with
   `disable_error_code = []` plus the full `enable_error_code` list.
   Currently strict: `tools.validation_utils`, `tools.exceptions`,
   `tools.mcp_shared`, `tools.kernel.*`, `tools.sandbox.*` (Tier 1,
   2026-09-07), plus `tools.api.run_manager`, `tools.run_service.execute`,
   `tools.run_service.tasks`, `tools.exploit_agent.model_client`,
   `tools.exploit_agent.context`, `tools.config.loader`, `tools.providers`
   and `tools.providers.*` (Tier 2, 2026-09-22, todo 08).

## Graduation order

1. `tools/kernel` — done (2026-09-07).
2. `tools/api` — `run_manager.py` done (2026-09-22, todo 08: the
   `union-attr` cluster on `handle.event_broker` is decided per site via
   `RunHandle.emit` / `close_broker` None-tolerant helpers, not asserts;
   `request`/`preview` narrowed once at the top of `_execute_run`).
3. `tools/sandbox` — done (2026-09-07).
4. Orchestration/session code (`run_service/`, `mcp_session.py`,
   `campaign/`, `swarm/`) — `run_service/execute.py` + `tasks.py` done
   (2026-09-22, todo 08: cross-mixin members declared under
   `TYPE_CHECKING` so the `AssessmentService` MRO is untouched at runtime;
   `except (..., *_EXC_GROUP_CATCH)` simplified to `except _EXC_GROUP_CATCH`
   — the tuple already covers every listed class). Remaining clusters:
   `mcp_session.py`, `attack_ui.py`.
5. Providers (`tools/providers/*` + `tools/config/loader.py`) — done
   (2026-09-22, todo 08: config accessors accept `Mapping`, not just
   `dict`; `make_model_client(host=None)` falls back to the Ollama Cloud
   default instead of forwarding None; fixed a real `config=` vs `cfg=`
   kwarg mismatch in `_get_api_key`).
6. Runner context (`tools/exploit_agent/context.py`, `model_client.py`)
   — done (2026-09-22, todo 08: retry state typed as `BaseException`,
   matching `_EXC_GROUP_CATCH`).
7. Remaining modules, highest-count first (`mypy-baseline.txt` is sorted
   for triage; error codes are dominated by `union-attr`, `attr-defined`,
   `name-defined`).

## How to graduate a module

1. Fix its errors with real types — `TypedDict`, dataclasses, `Protocol`,
   generics, explicit `Optional` + `None` narrowing. Do **not** silence
   with bare `Any`, per-file `ignore_errors`, or new `disable_error_code`
   entries.
2. Add the module to a strict override in `pyproject.toml` (copy the
   `enable_error_code` list from the `tools.kernel.*` block).
3. Run `python scripts/mypy_debt.py --update` and commit the refreshed
   `mypy-baseline.txt` together with the fixes.
4. Reduce per-file ignores as files become clean; never add new ones to
   cover new debt.

## Refreshing the baseline

Only after paying debt down: `python scripts/mypy_debt.py --update`,
verify the total dropped, commit. Never hand-edit the baseline upward —
the gate compares totals *and* per-file counts, so inflating one file
while fixing another still fails.
