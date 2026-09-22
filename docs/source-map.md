# Source map (generated stub for TODO 011; full generator in TODO 020)

> Canonical generated map: [generated/source-map.md](generated/source-map.md)
> (`python scripts/generate_source_map.py --check` fails CI on drift).
> This file is the interim manual map; the generated file is authoritative.

| Public import | Canonical | Status | Removal |
|---|---|---|---|
| `agent_loop` | `legacy.agent_loop` | Deprecated since 0.68 | remove in 0.71 |
| `cli` | `legacy.cli` | Deprecated since 0.68 | remove in 0.71 |
| `mission` | `legacy.mission` | Deprecated since 0.68 (root `mission.py` is shim) | remove in 0.71 |
| `tool_router` | `legacy.tool_router` | Deprecated since 0.68 | remove in 0.71 |
| `executor` | `legacy.executor` | Deprecated since 0.68 | remove in 0.71 |
| `planner` | `legacy.planner` | Deprecated since 0.68 | remove in 0.71 |
| `observer` | `legacy.observer` | Deprecated since 0.68 | remove in 0.71 |
| `task_queue` | `legacy.task_queue` | Deprecated since 0.68 | remove in 0.71 |
| `evidence` | `legacy.evidence` | Deprecated since 0.68 | remove in 0.71 |
| `memory` | `legacy.memory` | Deprecated since 0.68 | remove in 0.71 |
| `finding_verifier` | `legacy.finding_verifier` | Deprecated since 0.68 | remove in 0.71 |
| `report_generator` | `legacy.report_generator` | Deprecated since 0.68 | remove in 0.71 |
| `risk_controller` | `legacy.risk_controller` | Deprecated since 0.68 | remove in 0.71 |
| `tools.autonomous_orchestrator` | `tools.campaign.*` | Facade (canonical, not deprecated) | n/a — patch-seam contract |
| `tools.config_manager` | `tools.config.*` | Re-export shim (canonical) | n/a |
| `db.py`, `scope_gate.py` | shared kernel (dual-homed) | Frozen, not a shim | n/a |

`pyproject.toml py-modules` listed the root shims for one release so the
~250-file test suite keeps importing; it shrinks toward `breachpilot.*` in
TODO 020 after the 0.69 freeze.

Batch 1 (TODO 07 Step 1, done): `evidence`, `memory`, `observer`, `planner`
— all internal + test imports now point at `legacy.*` (pure re-exports, no
logic); their root shims stay on disk emitting `DeprecationWarning` until
0.71 file deletion but are no longer listed in `py-modules` (not shipped in
wheels). `db.py`/`scope_gate.py` are shared kernel (frozen, not shims) and
stay. Next batches: `executor`, `finding_verifier`, `report_generator`,
`task_queue`, then `agent_loop`, `cli`, `mission`, `tool_router`,
`risk_controller`.
