# intelligence — AttackGraph v2 + belief/evidence primitives

Wiring status by subpackage (verified against production callers):

| Subpackage | Status | Consumers |
|---|---|---|
| `graph/` | **Active production path (WebUI/API).** `tools/api/graph_service.py` and `tools/api/graph_builder.py` wrap `AttackGraphStore` / `GraphTraversal` / `GraphMergeEngine` to back the attack-path DAG API (`GET /api/v1/runs/{run_id}/graph`, gated by `api.graph_route`). | Flow A API |
| `adapters/` | **Legacy Flow B path (best-effort).** `legacy/observer.py` lazily imports `ObserverAdapter` and `legacy/finding_verifier.py` lazily imports `FindingAdapter`; import failures degrade silently. `PlannerAdapter` / `TargetGraphV2Adapter` / `MemoryAdapter` have no production caller (tests only). | Flow B + tests |
| `belief/` | Scaffold. Consumed by `adapters/observer_adapter.py` (the legacy path above) and tests; nothing on Flow A reads it. | adapters + tests |
| `evidence/` | Scaffold. Tests only. | tests |
| `fingerprint/` | Scaffold. `fingerprint.tracker.is_permanent_failure` is used by `adapters/observer_adapter.py`; the rest is tests only. | adapters + tests |
| `schemas/` (incl. `SafeSchemaLoader`) | Scaffold. Package-internal + tests only; no production caller. | tests |

Not wired into `main.py` / `mcp_exploit_server.py` / the exploit loop
(`tools/exploit_agent/runner/_impl.py`). The graph store is the only piece with a live
production caller. `belief/`, `evidence/`, `schemas/`, and the unused adapters
remain gated behind the existing `tools.*` mypy disables — wire or delete
before 0.50.
