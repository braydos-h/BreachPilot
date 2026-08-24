---
title: Graph Endpoints — Legacy DAG and AttackGraph v2 Explorer
sources:
  - tools/api/routes/graph.py
  - tools/api/routes/graph_explorer.py
  - tools/api/graph_builder.py
  - tools/api/graph_service.py
  - tools/intelligence/graph/types.py
  - tools/intelligence/graph/store.py
tests:
  - tests/test_api_frontend.py
subsystem: api
---

# Graph Endpoints

Two graph surfaces share the `api.graph_route` gate:

- **Legacy DAG** `GET /api/v1/runs/{run_id}/graph` (`tools/api/routes/graph.py:167`) — lightweight temporal DAG from `exploit_audit.jsonl` + `enhanced_report.json` chains.
- **Explorer (v2)** `/api/v1/graph/runs/...` (`tools/api/routes/graph_explorer.py:1`) — per-run `AttackGraphStore` built by `tools/api/graph_builder.py` with bounded queries via `tools/api/graph_service.py`.

Both are read-only, never touch a target, never mutate artifacts, and return `404 graph_disabled` when `api.graph_route:false` (`tools/api/routes/graph.py:178`, `tools/api/routes/graph_explorer.py:61`).

## Legacy DAG — `GET /api/v1/runs/{run_id}/graph` — `get_run_graph`

`tools/api/routes/graph.py:167` — `APIRouter(prefix="/api/v1", tags=["graph"])` (`tools/api/routes/graph.py:25`).

Logic:

- Gate `if not _GRAPH_ROUTE_ENABLED` → `404 "Graph route disabled (api.graph_route=false)"` (no auth leak before gate).
- `if persistence.get_run(run_id) is None` → `404 Run not found`.
- `_read_audit(run_dir)` tries `reports/<run_id>/exploit_audit.jsonl` then `reports/<run_id>/exploit_workspace/exploit_audit.jsonl` tolerant JSONL scan (`tools/api/routes/graph.py:60`).
- `_read_enhanced_chains(run_dir)` reads `reports/<run_id>/enhanced/enhanced_report.json` `exploitation_chains` list (`tools/api/routes/graph.py:84`).
- `build_graph(records, chains)` (`tools/api/routes/graph.py:97`): deduped `tool:<name>` + `target:<ip>` nodes, `tool→target:targets`, temporal `prev_tool→tool:enables`; plus `step:<chain>:<i>:<module>` nodes and `enables` chain order edges. `{nodes:[{id,type,label,status?}], edges:[{source,target,relation}]}`.

Response `200 {run_id, nodes, edges}`.

## Explorer — `AttackGraphService` — `tools/api/graph_service.py`

Per-run `AttackGraphStore(":memory:", scope=scope_for_run(run_id))` (`scope=run:<run_id>` `tools/api/graph_builder.py:50`) populated by `build_graph_store` (`tools/api/graph_builder.py:448`): `ingest_run_metadata` (HOST/DOMAIN/IP + `RESOLVES_TO`), `ingest_audit` (OBSERVATION per `(tool,target)` + `OBSERVED_ON`), `ingest_report` (FINDING / VULNERABILITY_CANDIDATE / EVIDENCE + affected-asset HOST/ASSET + AFFECTED_BY/SUPPORTED_BY/DERIVED_FROM + chain OBSERVATION steps DEPENDS_ON). Command/args never copied (credential hygiene). Merge conflicts captured via `GraphMergeEngine` (`tools/api/graph_builder.py:197`) and returned separately, never hidden.

`AttackGraphService` (`tools/api/graph_service.py:39`):

- `_fingerprint(run, run_dir)` (`tools/api/graph_service.py:50`) = `(run.id, run.updated_at, _state_audit (mtime+size), _state_enhanced)` — `AttackGraphStore(":memory:", scope)` rebuilt when fingerprint changes, else cached LRU `dict[str,_Store]` max 8 (`tools/api/graph_service.py:78`).
- Bounds: `_GRAPH_LIMIT_MAX=500`, `_NEIGHBOR_MAX_NODES=200`, `_NEIGHBOR_MAX_HOPS=4`, `_PATH_MAX_LENGTH=8`, `_PATH_MAX_PATHS=8` (`tools/api/graph_service.py:24`).

### `GET /api/v1/graph/runs/{run_id}` — `get_graph`

`tools/api/routes/graph_explorer.py:86` — `APIRouter(prefix="/api/v1/graph", tags=["graph-explorer"])`. Query: `node_type` repeated, `status` repeated (invalid values silently ignored via `_parse_enums` `tools/api/graph_service.py:305`), `q` substring, `limit` clamped `1..500` default 300 (`_clamp` `tools/api/routes/graph_explorer.py:79`). Delegates to `service.graph(run, node_types, statuses, search, limit)` (`tools/api/graph_service.py:120`) which `_query_nodes` cross-product across `(type,status)` combos then gathers matching edges whose endpoints are included plus `total_nodes`. Returns `{run_id, scope, nodes:[to_dict], edges:[to_dict], total_nodes, truncated}`.

### `GET /api/v1/graph/runs/{run_id}/summary` — `get_summary`

`tools/api/routes/graph_explorer.py:102` → `service.summary(run)` (`tools/api/graph_service.py:153`): `store.summary()` plus `stats{hosts,domains,ips,services,findings,hypotheses,evidence,observations,vulnerability_candidates,confirmed,likely,refuted,highest_degree_node:{node_id,value,node_type,degree}, conflict_count}`. `highest_degree_node` null when no edges.

### `GET /api/v1/graph/runs/{run_id}/conflicts` — `get_conflicts`

`tools/api/routes/graph_explorer.py:111` → `service.conflicts(run)` (`tools/api/graph_service.py:201`): one entry per `GraphMergeConflict` from ingestion `{node_value, reason, existing_confidence, proposed_confidence, node_id (resolved via value), scope, built_at}`. Empty list when no conflict.

### `GET /api/v1/graph/runs/{run_id}/nodes/{node_id}` — `get_node`

`tools/api/routes/graph_explorer.py:120` → `service.node(run, node_id)` (`tools/api/graph_service.py:220`): single node detail + ≤100 connected edges + neighbors (scope-isolated). Returns `404 node_not_found` when missing or `node.scope != store.scope`. Response `{run_id, node, edges, neighbors}`.

### `GET /api/v1/graph/runs/{run_id}/nodes/{node_id}/neighbors` — `get_neighbors`

`tools/api/routes/graph_explorer.py:133` → `service.neighbors(run, node_id, max_hops, max_nodes)` (`tools/api/graph_service.py:238`). Both query params clamped: `max_hops 1..4` default 1, `max_nodes 1..200` default 50 (`tools/api/routes/graph_explorer.py:139`). BFS includes start node. `404` when start unknown. Response `{run_id, start_node, nodes, edges}`.

### `GET /api/v1/graph/runs/{run_id}/paths` — `get_paths`

`tools/api/routes/graph_explorer.py:154` → `service.paths(run, start, end, max_length, max_paths)` (`tools/api/graph_service.py:270`). Required `start`/`end` node ids; both clamped: `max_length 1..8` default 4, `max_paths 1..8` default5. Unknown endpoints → `[]` no error. Each path: `[[{distance:int, node:dict, edge:dict}]]` where `distance` starts at 1 (start node not emitted).

### Explorer Wiring & Common Checks

`graph_explorer_routes.configure(auth, persistence, config)` (`tools/api/routes/graph_explorer.py:45`) builds `AttackGraphService(persistence)` and reads `api.graph_route` into `_GRAPH_ROUTE_ENABLED`. Every handler calls `_gate()` (`tools/api/routes/graph_explorer.py:61`) before reaching the service and `_get_run(run_id)` (`tools/api/routes/graph_explorer.py:72`) which raises `404 run_not_found` if missing. All error codes use `APIError` envelope (`tools/api/errors.py:42`).

Node/edge types are the real `tools/intelligence/graph/types.py::NodeType`/`EdgeType`/`NodeStatus` members (never invented). Graph is bounded, scope-isolated, traversal-safe (`_run_dir` escape check, invalid id 404).

## Tests

Explorer routes are exercised via end-to-end WebUI tests and targeted `tests/test_api_frontend.py` suites; builder tolerance is covered by graph-store unit tests.
