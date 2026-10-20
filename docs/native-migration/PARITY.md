# Parity — WebUI/API contracts native backend must preserve

Source: `webui/` (React/TS, untouched) + `docs/api/endpoint-matrix.md`, `docs/ipc-protocol.md`, `proto/exec.proto`.

- REST: `GET /api/v1/health` (no auth, `{ready:true,version:v1}`), `GET /` SPA 200 public, `/api/*` 401 without bearer; capabilities, runs CRUD, decisions (attack exact-ALLOW / recon y|yes / goal_select names, 409 on answered), tools `POST /tools/{name}/calls` (404/403/409/500 + allowlist gate + audit row + event), config PATCH validate-before-write, secrets never return values, skills list/search/get/create/delete, plugins list, models/ollama/providers status, benchmarks, events replay/cursors, SSE `: heartbeat`, WS replay+live.
- Events: `run_created → state → recon_completed → run_completed`, `scope_denied`, `run_cancelled/run_failed`; sequence cursors survive reconnect.
- IPC: `ExecRequest/ExecResult/ExecError` version `v1` required; `SANDBOX_SCOPE_DENIED|TIMEOUT|SPAWN_FAILED|INVALID|UNAVAILABLE` fail-closed, never fall back to host exec.
- DB: schema v10 (`runs/decisions/findings/audit` + `custom_goals` NOCASE unique); reports `reports/<run_id>/` artifacts (`recon_assessment.json`, `goal_suggestions.json`, `run.json`, `session_summary.md`, `activity.jsonl`, `session_state.json`).
- Errors: JSON envelope `{error:{code,message}}`; MCP JSON-RPC 2.0 `initialize/ping/tools-list/tools-call`, unknown tool `-32601`, bad parse `-32700`.
- Auth: loopback-only bind; non-loopback requires explicit flags + env + token (mirrored in `internal/mcp.ValidateBindHost`).
- Pending parity risks: swarm/campaign event shapes, full recon field supersets, report export formats, eval harness outputs, ChatGPT proxy flows (honest 503 `proxy_runtime_missing` while oauth runtime untracked — actionable, not an unported sentinel).
