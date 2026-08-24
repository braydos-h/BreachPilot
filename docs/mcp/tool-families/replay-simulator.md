---
title: "Tool Family: replay-simulator"
sources:
  - tools/mcp_tools/replay_simulator.py
  - tools/replay_simulator.py
  - tools/kernel/audit.py
tests:
  - tests/test_replay_simulator.py
subsystem: mcp
---

# Tool Family: replay-simulator

- **Registration source:** `tools/mcp_tools/replay_simulator.py:22 register_replay_simulator_tools(mcp, *, ctx)` — auto-discovered but **conditionally registers** only when `(config["replay_simulator"]["enabled"]: true)` (`replay_simulator.py:25-28`). When false (default), no tools.
- **Gate:** `@audit_tool` — local-only dry-run, no target touch, pure simulation. LLM never touches target through this path.

## Tools Exported (1) — conditional

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `replay_simulate` | `plan_json: str`, `recon_json: str` (both JSON strings, must be JSON objects) | `render_simulation_result(result)` → `confidence 0..1, critique text, branch proposals` | Validates non-empty else `BLOCKED: plan_json is required.` / `recon_json is required.`; `json.loads` on each else `BLOCKED: ... is not valid JSON (...)`; type check `isinstance(..., dict)` else `BLOCKED: ... must be JSON objects.` Tries `model_client, model_alias = _get_model_client(config)` (best-effort try/except → `None` on failure); calls `simulate(plan, recon, model_client, model_alias)` (`tools/replay_simulator.py`): LLM critiques plan against `ReconAssessment`, or degrades to rule-based scoring when LLM unavailable. Zero target touch — reads `ReconAssessment` JSON + plan DAG only. |

## Dependencies

- `tools/replay_simulator.simulate`, `render_simulation_result`
- `tools/mcp_tools/registry._get_model_client` — router seam for critique LLM
- `tools/kernel/audit.make_audit_tool`

## Config

- `replay_simulator.enabled: bool` (default false) — registration gate
- `models.registry` / `ollama.host` via `build_router` for critique model; embeddings not used

## Auditing

- `@audit_tool` — `plan_json`/`recon_json` not redacted (no secret field), but large payloads are `started`/`completed` recorded with truncated not full JSON (audit stores `args` dict of strings, length capped by caller).

## Validation

- JSON parse errors surfaced as `BLOCKED` with exception text; not an exception propagation.
- Degrades gracefully to rule-based when `model_client` is `None`.

## Tests

- `tests/test_replay_simulator.py` — enabled/disabled registration, valid JSON path, invalid JSON `BLOCKED`, degrade to rules, model client path mock

## Related Docs

- `docs/mcp/tool-families/assessment-state.md` — plan DAG that `replay_simulate` critiques
- `tools/replay_simulator.py` — simulation confidence rubric
