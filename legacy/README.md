# Legacy — Flow B (Frozen)

This directory holds the **SQLite-backed research loop** that predates the current exploitation engine. It is **frozen** — no new features, no bug fixes except security.

**Active engine (what users run):** `main.py` / `app.py` → `tools/exploit_agent/` / `tools/mcp_tools/` / `tools/swarm/` / `tools/autonomous_orchestrator.py` / `tools/run_service/` / `tools/api/` (Flow A, target-locked, audited).

**Legacy (this directory):** `legacy/cli.py` + `legacy/agent_loop.py` / `legacy/mission.py` / `legacy/tool_router.py` / `legacy/risk_controller.py` / `legacy/planner.py` / `legacy/executor.py` / `legacy/observer.py` / `legacy/task_queue.py` / `legacy/evidence.py` / `legacy/finding_verifier.py` / `legacy/memory.py` / `legacy/report_generator.py` (Flow B, SQLite, scope-gated, headless/CI).

## Why two flows?

Phase 2 ADR-001 (`docs/architecture.md`) kept both in one checkout for migration: Flow B carries recon safety (`scope_gate.py`, `safety_reviewer.py`); Flow A is the modern MCP-based attack path. The checkout is honest about which is real: **Flow A is real**; Flow B is a frozen reference.

## Import rules

- New code MUST NOT import from Flow B. Use `tools/kernel/`, `tools/run_service/`, `tools/exploit_agent/`.
- Root shims (`agent_loop.py`, `cli.py`, etc.) remain for one release (248 tests still import `import agent_loop`) and emit `DeprecationWarning`. They simply do `sys.modules[__name__] = importlib.import_module("legacy.<name>")`.
- Shared kernel `db.py`, `scope_gate.py`, and `mission.py` schema are intentionally dual-homed: `legacy/mission.py` is canonical, root `mission.py` is a shim (likewise `db.py`/`scope_gate.py` stay at root until 0.50 for minimal diff).

## If you thought Flow B was the product

Run `python main.py` (Flow A menu) or `python main.py --help` — not `python cli.py`. `cli.py` is the legacy deterministic loop; `main.py` is the interactive/autonomous engine. See `docs/runtime-flows.md` (Database-Backed Research Loop vs Exploit Session Flow).

## Deletion plan

After 0.50, shims will be removed and `legacy/` may be deleted or archived. Do not add features here; add to Flow A.
