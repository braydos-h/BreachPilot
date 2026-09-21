# Legacy — Flow B (Frozen)

This directory holds the **SQLite-backed research loop** that predates the current exploitation engine. It is **frozen** — no new features, no bug fixes except security.

**Active engine (what users run):** `main.py` / `app.py` → `tools/exploit_agent/` / `tools/mcp_tools/` / `tools/swarm/` / `tools/autonomous_orchestrator.py` / `tools/run_service/` / `tools/api/` (Flow A, target-locked, audited).

**Legacy (this directory):** `legacy/cli.py` + `legacy/agent_loop.py` / `legacy/mission.py` / `legacy/tool_router.py` / `legacy/risk_controller.py` / `legacy/planner.py` / `legacy/executor.py` / `legacy/observer.py` / `legacy/task_queue.py` / `legacy/evidence.py` / `legacy/finding_verifier.py` / `legacy/memory.py` / `legacy/report_generator.py` (Flow B, SQLite, scope-gated, headless/CI).

## Why two flows?

Phase 2 ADR-001 (`docs/architecture.md`) kept both in one checkout for migration: Flow B carries recon safety (`scope_gate.py`, `safety_reviewer.py`); Flow A is the modern MCP-based attack path. The checkout is honest about which is real: **Flow A is real**; Flow B is a frozen reference.

## Import rules

- New code MUST NOT import from Flow B. Use `tools/kernel/`, `tools/run_service/`, `tools/exploit_agent/`.
- Root shims (`agent_loop.py`, `cli.py`, etc.) remain until 0.71 (deprecated since 0.68; the ~250-file test suite still imports `import agent_loop`) and emit `DeprecationWarning`. They simply do `sys.modules[__name__] = importlib.import_module("legacy.<name>")`.
- Shared kernel `db.py`, `scope_gate.py`, `outcome_judge.py`, `target_graph.py`, `summarizer.py` are real files at the repo root (NOT shims) used by both flows; they stay at root and remain importable as `from db import ...`. `legacy/mission.py` is canonical for mission schema, root `mission.py` is a shim.
- Inside `legacy/`, Flow B siblings import each other via the canonical `legacy.*` path (`from legacy.mission import ...`), never via root-shim paths.

## Canonical namespace decision (p2-05)

The canonical Flow B namespace is **`legacy.*`**. The proposed
`breachpilot.legacy.*` package rename is **dropped as unnecessary churn**:
no `breachpilot` package exists (`pyproject.toml` exposes top-level
`legacy` + `tools` packages and root `py-modules` shims), editable and
wheel installs already import `legacy.*`, and a rename would touch every
consumer for zero runtime benefit.

Allowed `legacy.*` consumers outside `legacy/` (enforced by
`tests/test_legacy_shims.py`, everything else importing `legacy` fails CI):

- `tools/intelligence/adapters/{observer,memory,finding}_adapter.py` — frozen-surface bridges (defects C4/C5/C6)
- `tools/interactive_menu.py` — mission-management submenu (`legacy.mission`)
- `tools/run_service/tasks.py` — swarm bridge (`legacy.agent_loop`)

## If you thought Flow B was the product

Run `python main.py` (Flow A menu) or `python main.py --help` — not `python cli.py`. `cli.py` is the legacy deterministic loop; `main.py` is the interactive/autonomous engine. See `docs/runtime-flows.md` (Database-Backed Research Loop vs Exploit Session Flow).

## Deletion plan

After 0.71, shims will be removed and `legacy/` may be deleted or archived. Do not add features here; add to Flow A. Import hygiene is enforced by `tests/test_legacy_shims.py` (shim warnings + canonical-namespace imports + banned-import lint).
