"""Legacy Flow B package — frozen.

Canonical location for the SQLite-backed research loop (cli.py + agent_loop.py / mission.py / scope_gate.py / risk_controller.py / tool_router.py / planner.py / executor.py / observer.py / task_queue.py / evidence.py / finding_verifier.py / memory.py / report_generator.py).

Frozen per docs/architecture.md ADR-001 (2026-08-24). No new features. Active engine is Flow A: main.py / app.py → tools/exploit_agent/ / tools/mcp_tools/ / tools/swarm/.

Root-level shims (e.g. `import agent_loop`) remain for one release and emit DeprecationWarning; new code must import from `legacy.*` or preferably from Flow A.

Shared kernel (db.py, mission.py schema, scope_gate.py) stays at repo root for backwards compat until 0.50; legacy/mission.py is the canonical copy, root mission.py is a shim (see mission.py shim).
"""
