# ADR-002: Language Boundary — Keep Python, No Rewrite

**Status:** Accepted 2026-09-22 (PERF P3-03, decision record — not code).
**Scope:** Locks the PERF report conclusion against wholesale Rust/Go rewrite proposals.
**Revisit only on:** profiling evidence showing Python CPU on the critical path.

## Context

BreachPilot wall-clock time is dominated by I/O waits outside the interpreter:

- LLM provider API round-trips (chat/generate over HTTP; see `docs/providers.md`).
- MCP subprocesses (`tools/mcp_tools/` tool families via stdio/HTTP transports).
- Docker/sandbox worker lifecycle (`tools/sandbox/`, image `breachpilot-sandbox:latest`; see `docs/sandbox.md`).
- Scanners and target I/O (nmap, service enumeration, web probes, lab targets).

Python interpreter CPU is not the bottleneck. At `api.max_concurrent_runs: 3`
(`config.yaml`), process/supervisor scale arguments for a rewrite do not apply.
The P0–P2 PERF work (event broker batching, persistent HTTP pools, DB actor,
indexed replay, batch upserts, O(1) telemetry) addresses the measurable
in-process overhead without leaving Python.

## Decision

**No wholesale Rust/Go rewrite.** Target architecture stays Python end to end:

```text
Python agent loop → model client (persistent HTTP pool) → MCP/tools (subprocess I/O)
→ state updates (queues/actors) → persistent writers (SQLite conn, events/audit/telemetry JSONL)
```

**Keep in Python:** agent orchestration, FastAPI, MCP integration, model
routing, policy/approval, SQLite persistence, skills, assessment logic,
reports, swarm.

**Rust later only as a PyO3/maturin extension, after profiling proves a CPU
bottleneck:** high-volume packet/binary parsing, million-node graph
algorithms, content scanning, heavy local transforms.

**Go later only for:** a standalone sandbox/process supervisor at 100+
concurrent sessions / thousands of processes / static-binary distribution.
At `max_concurrent_runs: 3` this is premature.

## Review gate

Any native-component proposal must bring profiles showing Python CPU on the
critical path (not I/O wait). Extensions ship as optional accelerators with a
Python fallback — never hard rewrites.

## References

- `todo/perf-p3-03-no-rewrite-boundary.md` (source todo)
- `todo/perf-meta-00-order-tracker.md` (Boundary line)
- `config.yaml` (`api.max_concurrent_runs: 3`, `sandbox.*`, `docker/sandbox` image build)
- `docs/architecture.md` (ADR-001 Flow B freeze; system shape)
- `docs/providers.md`, `docs/sandbox.md`, `docs/benchmarks.md`
