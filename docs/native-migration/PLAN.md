# Native Migration Plan — Go + Rust, Zero Python

> Goal: fully functional BreachPilot on Go (control plane) + Rust (execution plane) + existing TypeScript WebUI, with zero Python dependency.

## Architecture

- Go owns: entrypoint `cmd/bp`, HTTP REST + WS/SSE `internal/api`, auth `internal/auth`, runs `internal/runner`, agent `internal/agent`, swarm/campaign (to complete), MCP `internal/mcp`, config `internal/config`, secrets `internal/secrets`, store `internal/store`, events `internal/events`, skills `internal/skills`, plugins `internal/plugins`, recon `internal/recon`, intel `internal/intel`, modules `internal/modules`, browser `internal/browser`, bench `internal/bench`, providers/ollama, diag.
- Rust owns: `rust/crates/bp-allowlist` (scope gate), `bp-exec` (argv-only exec, timeout, caps), `bp-evidence` (hash chain), `bp-sidecar` (loopback JSON-v1 server over TCP per `proto/exec.proto`).
- IPC: JSON-v1 over loopback TCP, version-gated (`internal/ipc` ↔ `bp-sidecar`). No Python bridge, no embedded interpreter.

## Phase order (dependency order)

1. Audit + gate + ADR + Dockerfile fix (this phase, no behavior change).
2. Control plane: swarm/campaign/checkpoints, recon full profiles, intel KEV/EPSS, memory/semantic, reporting export, eval harness, providers/routing, CLI flags, API/WS parity, legacy-required behavior.
3. Execution plane: Docker worker lifecycle + netns firewall, assessment families, browser hardening, evidence persistence.
4. Cutover: delete Python per-row only after native tests pass; native installers/CI/Docker; full `go/cargo/npm` verification; zero-python gate.

## Rules

- No Python file deleted until its INVENTORY row is `done` with passing native tests.
- Security preserved: explicit allowlist lock (`internal/allowlist` + `bp-allowlist`), fail-closed sandbox (`SANDBOX_*`), no implicit self-auth, audit chain intact.
- WebUI untouched; Go adapts to existing API contracts.
- shortcut: full 1,121-file port is multi-session work; this session lands the foundation + first vertical slices, leaves the rest tracked in INVENTORY/PARITY/PROGRESS.
