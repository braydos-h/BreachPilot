# CLAUDE.md

Authoritative architecture and safety reference for BreachPilot (100% Go + Rust backend with React/TypeScript WebUI — Zero Python).

## Architecture Overview

BreachPilot is split across two native planes communicating over a versioned, typed JSON-v1 IPC contract (`proto/exec.proto`), paired with the existing React/TypeScript WebUI (`webui/`):

1. **Go Control Plane (`cmd/`, `internal/`)**
   - `cmd/bp`: CLI entrypoint and loopback HTTP/SSE/WebSocket daemon (`127.0.0.1:8765`).
   - `cmd/bp-mcp-defensive` (:8000), `cmd/bp-mcp-assess` (:8001), `cmd/bp-mcp-engine` (:8002): Standalone JSON-RPC 2.0 MCP servers (stdio + loopback-gated HTTP).
   - `cmd/bp-codegen`: Catalog generator, capability counter, and strict zero-Python release gate.
   - `internal/api`: Bearer-gated REST API, RFC6455 WebSocket + SSE event streaming, HITL finding review (`/decide`), manual tool gateway (`/tools/{name}/calls`), attack graph explorer (`/graph/runs/{id}/*`), operator connections (`/connections/*`), benchmark harness (`/benchmarks/*`), and system diagnostics (`/system/*`).
   - `internal/runner`, `internal/agent`, `internal/campaign`: Run state machine (`preparing` → `awaiting_confirmation` → `queued` → `running` → `completed`/`failed`/`cancelled`), LLM planning pass + budget-capped multi-model peer consultation (`ConsultPeers`), and multi-agent swarm/campaign orchestration (Blackboard, milestones, Recon/Vuln/Validation/Critic/Reflection specialists, checkpoints, interrupted-run resume recovery).
   - `internal/modules`: Compile-time registry of 91 native assessment and attack modules across 16 families (`network`, `web`, `network_smb`, `ad`, `auth_creds`, `ssh`, `services`, `crypto_jwt`, `deserialize`, `privesc`, `persistence`, `ics_iot`, `supply_chain`, `synthesis`, `detect`, `orchestrator`) with `FindApplicable` static scoring.
   - `internal/recon`, `internal/intel`, `internal/threatintel`: TCP connect + banner scanner, connected-socket UDP scanner, multi-signal OS fingerprinting (`FingerprintOS`) with graceful unprivileged fallback, `rustscan`/`masscan`/native high-speed port scanner (`RunFastScanner`), NVD v2 + EPSS + CISA KEV client, and OSV + GHSA + KEV threat-intel client.
   - `internal/reporting`: HITL-gated `enhanced_report.json`, `enhanced_report.md`, `enhanced_report.html`, and pure-Go PDF 1.4 (`enhanced_report.pdf`) generator.
   - `internal/store`, `internal/memory`, `internal/audit`, `internal/secrets`, `internal/config`, `internal/skills`, `internal/plugins`, `internal/browser`, `internal/operator`, `internal/graph`, `internal/bench`.

2. **Rust Execution Plane (`rust/crates/`)**
   - `bp-allowlist`: Exact IP, CIDR, domain, and `*.wildcard` dot-boundary allowlist matcher. Empty allowlist fails closed when `require_allowlist` is true.
   - `bp-exec`: Bounded argv execution + disposable Docker worker lifecycle (`SandboxManager`). Hardens workers with `--cap-drop ALL` (`--cap-add NET_RAW` only when configured; never `NET_ADMIN`), `--security-opt no-new-privileges`, non-root `--user sandbox`, `--read-only` rootfs, bounded memory/CPU/PIDs, `/workspace` bind mount confinement, and an ephemeral `NET_ADMIN` sidecar that loads default-DROP IPv4/IPv6 rules (`iptables-restore`/`ip6tables-restore`) blocking embedded DNS (`127.0.0.11`) and port 53 before `-o lo -j ACCEPT` and blocking cloud metadata CIDRs.
   - `bp-evidence`: SHA-256 hash-chained JSONL audit log writer and verifier.
   - `bp-sidecar`: Loopback TCP server speaking the `v1` JSON IPC protocol (`health`, `exec`, `sandbox_status`, `sandbox_rules`, `sandbox_cleanup`).

## Build, Test, and Verification Commands

```bash
# Go control plane
go build ./...
go vet ./...
go test ./... -count=1

# Rust execution plane
cd rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release

# WebUI
cd webui
npm ci
npm run build
npm run test

# Zero-Python Gate (must pass with 0 .py files and 0 Python references)
sh scripts/zero-python-gate.sh --strict
go run ./cmd/bp-codegen -mode release-gate -strict
```
