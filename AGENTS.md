# AGENTS.md

Compact guide for AI coding agents working in this repo. Read this first, then
`CLAUDE.md` for architecture/safety depth and `docs/` for topic guides.

## Architecture (100% Go + Rust + TypeScript WebUI — Zero Python)

- **Go Control Plane (`cmd/`, `internal/`)**:
  - `cmd/bp`: Primary CLI and loopback WebUI/API daemon (`http://127.0.0.1:8765`).
  - `cmd/bp-mcp-defensive` (:8000), `cmd/bp-mcp-assess` (:8001), `cmd/bp-mcp-engine` (:8002): Standalone native MCP servers over stdio and loopback-gated HTTP.
  - `cmd/bp-codegen`: Native catalog generator, capability counter, and strict zero-Python release gate.
  - `internal/`: `agent`, `allowlist`, `api`, `audit`, `auth`, `bench`, `browser`, `campaign`, `codegen`, `config`, `diag`, `events`, `goals`, `graph`, `intel`, `ipc`, `mcp`, `mcpserve`, `memory`, `modules` (91 registered tools), `ollama`, `operator`, `plugins` (15 plugins), `providers`, `recon`, `reporting` (JSON/MD/HTML/PDF 1.4), `runner`, `secrets`, `skills`, `store` (SQLite schema v10), `threatintel`, `zeropython`.
- **Rust Execution Plane (`rust/crates/`)**:
  - `bp-allowlist`: Target IP/CIDR/domain/`*.` wildcard allowlist gate (empty union fails closed; no target self-authorization).
  - `bp-exec`: Sandboxed command execution + disposable Docker worker lifecycle (`SandboxManager`), `--cap-drop ALL`, non-root user, read-only rootfs, and default-DROP IPv4/IPv6 netns firewall via ephemeral `NET_ADMIN` sidecar (`iptables-restore`/`ip6tables-restore`).
  - `bp-evidence`: Tamper-evident SHA-256 hash chain for execution audit logs.
  - `bp-sidecar`: Loopback JSON-v1 IPC server (`127.0.0.1:18765`, IDL in `proto/exec.proto`).
- **Frontend (`webui/`)**:
  - React 18, TypeScript, Vite, Tailwind CSS.

## Commands

```bash
# Build & install (Linux / macOS)
./install.sh
bp --doctor          # env check (loopback bind, SQLite store, allowlist gate, provider, Rust sidecar)
bp --self-test       # safe localhost smoke test
bp                   # WebUI daemon + browser on http://127.0.0.1:8765

# Go control-plane build & tests
go build ./...
go vet ./...
go test ./... -count=1

# Rust execution-plane build & tests (from rust/)
cd rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release

# WebUI build & tests (from webui/)
cd webui
npm ci
npm run build
npm run test

# Strict Zero-Python Gate
sh scripts/zero-python-gate.sh --strict
go run ./cmd/bp-codegen -mode release-gate -strict
```

<details>
<summary>Windows PowerShell</summary>

```powershell
.\install.ps1 -Check
.\install.ps1
.\bp.exe --doctor
.\bp.exe --self-test
powershell -File scripts\zero-python-gate.ps1 -Strict
```

</details>

## Non-Obvious Rules

1. **Zero Python Policy**: Do not add `.py` files, `pyproject.toml`, `requirements.txt`, `pytest`, or Python subprocess calls. `internal/zeropython` and `scripts/zero-python-gate.sh --strict` fail CI if any Python file or reference is introduced.
2. **Explicit Target Allowlist Lock**: Enforced in both Go (`internal/allowlist.ApprovalEntries` + `Check`) and Rust (`bp-allowlist` + `bp-exec`). Targets never self-authorize.
3. **Fail-Closed Sandbox**: Command execution routes through `bp-sidecar` / `bp-exec::sandbox` and returns typed `SANDBOX_*` errors when out of scope or when Docker isolation is unavailable — never fall back to host execution.
4. **Destructive ICS Gate**: Modules with `DestructiveICS: true` (`ModbusWriteCoil`, `ModbusWriteRegister`, `S7PlcStop`, `S7PlcStart`) require explicit `confirm_ics_write: true`.
5. **HITL Reporting Gate**: Only `APPROVED`, `VERIFIED`, or `STILL_OPEN` findings enter `technical_findings` in `enhanced_report.{json,md,html,pdf}`; `PROPOSED` candidates remain isolated under `proposed_findings`.
