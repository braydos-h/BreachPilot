# Parity — Verified Native Go + Rust Contracts

All WebUI (`webui/`, React/TypeScript untouched), CLI, REST, SSE/WebSocket, MCP JSON-RPC 2.0, SQLite, and Go↔Rust IPC contracts are verified against the native implementation:

- **REST & WebUI**:
  - `GET /api/v1/health` (200 unauthenticated), `GET /` SPA (200 unauthenticated), `/api/v1/*` bearer-gated (401 without token).
  - `/api/v1/capabilities`, `/config`, `/config/schema`, `/secrets`, `/models`, `/providers`, `/goals`, `/skills`, `/plugins` (including `config_section` and `loaded`), `/attack/modules` (all 91 native tools with `target_services`, `target_ports`, `required_cves`, `destructive_ics`), `/ops/summary`, `/diagnostics/doctor`, `/diagnostics/self-test`, `/benchmarks/*`, `/connections/*`, `/graph/runs/{id}` (+ `/summary`, `/conflicts`, `/nodes/{id}`, `/nodes/{id}/neighbors`, `/paths`).
  - `/api/v1/system/info`, `/system/telemetry`, `/system/memory` (`lessons`, `confidence`, `attack_memory`), `/system/sandbox` (+ `/fix/plan`, `/fix`, `/fix/{job_id}`), `/system/browser`, `POST /system/reset`.
  - `/api/v1/runs` + `/runs/{id}` subroutes: `cancel`, `resume`, `title`, `tools`, `tools/{name}/calls`, `artifacts`, `artifacts/{name}`, `audit`, `sandbox`, `proposed`, `decide`, `swarm`, `campaign`, `witness`, `errors`, `events`, `events/stream`, `ws/runs/{id}`, `decisions`, `logs/{name}`, `credentials` (+ `reveal`, `confirm`), `loot`, `workspace` (+ `workspace/{path}`).
- **Reporting**:
  - `enhanced_report.json`, `enhanced_report.md`, `enhanced_report.html`, and `enhanced_report.pdf` (pure-Go PDF 1.4) generated with strict HITL filtering (`APPROVED`/`VERIFIED`/`STILL_OPEN` in technical findings; `PROPOSED` isolated in unvetted section).
- **MCP**:
  - `cmd/bp-mcp-defensive` (:8000), `cmd/bp-mcp-assess` (:8001), `cmd/bp-mcp-engine` (:8002) over stdio and loopback-gated HTTP (`--allow-public-bind` + `MCP_ALLOW_PUBLIC_BIND=1` + `MCP_HTTP_TOKEN`).
- **Execution & Containment (Rust)**:
  - `bp-allowlist`, `bp-exec` (`SandboxManager`, `--cap-drop ALL`, non-root user, read-only rootfs, default-DROP `NAI-OUTPUT` netns firewall with DNS drop before `-o lo`, fail-closed `SANDBOX_*`), `bp-evidence` (SHA-256 chain), `bp-sidecar` (JSON-v1 over loopback TCP).
