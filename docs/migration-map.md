# BreachPilot Go + Rust migration map (implemented functionality only)

Audit baseline: 1,121 tracked `.py` files. A row is `done` only with passing
native tests + real backend behavior. `pending` rows keep their Python
implementation as reference; the native side returns real empty state or an
explicit `501 not_ported` — never fabricated data.

## Control plane (Go) — done

| Python subsystem | Native replacement | Evidence |
|---|---|---|
| `main.py` + `tools/cli_args.py` flags | `cmd/bp/main.go` (target/mode/goal/web/doctor/self-test/version/list-plugins/…) | `go build`, doctor/self-test outputs |
| `app.py` daemon + SPA hosting | `serve()` loopback daemon + `spaHandler` (no-auth SPA, auth-gated `/api/*`) | e2e: `GET /` 200, `/api/*` 401 w/o token |
| `tools/api/auth.py` | `internal/auth` (bearer gate, 0o600 token file, WS 4400/4401/4403/4404) | `server_test.go` auth gate tests |
| `tools/api/event_broker.py` | `internal/events` (ordered replay, cursors, SSE `: heartbeat`, WS replay+live) | replay/cursor tests + e2e event trail |
| `tools/config/loader.py` | `internal/config` (defaults, loopback validation, atomic `PatchFile`/`DeleteMapKey` with validate-before-write) | patch/reject-leaves-file-untouched tests |
| `tools/api_key_store.py` + PUT/GET `/secrets` | `internal/secrets` (secr.json v1, 0600, atomic, bare-map tolerant, values never returned) | round-trip + leak tests |
| `db.py` + `api/persistence.py` custom_goals | `internal/store` (schema v10 runs/decisions/findings/audit + `custom_goals` NOCASE unique) | CRUD/duplicate/decision-lifecycle tests |
| `tools/goal_engine.py` presets | `internal/goals` (14 presets, safe/gated/high + standard_authorized compat) | 14-preset API test |
| `tools/skill_registry.py` + skills API | `internal/skills` (SKILL.md front-matter discovery, search, atomic create, traversal-safe delete) | list/search/get/create/delete tests |
| `tools/plugins.py` manifests | `internal/plugins` (`plugin.yaml` discovery: name/version/caps/enabled/…) | fixture discovery test |
| `ollama_provider` discovery/refresh | `internal/ollama` (GET /api/tags, `parse_model_spec` + family/max-version/same-tag refresh) | httptest live + vector tests |
| Provider status | providers endpoint (chatgpt file-existence auth, proxy probe; login/start `501 not_ported`) | honest-status tests |
| `tools/api/run_service` + `run_manager` states | `internal/runner` (preparing→awaiting→queued→running→completed/failed/cancelled, cancel, resume-adopt, artifacts) | recon e2e, scope-denied, cancel/resume tests |
| `tools/recon` fast/assessment path | `internal/recon` (parse/validate, bounded DNS, 24-port scan+banners, assessment JSON, heuristic suggestions) | scan/assess/suggest tests |
| `tools/api/routes/decisions.py` | DB-backed decisions + answer rules (attack exact-ALLOW, recon y/yes, goal_select names) | gate/409/answer tests |
| Tool-call policy + `call_tool` | `POST /tools/{name}/calls` (404/403/409/500, allowlist gate, audit row, event) | gate/audit tests |
| `policy.record` audit chain | `internal/audit` (SHA-256 hash chain JSONL, verify, dir auto-create) | round-trip + tamper tests |
| recon artifacts + proposed/decide | `recon_assessment.json`, `goal_suggestions.json`, `run.json`, `session_summary.md`, `proposed.json` + HITL decide | e2e artifact + decide tests |
| `tools/exploit_agent` loop (native subset) | `internal/agent` (per-service probes, evidence findings, allowlist-gated, bounded) | skip-on-denial, empty-assessment tests |
| `tools/attack_modules` network family | `internal/modules` (`resolve`, `tcp_scan`, `http_probe`, `tls_probe`) | loopback + rejection tests |
| `tools/benchmark` smoke | `internal/bench` (native-smoke suite, trials, oracle=solved-when-clean, baseline save/compare with hard gates) | validation/conflict/scope/compare tests |
| `tools/browser` (playwright) | `internal/browser` (chromedp CDP: create/navigate/text/screenshot/close, allowlist gate, chrome probe) | gate/scheme/probe tests |
| `tools/doctor.py` + self-test | `internal/diag` shared by CLI + API (loopback/store/allowlist/tags/sidecar checks) | exit-code tests |
| Go↔Rust protocol | `proto/exec.proto` IDL + JSON-v1 TCP (`internal/ipc` ↔ `bp-sidecar`); see `docs/ipc-protocol.md` | 5 live contract tests |

## Execution plane (Rust) — done

| Python subsystem | Native replacement | Evidence |
|---|---|---|
| `sandbox/exceptions.py` SANDBOX_* | `bp-exec::ExecError` (ScopeDenied/Timeout/Spawn, fail-closed) | unit tests |
| `terminal/allowlist.py` + matchers | `bp-allowlist` (IP/CIDR/domain/`*.` dot-boundary, empty fails closed, no self-auth/DNS-grant) | 5 unit tests, vectors pinned vs Go |
| `sandbox/manager.py` exec path | `bp-exec::execute` (argv-only, timeout+kill, output caps) | timeout-kill/spawn-fail tests |
| audit chain | `bp-evidence` (SHA-256 chain, verify) | chain + tamper tests |
| MCP HTTP transport (sidecar) | `bp-sidecar` loopback server (health/exec, version gate) | live IPC tests |

## Explicitly pending (Python reference retained, native returns real empty/501)

- Swarm/campaign orchestration, checkpoints beyond resume-adopt (`--swarm` recorded, not executed)
- 83 attack-module classes beyond the network family; 15 plugin behaviors (manifests discovered)
- ~174 skill `scripts/*.py`: XSS-style checkers → future `modules` web families; KEV/EPSS-style processors → future native enrichment. SKILL.md metadata is native today.
- Docker worker lifecycle + netns firewall (Rust gate+exec exist; container isolation pending)
- `mcp_server.py` / `mcp_exploit_server.py` / `mcp_engine_server.py` (no native MCP servers yet)
- Full recon profile (nmap/rustscan/masscan fallbacks), UDP, OS fingerprinting, CVE intel
- Memory/semantic services, report export (md/html/pdf), eval graded harness, operator connections
- Recon-first goal-select flow, multi-model consult, critic/reflection agents
- `go test -race` (no cgo on Windows; Linux CI covers it), Docker image build (no daemon here; CI covers it)

## Deletion rule

No Python file is deleted until its row is `done` with passing native tests.
Today: zero Python files deleted (correct — pending rows remain).
