# Hands-On Tutorial

> [!WARNING]
> **Safety first.** NetAttackAI is a **lab-only build** for systems you own or
> have explicit written authorization to test, on a throwaway operator box.
> Attack mode ships as `full_access` — every action is auto-approved with no
> command-content or scope inspection. The one attack-path safety kept is the
> **target-IP allowlist lock** (a destination guard at the MCP tool layer, not
> authorization proof and not a sandbox). Recon keeps its full scope-gated
> safety model. See [`docs/safety-model.md`](safety-model.md) before running
> anything. Never point this at a target you don't control.

This tutorial walks the full operator loop end to end: setup, verification,
recon, exploitation, swarm, WebUI, demo/eval, and reading the artifacts. All
paths and prompts below are drawn from the code, so what you see on screen
will match.

---

## Section 1: Setup on Windows

### 1.1 Create the virtual environment and install dependencies

From the repository root, in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Expected output: pip resolves and installs the runtime dependencies
(including `yaml`, `ollama`, `mcp`, `uvicorn`, `websockets`, `questionary` —
the exact set `--doctor` later verifies). There is no long build step.

For editable package metadata and dev extras (ruff + pytest + coverage):

```powershell
python -m pip install -e ".[dev]"
```

Prerequisites beyond Python: `nmap` on `PATH` (or set `nmap.path` in
`config.yaml`) and an Ollama endpoint — the default is Ollama Cloud at
`https://api.ollama.com`, which needs `OLLAMA_API_KEY`.

### 1.2 Configure API keys (before `--doctor`)

Keys are read from **process environment variables** or `secr.json` — there
is no `.env` auto-load. The default cloud path requires `OLLAMA_API_KEY` or
the doctor's Ollama check will 401. Set it (and optionally the others) with:

```powershell
python main.py --setup-api-keys
```

This prompts for each key and writes `secr.json` (gitignored). Alternatively
set the environment variable in your shell:

```powershell
$env:OLLAMA_API_KEY = "sk-..."
```

| Var | Purpose |
|-----|---------|
| `OLLAMA_API_KEY` | **Required** for the default Ollama Cloud path |
| `NVD_API_KEY` | Raises NVD CVE lookup rate limit |
| `GITHUB_TOKEN` | Raises `cve_to_poc` GitHub Search API limit 60→5000/hr |
| `SERPAPI_API_KEY` | Optional fallback web research provider |
| `NETATTACKAI_API_TOKEN` | Override the auto-generated WebUI bearer token |

### 1.3 Verify the environment: `--doctor`

```powershell
python main.py --doctor
```

This runs a battery of checks (`tools/doctor.py`) and exits 0 when all pass.
A clean run looks like:

```text
============================================================
  NetAttackAI - Self-Check (`--doctor`)
============================================================
  [OK] python_version             3.11.9
  [OK] python_imports
  [OK] nmap_binary                C:\Program Files (x86)\Nmap\nmap.exe
  [OK] workspace_writable         research_workspace
  [OK] config_valid               config.yaml
  [OK] ollama_reachable           https://api.ollama.com
  [OK] model_registry
        -> verified cloud models by running a test generation: glm-5.2:cloud
  [OK] port_8001_free             127.0.0.1
  [OK] port_8080_free             127.0.0.1
============================================================
  All 8 checks passed. You're ready to run.
```

Notes:

- Python must be >= 3.11 (the check rejects 3.10).
- Cloud models are verified by running a real 1-token generation
  (`_ping_cloud_model`), so a missing `OLLAMA_API_KEY` surfaces here as a
  failed `ollama_reachable` / `model_registry` check with the hint
  "start Ollama, set OLLAMA_API_KEY, or update ollama.host in config.yaml".
- `port_8001_free` matters: 8001 is the exploit MCP HTTP port. If something
  holds it, stop it or set `mcp.http_port` in `config.yaml`.
- On Linux/macOS two informational checks also run: `linux_privilege` and
  `optional_tools` (Kali tooling). They never fail the run.

### 1.4 Swap to a local Ollama (optional)

Cloud is the default, but the same code path runs against a local daemon —
just change `ollama.host` in `config.yaml`:

```yaml
ollama:
  host: http://localhost:11434
```

No probe or fallback logic: the Ollama client auto-attaches
`Authorization: Bearer $OLLAMA_API_KEY` only when the key is present, so a
local daemon ignores it. Embeddings stay local by default via
`ollama.embed_host` (`nomic-embed-text`).

---

## Section 2: Safe smoke test: `--self-test`

```powershell
python main.py --self-test
```

This runs a safe, read-only diagnostic against `127.0.0.1` (`tools/self_test.py`):

1. Environment checks (Python, imports, nmap, Ollama, ports) — same battery as
   `--doctor`.
2. Config validation.
3. Boots the MCP exploit server over stdio with `soft_fail=True`.
4. Calls a fixed allow-list of introspection/scan tools against localhost:
   `check_os`, `quick_scan` (ports `22,80,443,8080`), `search_cve_intel`,
   `list_workspace`.
5. Writes `self_test_report.json` + `self_test_report.md`.

The routine hard-rejects any target other than `127.0.0.1`/`localhost` and
forces `read_only` — no write/run/exploit tools are ever invoked. Expected
output:

```text
============================================================
  NetAttackAI — Self-Test (`--self-test`)
  Target: 127.0.0.1 (localhost only)
  Workspace: reports\self_test_20260814_103000
============================================================
  [✓] python_version
  [✓] python_imports
  [✓] nmap_binary
  ...
  [✓] MCP exploit server booted
  [✓] Tool call check_os (412 chars)
  [✓] Tool call quick_scan (1180 chars)
  [✓] Tool call search_cve_intel (623 chars)
  [✓] Tool call list_workspace (95 chars)
  [i] JSON report: reports\self_test_20260814_103000\self_test_report.json
  [i] Markdown report: reports\self_test_20260814_103000\self_test_report.md
============================================================
  All self-test stages passed.
```

The exit code is 0 only when every stage passes. Run this after any
safety-sensitive code change (see the developer loop in
[`docs/getting-started.md`](getting-started.md)).

---

## Section 3: Recon-first run against a lab target

Use the WebUI daemon — the default with no arguments:

```powershell
python main.py
```

This builds and serves the WebUI at `http://127.0.0.1:8765` and opens a
browser. Prefer the terminal? The legacy arrow-key menu is available with
`--menu` (`tools/interactive_menu.py`):

```text
============================================================
  NetAttackAI — AI Bug Bounty Research Agent
  Authorized reconnaissance, research, evidence, reporting
============================================================
? What would you like to do?
  > Recon & Suggest Goals
    Start New Session
    Manage Missions
    View Reports
    Settings
    Help
    Exit
```

Pick **Recon & Suggest Goals** (or **Start New Session** — both reach the same
wizard, the first forces `--recon-first`).

### 3.1 Target prompt and the allowlist step

The wizard (`tools/attack_ui.py`) first asks for a target:

```text
Enter target (IP address or domain):
  Only scan systems you own or are explicitly authorized to test.
  > 10.0.0.50
```

For this walkthrough, use a lab host on your home network (a VM or old
router — **not** your production LAN). Both IPv4/IPv6 literals and domains
are accepted; domains are resolved later in `main.py` via
`tools/validation_utils.resolve_target_to_ip`, so both the domain and its IP
thread through the session.

Because you entered the target interactively, `main.py` persists it to
`config.yaml`'s `exploit.allowed_targets` and prints:

```text
[STATUS] Saved 10.0.0.50 to config.yaml exploit.allowed_targets.
```

**This is the allowlist lock in action.** Every target-touching MCP tool is
decorated with `@require_allowlist()` (`tools/mcp_shared.py:651`), which
checks the target against the union of `exploit.allowed_targets` +
`EXPLOIT_TARGET` (the runtime target injected into the MCP subprocess env by
`tools/mcp_session.py:255`). A tool call against any other host is refused:

```text
BLOCKED: Target IP 10.8.0.9 is not in the explicit allowlist. Add it to
config.yaml exploit.allowed_targets to authorize.
ATTEMPT_ID: preflight
TOOL: run_exploit_terminal
TARGET: 10.8.0.9
```

Free-text commands (terminal, Python files, Metasploit) are scanned for
destination tokens — URL authorities, `/dev/tcp` hosts, LHOST/RHOST, scanner
verbs, bare IPs — by `tools/mcp_tools/terminal._target_lock_block`
(`tools/mcp_tools/terminal.py:57`). The lock supports domains, `*.wildcard`
and CIDR; callback/C2 hosts must be added to `exploit.allowed_targets`
explicitly.

### 3.2 The wizard continues

Next prompts (all questionary select/text, Enter accepts the default):

- **Select model alias:** defaults to `glm` (GLM-5.2, 976K context).
- **Enable peer-model consultation?** default `No` (advisory peer models get
  no tool schemas).
- **Reports output directory:** default `reports`.
- **Disable color output? / stealth prompts:** defaults off.
- **Power-ups (space to toggle):** `Swarm mode`, `Critic agent`,
  `Reflection agent`, `Adaptive exploits`, `Long session`, `Ultrathink`,
  `Debug logging`, `Auto-confirm all prompts`.
- **Recon-first?** `on` — run recon, then attack.
- **Observer mode:** `hybrid`.

Then the run summary and the ready-to-begin gate:

```text
[STATUS] Target: 10.0.0.50
[STATUS] Mode: attack
[STATUS] Goal: initial_access
------------------------------------------------------------
Run summary:
  Config:      config.yaml
  Reports root:reports
  Run ID:      20260814_104512_123456
  Target:      10.0.0.50
  ...
  Budget:      200 commands, 50 rounds, 60 min.
  [SKILLS] 12 active
? Proceed? [Y/n]
```

### 3.3 What recon-first does

The session opens the MCP exploit server (boot checklist — grep-able
`[BOOT]`/`[OK]` lines, `tools/mcp_session.py:284`):

```text
> MCP exploit session boot sequence
  --------------------------------------------------------
  [BOOT] Booting MCP server (stdio)
  [OK] Booting MCP server (stdio)
```

Then recon runs (`tools/recon_assessment_cli.py`): `check_os` (TTL/port
analysis), `quick_scan` of the top 24 ports, and `search_cve_intel` per
discovered product/version banner. You get a structured assessment:

```text
============================================================
  RECONNAISSANCE ASSESSMENT
============================================================
  Target:        10.0.0.50
  OS Verdict:    LINUX (Ubuntu)
    -> ttl=64, open ports 22/80/443
  Open Ports:    3 (22, 80, 443)
  Services:      3
    - ssh on port 22/tcp [risk:45]
    - http on port 80/tcp [risk:70]
      banner: Apache/2.4.41 (Ubuntu)
  CVEs Found:    1 service(s) checked
  Attack Surface: 62/100
============================================================

SUGGESTED GOALS (ranked by exploit success rating):
  * initial_access               likely         80/100  GATED
    -> Apache 2.4.41 + exposed SSH
  ...
```

Then you pick a goal (`ask_goal_from_suggestions`) and the session continues
toward it — which is the subject of the next section. Note: in **recon
mode** (`--mode recon`) the whole run stays `read_only`: the policy proposes
but never executes (`tools/exploit_agent/policy.py:396`).

---

## Section 4: Full exploit session walkthrough

Non-interactive equivalent of the wizard path (all flags exist on the CLI —
see `main.py:342`):

```powershell
python main.py --target 10.0.0.50 --mode attack --goal initial_access --yes
```

**Do not skip the confirmation gate in real use** — `--yes` skips it. The
interactive gate requires typing `ALLOW 10.0.0.50` verbatim for destructive
(full_access + attack) runs (`tools/attack_ui.py:1311`), so a reflexive Enter
never authorizes a destructive run.

### 4.1 Permission modes

`config.yaml` → `exploit.permission` drives behavior
(`tools/exploit_agent/policy.py:368`):

| Mode | Behavior |
|------|----------|
| `full_access` (default, lab) | Auto-approves **every** action with no command-content or scope inspection; only the command budget and the MCP-layer target-IP lock apply |
| `approve_only` | Every action prints a banner and waits for `ALLOW <target>` |
| `read_only` | Propose-only: actions are recorded with status `proposed` and never executed; the fallback if the config key is missing |

With `approve_only` each sensitive action looks like:

```text
======================================================================
  EXPLOIT ACTION REQUIRES APPROVAL
======================================================================
  Target:   10.0.0.50
  Action:   run_exploit_terminal
  Detail:   check sudo version for CVE-2021-3156
  Command:  sudo --version
----------------------------------------------------------------------
Type ALLOW 10.0.0.50 to approve, anything else to deny: ALLOW 10.0.0.50
```

With the default `full_access`, actions stream past without prompts; you
watch the agent's rounds instead:

```text
[ROUND 1/50] phase=recon actions=0 cmds_left=200
[THINKING] round 1 — waiting for model…
[TOOL] run_exploit_terminal {"command": "nmap -sV -p- 10.0.0.50", "timeout": 300}
[OK]#1 exit=0
[ACTION #2] search_cve_intel target=10.0.0.50 phase=vuln
```

### 4.2 Milestone lines and what they mean

The UI prints distinct milestones (`tools/attack_ui.py:404`):

```text
[COMPROMISE]#7 foothold established shell=reverse_shell priv=root
[CRED DUMP]#9 credentials harvested
[PARTIAL]#12 — banner confirmed but no vector
[FAILURES] 3 consecutive exploit failure(s)
[PHASE] entering post_exploit
```

The agent loop also stops early on a verified win
(`scripts/runner_impl.py:1030`):

```text
[INFO] Goal complete - verified compromise/cred dump; terminating.
```

### 4.3 Where evidence lands

Session artifacts are written to
`reports/<run_id>/` (`tools/run_service/service.py:430`):

```text
reports/20260814_104512_123456/
├── session_summary.md          # target, mode, goal, actions, model usage, audit trail path
├── run.json                    # full RunResult as JSON
├── events.jsonl                # live run events (same stream the WebUI shows)
├── activity.jsonl              # ActivityLog timeline
├── swarm_workspace/            # present when --swarm (see Section 5)
└── enhanced/enhanced_report.json  # attack-graph rendering for the WebUI
```

The exploit workspace itself defaults to
`exploit_workspace/<target_ip>/` (from `exploit.workspace_dir` in
`config.yaml`), and every action is additionally chained into:

```text
exploit_workspace/10.0.0.50/
├── exploit_audit.jsonl         # SHA256 hash-chained audit trail
└── 20260814_104512_123456_ab12cd34/   # per-attempt dir (stamp + random suffix,
                                       # tools/mcp_shared.py:889): generated
                                       # scripts, tool outputs, artifacts
```

The audit log is append-only with a `prev_hash` chain
(`tools/exploit_agent/policy.py:128`); a startup integrity check warns if a
prior chain was tampered with, and the WebUI verifies and surfaces chain
validity. Generated Python is recorded with `code_sha256`. Credentials go to
an HMAC-signed store (`tools/credential_store.py`) — never printed to the
terminal.

---

## Section 5: Swarm mission

Launch the full-power swarm run:

```powershell
python main.py --target 10.0.0.50 --mode attack --swarm --critic --reflection --adaptive-exploits
```

You'll see:

```text
[INFO] Swarm mode ENABLED (critic=True, reflection=True, adaptive_exploits=True).
```

### 5.1 How it works

The swarm is a parallel specialist decomposition
(`tools/swarm/orchestrator.py`), distinct from the autonomous campaign
engine. Six specialist agents exist (`tools/swarm/agents/`): **recon**,
**vuln** (research/analysis), **exploit** (validation + exploitation),
**post-exploit**, plus optional **critic** (pre-approval) and **reflection**
(strategy review) agents. Tasks are routed by type
(`orchestrator.py:28`):

```python
_DEFAULT_AGENT_MAP = {
    "recon": ReconAgent,
    "analysis": VulnAgent,
    "test": VulnAgent,
    "validate": ExploitAgent,
    "exploit": ExploitAgent,
    "post_exploit": PostExploitAgent,
    "report": ReflectionAgent,
}
```

All agents share one thread- and async-safe **blackboard**
(`tools/swarm/blackboard.py`) — services found by recon, `access_achieved`
flags, lessons, reflection output — and a **battle log** that the reflection
agent reads to recommend strategy shifts. With `--parallel-swarm`
(`--parallel-swarm` flag), recon + vuln-research parallelize via semaphore;
exploit/post-exploit stay sequential unless configured otherwise.

The swarm's tool calls bridge onto the same live MCP session and the same
target-IP allowlist lock as the single-agent path (`SwarmMcpBridge` in
`tools/swarm_bridge.py`), so an agent cannot touch an off-target host any
more than the solo agent could. The mission config built for the swarm locks
`allowed_assets` to the target IP and forbids DoS/social-engineering/physical
attack (`tools/run_service/service.py:999`).

### 5.2 Live progress and output

While it runs you see per-agent status ticks built from the persisted state
snapshot:

```text
[STATUS] swarm: 2 done, 3 running, 1 blocked
```

Output lands under the run's `swarm_workspace/`:

```text
reports/20260814_104512_123456/swarm_workspace/
├── swarm_state.json           # agents, per-task outcomes, blackboard snapshot,
│                              # battle-log tail (atomic tmp+rename write)
└── ...                        # per-attempt workspaces and artifacts
```

`swarm_state.json` also lets a later run restore the blackboard, so a
resumed swarm keeps every discovered fact. The session summary then includes
a Swarm block (tasks completed/blocked/failed, report-ready findings).

---

## Section 6: Web UI

```powershell
python main.py --web
```

### 6.1 First build

On the first run, if `webui/dist/index.html` is missing, `main.py` builds it
(`main.py:436`): `npm install && npm run build` in `webui/` (needs Node.js +
npm on `PATH`; ~1–2 minutes, 600s timeout). You'll see:

```text
[STATUS] Building the WebUI (first run only)...
[STATUS]   npm install...
[STATUS]   npm build...
[STATUS] WebUI build complete.
```

Subsequent `--web` runs reuse the built `dist/`. If npm isn't installed it
prints the manual fallback commands instead.

### 6.2 Token and endpoints

The daemon binds **loopback only** (`127.0.0.1:8765`; any other bind host is
refused) and prints:

```text
[STATUS] Starting WebUI API daemon on http://127.0.0.1:8765
[STATUS]   Interactive docs: http://127.0.0.1:8765/docs
[STATUS]   WebUI:             http://127.0.0.1:8765/
```

A 256-bit bearer token is auto-generated into `.webui_secret_key`
(gitignored) on first boot, or overridden via `NETATTACKAI_API_TOKEN`
(`tools/api/auth.py:39`). A browser opens automatically; paste the token into
the TokenGate prompt. All routes except `/health` require it, and the
WebSocket needs `{"auth": "<token>"}` as its first message.

### 6.3 Live run view

Start a run from the wizard in the SPA. Live events stream over WebSocket
(with SSE fallback) while the run is active — the same
`events.jsonl` stream is the authoritative record. You see rounds, tool
calls, approvals, milestone banners, and the audit-chain validity check in
realtime; the Artifacts and Loot pages surface the workspace files and the
HMAC-signed credential store. Only one run may be active at a time (HTTP 409
on conflict). `python main.py --demon` starts the API without the SPA for
dev mode (`webui` dev server on `:5173` proxies `/api` to `:8765`).

---

## Section 7: Demo mode + eval harness

### 7.1 `--demo` — local sandbox

```powershell
python main.py --demo
```

This runs a **defensive simulation** against a local sandbox only
(`tools/demo_mode.py`): if Docker is available it starts the DVWA image
(`vulnerables/web-dvwa`) on `127.0.0.1:8081`; otherwise it falls back to a
synthetic in-process HTTP server that returns canned CVE banners (safe by
design — never a real exploit, never a non-local target). Expected output:

```text
============================================================
  NetAttackAI — DEMO mode (`--demo`)
  Target: 127.0.0.1:8081 (local sandbox only)
============================================================
  [i] Starting DVWA via Docker…
  [✓] DVWA started in Docker.
  [✓] Demo report written to: reports/demo/demo_report.md
  [i] Tearing down demo DVWA container…
```

The demo then tells you how to run the full flow against that target
yourself:

```text
  To run the full exploitation flow against this target:
    python main.py --target 127.0.0.1 --mode recon --goal initial_access
```

### 7.2 `--eval` — benchmark harness

```powershell
python main.py --eval --target 10.0.0.50
```

Runs the eval/benchmark harness against the target with `FULL_ACCESS`
permission and a bounded round budget (`tools/eval_harness.py:362`, config
block `eval` — defaults: `output_dir: reports/eval`, `max_rounds: 30`,
Markdown + HTML reports on):

```text
============================================================
  NetAttackAI — Eval Harness (`--eval`)
  Target: 10.0.0.50
  Run ID: 20260814_105500_ab12
  Output: reports/eval/20260814_105500_ab12
============================================================
  ...
  [i] verdict=exploited  success_rate=66.7%  out=reports/eval/20260814_105500_ab12
```

`--eval` requires `--target` (exit 2 otherwise). Each run writes its own
tree under `reports/eval/<run_id>/` containing the exploit workspace,
`eval_report.json`, and (by default) `eval_report.md` / `eval_report.html`
with metrics (verdict, success rate, action counts, durations). If the MCP
server can't boot, it degrades to an error verdict report instead of raising.

---

## Section 8: Where to look next

Everything is under `reports/`, `exploit_workspace/`, and
`research_workspace/` (all gitignored runtime state).

| Artifact | Location | Contents |
|----------|----------|----------|
| Session summary | `reports/<run_id>/session_summary.md` | Target, mode, goal, actions executed, model usage, active skills, audit trail path, swarm block |
| Run JSON | `reports/<run_id>/run.json` | Full structured result (records, messages, outcome) |
| Live events | `reports/<run_id>/events.jsonl` | The run timeline the WebUI streams |
| Activity timeline | `reports/<run_id>/activity.jsonl` | ActivityLog events |
| Audit chain | `exploit_workspace/<ip>/exploit_audit.jsonl` | SHA256 hash-chained record of every action (approved/blocked, code hash) |
| Attempt artifacts | `exploit_workspace/<ip>/<attempt_id>/` | Generated scripts, outputs per attempt |
| Swarm state | `reports/<run_id>/swarm_workspace/swarm_state.json` | Agents, blackboard snapshot, battle log |
| Eval reports | `reports/eval/<run_id>/` | `eval_report.{json,md,html}` + workspace |
| Self-test | `reports/self_test_<ts>/` | `self_test_report.{json,md}` |
| Model telemetry | `research_workspace/logs/llm_usage.jsonl` | Per-call token/context usage |

Good next stops in the docs: the mission-driven Flow B research loop
(`python cli.py init-mission --config mission.yaml`, then `next-task`,
`run-task`, `list-findings`, `generate-report` — see
[`docs/getting-started.md`](getting-started.md) and
[`docs/runtime-flows.md`](runtime-flows.md)), domain targeting
(`--target example.com`, which auto-authorizes discovered subdomains through
the allowlist), `--long-session` for multi-hour runs, and the WebUI
reference in [`docs/webui.md`](webui.md). Remember the developer loop: after
any code change, run `python -m pytest tests/ -v`, `ruff check .`, and
`python main.py --doctor` + `python main.py --self-test`.
