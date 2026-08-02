<div align="center">

# NetAttackAI

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/status-beta-6f42c1?style=flat-square)
![License](https://img.shields.io/badge/license-GPL--3.0--only-blue?style=flat-square)

[Quick Start](#quick-start) · [What It Does](#what-it-does) · [CLI Reference](#cli-reference) · [MCP Tools](#mcp-tools) · [Configuration](#configuration) · [Safety](#authorized-use-only)

</div>

---

## What NetAttackAI is

NetAttackAI (also referenced in the code as **AI Target Exploitation Engine**) is a Python application that uses local Ollama LLMs to plan and run authorized security assessments end-to-end. It combines reconnaissance, model-guided analysis, exploit orchestration, evidence tracking, and reporting into one local workspace.

It is **local-first** and runs entirely on your machine. It talks to a local Ollama instance and drives security tools (Nmap, Metasploit, searchsploit, Impacket, hashcat/john, Nikto/Nuclei/sqlmap/gobuster, and others) against the one target you authorize.

> [!WARNING]
> This is a **lab-oriented build**. Attack workflows can run offensive tools on your operator machine. Use only against systems you own or are explicitly authorized to assess. See [Authorized use only](#authorized-use-only).

---

## What it does (at a glance)

| Capability | Description |
| --- | --- |
| **Reconnaissance** | Nmap scanning, service fingerprinting, CVE lookup, web research, domain ops (subdomain enum, DNS recon, vhost enum, WHOIS), recon diffing |
| **Exploit orchestration** | Policy-driven AI agent loop that plans and executes attack steps against a target-locked scope |
| **Autonomous campaigns** | Persistent multi-phase attack engine with adaptive aggression, auto-retry, and vulnerability chaining |
| **Multi-agent swarm** | 6 specialist agents (recon / vuln / exploit / post-exploit / critic / reflection) with a shared blackboard |
| **Attack modules** | 100+ ranked built-in modules across web, AD, privesc, services, crypto, deserialization, and more |
| **Runtime skills** | 130+ advisory methodology skills injected into the agent's prompt context, with semantic selection |
| **Metasploit integration** | MSF module runs, sessions, payloads, recipes, auxiliaries, post modules, resource scripts |
| **Credential/AD tooling** | Impacket lateral movement, credential dumping, Kerberoasting, AS-REP roasting, pass-the-hash, ADCS, BloodHound |
| **Hash cracking** | hashcat/john with auto hash-type identification and plaintext recovery |
| **Web scanning** | Nikto, Nuclei, sqlmap, Gobuster/Feroxbuster, WhatWeb, WPScan, Dirb/Dirbuster |
| **OPSEC posture** | Target-aware pacing, UA rotation, DNS-over-HTTPS, noise scoring, quieter command suggestions |
| **Memory & learning** | Semantic memory, cross-mission learning, Bayesian experience scoring, attack memory |
| **Reporting** | Per-run markdown/HTML reports, timelines, CVSS, exploit chains, findings CSV |
| **WebUI API** | Loopback REST + WebSocket API for third-party WebUIs to drive assessments |
| **Plugin system** | Extend with custom attack modules, MCP tools, skill directories, and config sections |
| **Legacy mission workflow** | SQLite-backed deterministic workflow (`cli.py`) for missions, tasks, findings, reports |

---

## Quick start

### Prerequisites

- **Python 3.10+** (3.11+ recommended)
- [**Ollama**](https://ollama.com/) running locally (default: `http://localhost:11434`)
- [**Nmap**](https://nmap.org/) on `PATH`

**Optional tools** (enabled automatically when installed):
Metasploit (`msfconsole`), `searchsploit`, `tmux`, `hashcat`/`john`, Impacket, Nikto, Nuclei, Gobuster/Feroxbuster, sqlmap, WhatWeb, WPScan, Dirb/Dirbuster, `subfinder`/`amass`, `whois`, `crackmapexec`, `hydra`.

### Install

**Linux / macOS:**

```bash
git clone https://github.com/braydos-h/NetAttackAi
cd NetAttackAi
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Verify your environment

```bash
python main.py --doctor      # checks Python, deps, Nmap, Ollama, models, config, workspaces, ports
python main.py --self-test   # safe localhost-only read-only smoke test
```

### Run it

```bash
python main.py               # interactive menu (the default, no-args behavior)
```

That's it. You're in the interactive menu and can pick a mode.

---

## Common ways to run

### Interactive menu (default)

```bash
python main.py                 # questionary-based interactive menu
python main.py --menu          # same thing, explicit
```

### Recon first, then pick a goal

```bash
python main.py --target 10.0.0.50 --mode recon --recon-first
```

Scans the target, suggests rated goals, then asks you to pick one.

### Direct attack

```bash
python main.py --target 10.0.0.50 --mode attack --goal initial_access
python main.py --target 10.0.0.50 --mode attack --goal backdoor
python main.py --target 10.0.0.50 --mode attack --goal privilege_escalation
python main.py --target 10.0.0.50 --mode attack --custom-goal "extract user database"
```

### Domain targets (Phase 4)

```bash
python main.py --target example.com --mode attack --goal initial_access
```

Resolves the domain to an IP, carries both, and can expand the attack surface via subdomain enumeration (auto-authorizing each discovered host).

### Swarm mode (multi-agent)

```bash
python main.py --target 10.0.0.50 --mode attack --swarm --critic --reflection --adaptive-exploits
```

### Autonomous campaign (persistent multi-phase)

```bash
python main.py --target 10.0.0.50 --mode attack --long-session
python main.py --target 10.0.0.50 --mode attack --long-session --resume <RUN_OR_SESSION_ID>
```

### Standalone exploit with a specific CVE

```bash
python main.py --exploit --exploit-mode standalone --exploit-target 10.0.0.50 \
  --exploit-cve CVE-2021-44228 --exploit-permission full_access
```

### Eval/benchmark harness

```bash
python main.py --eval --target <AUTHORIZED_LAB_IP>   # writes reports/eval/<run_id>/
```

### WebUI API daemon

```bash
python main.py --demon                         # start API on http://127.0.0.1:8765
python main.py --daemon --api-port 9000        # alias, custom port
python main.py --web                           # build + serve + open the WebUI in a browser
```

- **WebUI:** `python main.py --web` builds `webui/dist/` if needed (first run only), serves it at `http://127.0.0.1:8765/`, and opens a browser. The SPA talks to the `/api/v1` REST + WebSocket surface. Requires Node.js/npm on PATH for the first build.
- **Interactive docs (Swagger):** `http://127.0.0.1:8765/docs`
- **OpenAPI schema:** `http://127.0.0.1:8765/openapi.json`
- **Bearer token:** auto-generated into `.webui_secret_key` (gitignored), or set `NETATTACKAI_API_TOKEN`
- Loopback-only bind, one active run at a time, bearer auth everywhere except `/health`

Key API endpoints (all under `/api/v1`):

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | GET | Health check (no auth) |
| `/capabilities` | GET | API features + run options |
| `/config` | GET/PATCH | Redacted config view / atomic update |
| `/runs` | POST | Create a run (preview + start_confirm decision) |
| `/runs` | GET | List run history |
| `/runs/{id}` | GET | Run details (state, decisions, result, errors) |
| `/runs/{id}/cancel` | POST | Cooperative cancellation + child cleanup |
| `/runs/{id}/resume` | POST | Resume from a prior run |
| `/runs/{id}/decisions` | GET | List pending decisions |
| `/runs/{id}/decisions/{id}` | POST | Answer a decision (start_confirm/goal_select/tool_approval) |
| `/runs/{id}/events?after=N` | GET | Replay events from cursor |
| `/ws/v1/runs/{id}` | WS | Live event stream (auth message required) |
| `/runs/{id}/tools` | GET | Live MCP tool schemas |
| `/runs/{id}/tools/{name}/calls` | POST | Policy-gated manual tool call |

### Standalone MCP servers

```bash
python mcp_server.py --transport stdio --approved-subnets 192.168.1.0/24
python mcp_server.py --transport http --host 127.0.0.1 --port 8000 --approved-subnets 192.168.1.0/24
python mcp_exploit_server.py    # defaults: stdio, port 8001
```

---

## CLI reference

### `main.py` flags

| Flag | Purpose |
| --- | --- |
| `--target <ip-or-domain>` | Target IP address or domain to attack/recon |
| `--mode {recon,attack}` | `recon` = gather intel, `attack` = full exploitation |
| `--goal <name>` | Preset goal (`initial_access`, `backdoor`, `privilege_escalation`, etc.) |
| `--custom-goal <text>` | Custom goal description |
| `--config <path>` | Override config file path |
| `--model <alias>` | Override default model alias (`glm`/`kimi`/`deepseek`/`deepseek_flash`/`minimax`) |
| `--model-strategy {default,round-robin,random,specific}` | How to pick model across targets |
| `--mcp-transport {stdio,http}` | MCP transport (run path always forces http so the target-IP lock reaches the server) |
| `--http-port <port>` | HTTP MCP port |
| `--reports-dir <path>` | Override reports directory |
| `--setup-api-keys` | Prompt for provider API keys and save them |
| `--api-key-file <path>` | Local JSON file for saved provider API keys |
| `--no-api-key-prompt` | Skip the interactive startup API-key prompt |
| `--plain` | Disable color output |
| `--menu` | Force interactive menu mode even with other args |
| `--swarm` | Enable multi-agent swarm mode |
| `--parallel-swarm` | Enable parallel sub-agents (`route_parallel` + `spawn_subagent` MCP tool) |
| `--critic` | Enable critic agent pre-approval (requires `--swarm`) |
| `--reflection` | Enable reflection agent (requires `--swarm`) |
| `--adaptive-exploits` | Enable adaptive exploit generation with mutation |
| `--long-session` | Raise context window, timeouts, and budgets for multi-hour attack runs; checkpoints for resume |
| `--multi-model-consult` / `--no-multi-model-consult` | Allow/disallow peer-model advisory consultation |
| `--observer-mode {heuristic,llm,hybrid}` | Observer mode for fact extraction |
| `--recon-first` / `--no-recon-first` | Force/skip recon-first mode |
| `--doctor` | Run self-check (Python, nmap, Ollama, config) and exit |
| `--demo` | Run against a local sandbox target (DVWA-style) |
| `--resume <id>` | Resume a prior run by run_id or session_id |
| `--json` | Emit machine-readable JSON to stdout where supported |
| `--quiet` | Reduce output to warnings/errors only |
| `--debug` | Enable verbose debug output |
| `--yes` | Skip the ready-to-begin confirmation gate (use with caution) |
| `--self-test` | Run a safe localhost smoke test against 127.0.0.1 and exit |
| `--eval` | Run the eval/benchmark harness against `--target` |
| `--ultrathink` | Enable deep reasoning mode: verbose chain-of-thought and frequent reflection |
| `--skills {on,off,hints,lookup}` | Override runtime-skills behavior for this run |
| `--skills-list` | Print the runtime-skill catalog and exit (read-only) |
| `--skills-include <name>` | Force-include a skill by name (repeatable, sticky across re-selection) |
| `--skills-exclude <name>` | Exclude a skill by name (repeatable) |
| `--no-skills-reselect` | Disable mid-run skill re-selection for this run |
| `--list-plugins` | Print discovered plugins (name/version/capabilities/loaded) and exit |
| `--demon` / `--daemon` | Start the local WebUI API server instead of the terminal menu |
| `--web` | Build the WebUI if needed, serve it from the daemon at /, and open a browser |
| `--api-host <host>` | API daemon bind host (loopback only; default 127.0.0.1) |
| `--api-port <port>` | API daemon port (default 8765) |
| `--help` | Show the complete CLI reference |
| `--version` | Show version |

### `cli.py` (legacy structured workflow)

A database-backed, deterministic, scope-gated flow for repeatable assessments. Uses SQLite under `research_workspace/`.

```bash
python cli.py init-mission --config mission.yaml    # create a mission from YAML
python cli.py add-scope --allow "*.example.com"      # add an allow rule
python cli.py add-scope --deny "payments.example.com"# add a deny rule
python cli.py list-scope                              # show all scope rules
python cli.py next-task                               # show next pending task
python cli.py list-tasks                              # list all open tasks
python cli.py run-task T-00001                        # execute a task by ID
python cli.py summarize-target                        # show target memory + graph
python cli.py list-findings                           # list all findings
python cli.py validate-finding F-00001                # run validation on a finding
python cli.py generate-report F-00001                # generate a markdown report
python cli.py status                                  # show agent loop status
```

Core flow:
`Mission -> Scope/Risk Gate -> Planner -> TaskQueue -> Executor -> Observer -> OutcomeJudge -> Evidence/Memory/Graph -> FindingVerifier -> Report`

### Makefile shortcuts (Unix-like)

```bash
make install          # venv + pip install -r requirements.txt
make install-dev      # venv + pip install -e ".[dev]"
make doctor           # python main.py --doctor
make self-test        # python main.py --self-test
make test             # full pytest suite
make test-one F=tests/test_scope_gate.py   # single test file
make run              # interactive menu
make mcp-defensive    # defensive MCP server
make mcp-exploit      # exploit MCP server
make clean            # remove venv + __pycache__ dirs
```

---

## Feature inventory

### 1. Reconnaissance & intelligence

- Nmap-based scanning and host/service discovery (TCP + UDP top-ports)
- Service enrichment and fingerprint helpers (TLS/SSL cert parse, SMTP/DB banner parse, web spider)
- CVE lookup via NVD with circuit breaker + rate limiting
- EPSS + KEV vuln-intel enrichment (opt-in)
- GitHub PoC search (`cve_to_poc`)
- Web research integration (Ollama/SerpAPI) with caching/ranking
- Passive OSINT + IPv6 AAAA lookup (Shodan optional)
- Recon diffing between runs
- **Domain operations:**
  - Domain-to-IP resolution
  - Subdomain enumeration (crt.sh + DNS bruteforce + optional subfinder/amass; auto-authorizes discovered hosts, flags dangling-CNAME takeover)
  - DNS recon (AXFR/DNSSEC/SPF/DMARC/NS-version)
  - Virtual host enumeration (Host-header rotation)
  - WHOIS lookups
  - ASN/WHOIS, WAF fingerprint, SNMP enum, cloud metadata probe (all opt-in, default off)

### 2. Exploit runtime & orchestration

- Policy-driven exploit agent loop with tool-call planning and execution
- Attack goals: `initial_access`, `privilege_escalation`, `persistence`, `backdoor`, `data_exfiltration`, custom goals
- Resume/checkpoint support for long sessions
- Adaptive exploit generation and mutation (parameter tweak, encoding change, delivery swap, context-aware)
- Autonomous multi-phase campaign engine with retries and vulnerability chaining
- Per-attempt attack memory with context-window management
- Outcome judgment separating execution success from evidential success
- Exploit-script synthesis from CVE intel

### 3. Multi-agent swarm mode

Optional specialist swarm with a shared blackboard and battle log:

| Agent | Role |
| --- | --- |
| **Recon** | scanning, fingerprinting, attack-surface scoring |
| **Vuln** | CVE/exploit correlation and module matching |
| **Exploit** | exploit module selection, payload crafting, mutation, handoff |
| **Post-exploit** | post-exploit checks, credential/loot handling, lateral target generation |
| **Critic** | pre-execution scope, risk, and policy review |
| **Reflection** | strategy review and lessons learned |

Enable: `--swarm --critic --reflection`. Parallel sub-agents: `--parallel-swarm` (recon + vuln parallelize by default; exploit/post_exploit parallelize only if `swarm.exploit_parallel: true`).

### 4. Autonomous orchestrator

`tools/autonomous_orchestrator.py` drives persistent multi-phase attack campaigns:

- Adaptive aggression levels (STEALTH / STANDARD / AGGRESSIVE)
- Auto-triggers attack modules from recon findings
- Retries with modified parameters on failure
- Vulnerability chaining + privilege escalation tracking
- Persistence phase, checkpointing, adaptive replan (all opt-in via `config.yaml` `autonomous.*`)
- Domain targeting: subdomain expansion after recon, auto-authorizing each discovered host

### 5. Built-in attack modules

The app ships with a large ranked module set across categories:

| Category | Examples |
| --- | --- |
| Web attack patterns | SQLi, XSS, SSTI, GraphQL (introspect/depth), SSRF, XXE, LFI, request smuggling, race/timing, JWT tamper, password spray, type juggling, mass assignment, prototype pollution, NoSQL injection, IDOR, BFLA, broken-link hijacking, WebSocket vulns, open redirect, CSRF, clickjacking, CSP bypass, cache deception/poisoning, HTTP parameter pollution, directory traversal, email/host-header injection, OAuth misconfig |
| SMB/AD/Kerberos | EternalBlue (MS17-010), Zerologon (CVE-2020-1472), noPAC (CVE-2021-42278/42287), ADCS ESC1, BloodHound, pass-the-hash, AS-REP roast, Kerberoasting, SMB signing check |
| Privilege escalation & post-exploitation | Linux privesc checks, service-account audit, privesc assessment |
| Service-focused | SSH/SMB/FTP/Redis and more |
| ICS/SCADA/IoT | reconnaissance-focused modules |
| Supply-chain/CI | exposure checks |
| CVE-to-exploit synthesis | helpers |
| Detection-coverage | posture checks |

### 6. OPSEC & detection coverage

- Target-aware OPSEC (different posture for local/private vs public targets)
- Pacing/jitter controls, rate-per-minute token bucket
- User-Agent rotation and DNS-over-HTTPS (Cloudflare/Google)
- Command noise scoring and quieter command suggestions
- Detection-coverage planning and audit-footprint reporting surfaces
- Advisory only on the attack path; never gates execution

### 7. Memory, learning & reasoning

| Feature | What it does |
| --- | --- |
| Semantic memory | Ollama `nomic-embed-text` cross-mission learning |
| ExperienceStore | Bayesian confidence scoring for attack outcomes |
| Attack memory | Per-attempt memory with context-window management |
| Runtime skills | Selection / re-selection / feedback pipeline with semantic matching |
| Reasoning | Chain-of-thought, reflection every N actions, LLM-driven reflection (opt-in), ultrathink mode |
| Peer-model consultation | Advisory-only multi-model consultation (peers have no tool schemas) |

### 8. Reporting & artifacts

- Per-run reports under `reports/<run_id>/` (activity JSONL, raw/XML nmap, host markdown, network summary MD/HTML, findings CSV, exploit workspace copy, server logs)
- Enhanced markdown/HTML reporting with timelines, CVSS, exploit chains
- Exploit attempt artifacts in `exploit_workspace/<target>/<attempt_id>/`
- SQLite-backed mission records in `research_workspace/<mission_id>/`
- Eval harness outputs in `reports/eval/<run_id>/`

### 9. Plugin system

Opt-in plugin model to extend the platform without core rewrites:

- Register custom attack modules
- Register MCP tools
- Provide skill directories
- Extend config schema/sections

Plugins are trusted Python with full operator-box privileges, OFF by default (enable via `config.yaml` `plugins.enabled`). A reference plugin lives at `plugins/example_recon_report/`.

```bash
python main.py --list-plugins    # list discovered plugins (name/version/capabilities/loaded)
```

See [docs/plugin-development.md](docs/plugin-development.md) for the full guide.

### 10. Runtime skills

130+ advisory methodology skills in `skills-to-add/`, spanning:

- Core methodology, scope, recon, and workflow
- Recon, enumeration, and evidence analysis
- Web, API, and application security testing
- Exploit research, validation, and controlled exploitation
- Active Directory, privilege escalation, and attack paths
- Agent/MCP safety controls

Skills are advisory prompt-context only and never grant execution authority. Selection is deterministic (tags + config) plus semantic (`nomic-embed-text` cosine similarity), with cross-mission feedback (Bayesian Beta posterior).

```bash
python main.py --skills-list                 # view the catalog
python main.py --skills on                    # startup context injected
python main.py --skills hints                 # hints only (default)
python main.py --skills lookup                # MCP tools only
python main.py --skills off                  # disable skills
python main.py --skills-include <name>       # force-include a skill (repeatable)
python main.py --skills-exclude <name>       # exclude a skill (repeatable)
python main.py --no-skills-reselect          # disable mid-run re-selection
```

See [docs/skills.md](docs/skills.md) for the full pipeline.

---

## MCP tools

The app ships two MCP servers.

### Defensive MCP server (`mcp_server.py`)

Scope-aware, safer integration surface for client-side recon workflows:

- Scope-gated Nmap scanning
- Sanitized vulnerability search
- NVD CVE lookup

The tools enforce scope (approved subnets, allowed assets, forbidden actions, rate limits).

### Exploit MCP server (`mcp_exploit_server.py`)

Exposes the offensive tooling used by the attack runtime. Tools are registered through `tools/mcp_tools/registry.py`:

| Family | Tools |
| --- | --- |
| **Terminal** | `run_exploit_terminal`, `apt_install`, `git_clone`, `pip_install`, `run_as_root`, `check_environment`, `install_package`, `download_and_install`, `update_system` |
| **Recon** | `check_os`, `quick_scan`, `run_full_recon`, `get_service_fingerprint` |
| **Attack modules** | `jwt_tamper`, `ssti_probe`, `graphql_introspect`, `race_request`, `timing_oracle`, `request_smuggling_probe`, `password_spray`, `cve_to_exploit_synth`, `hash_crack_identify`, `create_attack_plan`/`get_current_plan`/`replan`, `start_autonomous_campaign`/`get_campaign_status`/`run_campaign_step`, `list_attack_modules`, `run_attack_module`, `craft_exploit`, `mutate_exploit` |
| **Metasploit** | `run_msf_module`, `msfconsole_start`/`stop`/`command`, `msf_run_exploit`, `msf_run_auxiliary`, `msf_list_sessions`, `msf_interact_session`, `msf_run_post_module`, `msf_kill_session`, `msf_generate_payload`, `msf_run_resource_script` |
| **Payloads** | `generate_payload` (msfvenom) |
| **Web scan** | `run_web_scan` (nikto/nuclei/sqlmap/gobuster/feroxbuster/whatweb/wpscan/dirb/dirbuster). Target-IP allowlist-locked. |
| **Cracking** | `run_hash_crack` (hashcat/john). Local-only, audit-only, auto hash-type identification. |
| **Credentials** | `cred_store_add`/`get`/`list`/`confirm`, `lateral_exec` (impacket), `dump_credentials`, `kerberoast` |
| **Workspace** | `write_python_file`, `run_python_file`, `read_workspace_file`, `list_workspace` |
| **Sessions/processes** | `start_tmux_session`, `send_to_session`, `read_session_output`, `kill_session`, `start_background_job`, `read_job_output`, `stop_background_job`, `start_listener`, `read_listener_output`, `stop_listener`, `list_sessions`, `list_processes`, `kill_process` |
| **Research** | `search_exploit_db`, `search_web_exploit`, `fetch_webpage`, `deep_research`, `search_cve_intel` |
| **Domain** | `resolve_domain`, `enumerate_subdomains`, `dns_recon`, `vhost_enum`, `domain_whois` |
| **Runtime skills** | `list_runtime_skills`, `search_runtime_skills`, `load_runtime_skill`, `list_skill_references` (conditionally registered) |
| **Peer models** | `consult_peer_models` (conditionally registered, advisory-only) |

All target-touching tools require a target IP, stay within `exploit_workspace/<ip>/`, and write to `exploit_audit.jsonl`. The one attack-mode safety kept is the target-IP lock (no pivoting to other hosts). See [Safety model](docs/safety-model.md).

---

## Configuration

### `config.yaml` (main runtime config)

Top-level keys:

| Key | Purpose |
| --- | --- |
| `ollama` | Host, model (`glm-5.2:cloud`), context window |
| `models` | Registry of model aliases (glm/deepseek/deepseek_flash/kimi/minimax) + `default_alias` |
| `mcp` | Default transport, http host/port |
| `nmap` | Path, sudo, priv_fallback |
| `exploit` | Mode, permission, attack mode, timeouts, workspace, allowed_targets, require_explicit_allowlist, shell, msfconsole_path, AD/Kerberos suite, MSF recipes, listener types |
| `stealth` | Legacy UI-only block (live block is `opsec`) |
| `opsec` | enabled, ua_rotation, doh, doh_provider, min_gap_seconds, jitter_seconds, rate_per_minute, quiet_command_patterns, noise_budget, local_targets_off, local_cidrs, public_autonomy |
| `cve_lookup` | NVD settings, EPSS/KEV enrichment, GitHub token |
| `research` | Provider (ollama/serpapi), timeouts, caching, assistant config |
| `swarm` | enabled, agents, max_parallel_agents, parallel_enabled, per_phase_concurrency, exploit_parallel, subagent_timeout_seconds |
| `autonomous` | persistence_phase, checkpoint_every, adaptive_replan, max_cycles, max_pivot_depth |
| `recon` | extended_enumerators, udp_top_ports, shodan_api_key, domain_resolution, extended depth enumerators (subdomain_enum, vhost_discovery, waf_fingerprint, asn_whois, cloud_metadata_probe, snmp_enum, dns_zone_transfer) |
| `eval` | output_dir, max_rounds, write_markdown, write_html |
| `long_session` | enabled, request_timeout_seconds, swarm_session_timeout_minutes, attack_max_rounds/commands/duration_minutes, persist_messages |
| `reasoning` | chain_of_thought, reflection_every_n_actions, critic_enabled, observer_mode, ultrathink, llm_reflection, peer_consult_on_failure_threshold |
| `memory` | semantic_enabled, embedding_model, cross_mission_learning, attack_memory, experience settings |
| `outcome_judgment` | max_inconclusive_attempts, confirmation/refutation thresholds, min_evidence_references, flow_a |
| `adaptive_exploits` | enabled, max_mutations, mutation_strategies |
| `multi_model` | enabled, consult_aliases, max_consultations, max_question/answer_chars |
| `skills` | enabled, roots, default_enabled, include_tags, semantic_matching, reselect_*, feedback_*, swarm_inject |
| `api` | enabled, host, port, token_file, allowed_origins, event_buffer_size, shutdown_timeout_seconds, serve_webui |

### `mission.yaml` (mission scope, for `cli.py`)

| Key | Purpose |
| --- | --- |
| `program_name` | Mission name |
| `objective` | Objective statement |
| `risk_profile` | `low_noise_non_destructive` / `standard_authorized` / `high_authorized_testing` |
| `allowed_assets` | Domains, wildcards, IPs, CIDRs in scope |
| `disallowed_assets` | Assets explicitly excluded |
| `forbidden_actions` | Always-forbidden action types (DoS, destructive, social engineering, etc. are hard-blocked regardless) |
| `rate_limits` | Per-target/per-action rate limits |
| `testing_modes` | Which phases are permitted (`recon`, `analysis`, `test`, `validate`, `exploit`, `report`) |
| `accounts` | Optional credentials for authenticated testing |
| `notes` | Context, program rules, special instructions |

### API key setup

```bash
python main.py --setup-api-keys     # prompt for provider API keys, save to secr.json
```

Supported keys: `NVD_API_KEY`, `SERPAPI_API_KEY`, `OLLAMA_API_KEY`, `GITHUB_TOKEN`, `SHODAN_API_KEY`.

---

## Generated workspace layout

| Path | Contents |
| --- | --- |
| `reports/<run_id>/` | Per-run outputs: activity.jsonl, raw_nmap/, xml_nmap/, host_<ip>.md, network_summary.{md,html}, findings.csv, mcp_server.log, exploit_workspace/ |
| `reports/eval/<run_id>/` | Eval harness outputs (eval_report.md/.html/.json) |
| `research_workspace/<mission_id>/` | Flow B mission data (research.db, evidence/, reports/) |
| `exploit_workspace/<target_ip>/<attempt_id>/` | Per-attempt exploit artifacts (exploit_script.py, terminal.log, python_run.log, msf_output.log, run_active_check.ps1) + `exploit_audit.jsonl` |
| `exploit_workspace/loot/` | Loot workspace |
| `swarm_workspace/` | Swarm-generated artifacts (created on demand) |

---

## Authorized use only

This tool is for legal, authorized testing only.

- Do not run against systems you do not own or explicitly control under written authorization.
- Do not treat built-in controls as legal authorization.
- Review and constrain scope before every run.
- Prefer recon-first runs before offensive paths.

For detailed boundaries and safety behavior, read [docs/safety-model.md](docs/safety-model.md).

**Permission modes** (`tools/exploit_agent/policy.py`):

| Mode | Behavior |
| --- | --- |
| `full_access` | Lab attack posture. Auto-approves every action; the only gate is the target-IP lock. |
| `approve_only` | Every tool call requires operator approval (interactive/recon paths). |
| `read_only` | Gather intel and propose attacks without executing (recon uses this). |

**Hard-blocked actions** regardless of config: `denial_of_service`, `destructive_exploit`, `social_engineering`, `physical_attack`, `malware`, `credential_theft` (see `scope_gate.py:_HARD_FORBIDDEN_ACTIONS`).

---

## Development

Install dev extras and run tests:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -v                                    # full suite
python -m pytest tests/test_scope_gate.py -v                  # single file
python -m pytest tests/test_recon_pipeline.py::TestClass::test_method -v   # single test
python -m pytest tests/ -v -k "scope"                         # by keyword
python -m pytest --cov=tools --cov=main.py --cov=cli.py       # with coverage
ruff check .                                                   # lint (line-length 120, select E/F/W/I)
```

The test suite (~80 files in `tests/`) covers scope gates, safety review, semantic memory, recon, MCP workspaces, reporting, CVE lookup, the agent loop, reliability, swarm behavior, retry logic, skills, reasoning, long sessions, peer consultation, audit chains, credential storage, Metasploit integration, and more.

---

## Documentation

| Doc | What it covers |
| --- | --- |
| [docs/getting-started.md](docs/getting-started.md) | Setup, common commands, local development loop |
| [docs/architecture.md](docs/architecture.md) | System shape, entry points, persistence, major flows |
| [docs/runtime-flows.md](docs/runtime-flows.md) | How recon, execution, exploitation, swarm, and MCP flows move through the code |
| [docs/module-guide.md](docs/module-guide.md) | Responsibilities of top-level modules, `tools/`, and tests |
| [docs/extension-guide.md](docs/extension-guide.md) | Exact edit points for adding tools, integrations, config, persistent data, tests |
| [docs/plugin-development.md](docs/plugin-development.md) | Writing, packaging, enabling, and distributing out-of-tree plugins |
| [docs/safety-model.md](docs/safety-model.md) | Scope checks, risk checks, permission modes, audit records, secure dev rules |
| [docs/testing-guide.md](docs/testing-guide.md) | Test layout, focused test commands, what to update with each change |
| [docs/skills.md](docs/skills.md) | Advisory skill pipeline: selection, re-selection, feedback, semantic matching |

---

## License

GPL-3.0-only. See [LICENSE](LICENSE).
