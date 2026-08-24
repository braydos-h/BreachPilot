# CLI Reference

Complete reference for every command-line entry point, flag, interactive option, and environment
variable in NetAttackAI. See `docs/getting-started.md` for setup and first commands.

## Entry Points

There are three top-level Python entry points, one per flow (see AGENTS.md Flow A / Flow B):

| Command | Flow | Purpose |
|---------|------|---------|
| `python main.py` | Flow A (modern, what users run) | Interactive menu, direct recon/attack runs, doctor/self-test/eval/demo, WebUI daemon |
| `python app.py` | Flow A | ASGI app factory — **not a CLI**; imported by `main._run_daemon` (`app.py:38`), never run directly |
| `python cli.py` | Flow B (legacy, SQLite-backed) | Database-backed mission/scope/task/finding/report workflow commands |

`app.py` contains no argument parser; it is invoked as `python main.py --demon` which imports
`create_app` (`main.py:532`) and serves it with uvicorn (`main.py:560`).

The MCP servers are separate entry points: `python mcp_server.py` (defensive),
`python mcp_exploit_server.py` (exploit, target-lock enforced), `python mcp_engine_server.py`
(engine advisory). All accept `--transport stdio|http`, `--config`, `--host`, `--port`
(`mcp_exploit_server.py:203-209`).

## `python main.py` — Flow A

Argument parser: `main.py:342-430`. Dispatch order in `main()` (`main.py:803`): API-key bootstrap →
`--setup-api-keys` exit → daemon (`--demon`/`--daemon`/`--web`) → `--doctor` → `--self-test` →
`--eval` → `--demo` → `--skills-list` → `--list-plugins` → interactive menu (`--menu` or no args)
→ `async_main` (`main.py:566`).

### Run flags

| Flag | Default | Description | Line |
|------|---------|-------------|------|
| `--version` | — | Print `NetAttackAI <version>` and exit | `main.py:344` |
| `--target <ip-or-domain>` | `""` | Target to attack or recon. Accepts an IP **or a domain** (Phase 4); domains resolve via `tools/validation_utils.resolve_target_to_ip` and thread `EXPLOIT_TARGET`/`EXPLOIT_TARGET_IP`/`EXPLOIT_TARGET_DOMAIN` into the MCP server (AGENTS.md rule 6) | `main.py:345` |
| `--mode {recon,attack}` | `""` | `recon` = gather intel only, `attack` = full exploitation. Recon is always `read_only` (`tools/cli_exploit_settings.py:157-159`) | `main.py:346` |
| `--goal <name>` | `""` | Preset goal: `backdoor`, `initial_access`, `privilege_escalation`, … | `main.py:347` |
| `--custom-goal <text>` | `""` | Free-text goal description | `main.py:348` |
| `--config <path>` | `config.yaml` | Config file path | `main.py:349` |
| `--model <alias>` | config default | Override model alias (`glm`/`kimi`/`deepseek`/`deepseek_flash`/`minimax`) | `main.py:350` |
| `--model-strategy {default,round-robin,random,specific}` | `default` | How to pick model across targets | `main.py:351` |
| `--mcp-transport {stdio,http}` | `None` | MCP transport. Ignored on the run path: always forced to `http` so the target-IP lock reaches the server | `main.py:353` |
| `--http-port <n>` | `None` | HTTP port for the MCP server (http transport) | `main.py:355` |
| `--reports-dir <path>` | `reports` | Root dir for run artifacts (`reports/<run_id>/`) | `main.py:356` |
| `--resume <run_id\|session_id>` | `""` | Resume a prior run by run_id or session_id | `main.py:391` |

### Swarm / reasoning flags

| Flag | Description | Line |
|------|-------------|------|
| `--swarm` | Enable multi-agent swarm mode | `main.py:363` |
| `--parallel-swarm` | Parallel sub-agents (recon + vuln-research parallelize; exploit/post_exploit stay sequential unless `swarm.exploit_parallel`) | `main.py:364` |
| `--critic` | Critic agent pre-approval (requires `--swarm`) | `main.py:371` |
| `--reflection` | Reflection agent (requires `--swarm`) | `main.py:372` |
| `--adaptive-exploits` | Adaptive exploit generation with mutation on failure | `main.py:373` |
| `--long-session` | Raise context window, LLM call timeout, round/command/duration budgets, and the swarm cap for multi-hour runs; checkpointed messages for crash-safe resume | `main.py:374` |
| `--multi-model-consult` / `--no-multi-model-consult` | Allow / forbid the agent asking configured peer models for advisory help | `main.py:377`, `main.py:379` |
| `--observer-mode {heuristic,llm,hybrid}` | Observer fact-extraction mode | `main.py:381` |
| `--recon-first` / `--no-recon-first` | Force recon-first (scan, suggest rated goals, then ask) / skip straight to goal selection | `main.py:382`, `main.py:384` |
| `--ultrathink` | Deep reasoning: verbose chain-of-thought and frequent reflection | `main.py:405` |

### Operational flags

| Flag | Description | Line |
|------|-------------|------|
| `--doctor` | Run the self-check (Python, nmap, Ollama, config) and exit — `tools.doctor.run_doctor` | `main.py:387`, dispatched `main.py:858` |
| `--self-test` | Run the safe localhost smoke test against `127.0.0.1` and exit — `tools.self_test.run_self_test` | `main.py:401`, dispatched `main.py:863` |
| `--eval` | Run the eval/benchmark harness against `--target` and write `reports/eval/<run_id>/`; requires `--target`, returns 2 without one (`tools/eval_harness.py:362-367`) | `main.py:403`, dispatched `main.py:868` |
| `--demo` | Run against a local sandbox target (DVWA via Docker on `127.0.0.1:8081`, synthetic in-process HTTP server as fallback); writes `reports/demo/demo_report.md` (`tools/demo_mode.py:118-198`) | `main.py:389`, dispatched `main.py:873` |
| `--resume <run_id>` | See run flags | `main.py:391` |
| `--yes` | Skip the ready-to-begin confirmation gate (`main.py:747-763`) — use with caution | `main.py:399` |
| `--json` | Machine-readable JSON to stdout where supported; also forces plain output | `main.py:393` |
| `--quiet` | Warnings/errors only; forces plain output | `main.py:395` |
| `--debug` | Verbose debug output; sets `AI_NMAP_DEBUG=1` (`main.py:590`) | `main.py:397` |
| `--plain` | Disable color output (ANSI) | `main.py:360` |

### API keys / config

| Flag | Description | Line |
|------|-------------|------|
| `--setup-api-keys` | Prompt for provider API keys and save them to the key file; exits after saving | `main.py:357` |
| `--api-key-file <path>` | Local JSON file for saved provider API keys (default `secr.json` / `DEFAULT_API_KEY_FILE`) | `main.py:358` |
| `--no-api-key-prompt` | Skip the interactive startup API-key prompt | `main.py:359` |

Startup key loading lives in `tools/config_cli.py:175` (`bootstrap_startup_api_keys`) and
`tools/api_key_store.py`.

### Skills / plugins flags

| Flag | Description | Line |
|------|-------------|------|
| `--skills {on,off,hints,lookup}` | Override runtime-skills behavior: `on`=startup context, `hints`=hints only (default), `lookup`=MCP tools only, `off`=disabled | `main.py:408` |
| `--skills-list` | Print the read-only runtime-skill catalog and exit | `main.py:411` |
| `--skills-include <name>` | Force-include a skill for this run. Repeatable (`action="append"`) | `main.py:413` |
| `--skills-exclude <name>` | Exclude a skill for this run. Repeatable | `main.py:415` |
| `--no-skills-reselect` | Disable mid-run skill re-selection | `main.py:417` |
| `--list-plugins` | Print discovered plugins (name/version/capabilities/loaded) and exit | `main.py:420` |
| `--ctf` | CTF autopilot: hunt flag file and exit when found | `main.py:431` |
| `--ctf-flag-path <path>` | CTF flag file path (default `/flag.txt`) | `main.py:432` |
| `--ctf-marker <str>` | CTF known-string marker expected from `--ctf-port` | `main.py:434` |
| `--ctf-port <n>` | CTF port to probe for marker | `main.py:433` |
| `--ctf-root-shell` | CTF: assume root shell | `main.py:435` |

### WebUI / API daemon flags

| Flag | Description | Line |
|------|-------------|------|
| `--demon`, `--daemon` | Start the local WebUI API server instead of the terminal menu (`main._run_daemon`, `main.py:509`) | `main.py:423` |
| `--web` | Daemon mode plus: build `webui/dist/` if needed, serve it at `/`, open a browser (`main.py:537-558`, `_ensure_webui_build` `main.py:436`) | `main.py:425` |
| `--api-host <host>` | Daemon bind host — **loopback only** (`127.0.0.1`/`localhost`/`::1`); any other host exits with code 2 (`main.py:516-518`) | `main.py:427` |
| `--api-port <n>` | Daemon port (default 8765) | `main.py:428` |

Daemon mode refuses to combine with target/goal/menu/doctor/demo/eval/self-test/skills-list/
list-plugins/setup-api-keys flags and exits 2 on conflict (`main.py:841-855`). The API is served
by the FastAPI factory in `app.py:38`, mounted under `/api/v1`, bearer-token protected
(`NETATTACKAI_API_TOKEN` env override, `app.py:69-73`).

### Interactive menu (default no-args)

`python main.py` with no arguments (or `--menu`, `main.py:903-905`) launches the questionary menu
(`tools/interactive_menu.py:633`):

1. **Recon & Suggest Goals** — recon-first session (`interactive_menu.py:576`)
2. **Start New Session** — interactive wizard → `async_main` (`interactive_menu.py:565`)
3. **Manage Missions** — list/create/delete Flow B missions in `research_workspace/research.db` (`interactive_menu.py:81`)
4. **View Reports** — browse `reports/<run_id>/` sessions (`interactive_menu.py:257`)
5. **Settings** — write a default `config.yaml` if missing (`interactive_menu.py:480`)
6. **Help** — quick reference (`interactive_menu.py:587`)
7. **Exit**

Menu choices defined at `interactive_menu.py:540-553`; fallback numbered menu at
`interactive_menu.py:53`. The wizard itself lives in `tools/attack_ui.py`:
`ask_advanced_settings` (`attack_ui.py:1261`) covers all CLI flags with current values as
defaults; `ask_power_ups` (`attack_ui.py:1214`) is a multi-select for
swarm/critic/reflection/adaptive-exploits/long-session/ultrathink/debug/yes. When no `--target`
is given, the flow prompts for one (`main.py:656-664`) and, in interactive sessions, persists it
to `exploit.allowed_targets` in the config (`main.py:685-693`, `tools/config_cli.py:30`).

## `python cli.py` — Flow B (SQLite mission workflow)

Subcommands built at `cli.py:504-572`. All commands except `init-mission` accept
`--mission-id <id>` (placed after the subcommand) to operate on a specific mission instead of
the latest `active` one — the resume/reattach path (`cli.py:513-518`).

| Command | Flags | Description | Line |
|---------|-------|-------------|------|
| `init-mission` | `--config <path>` (required) | Create a new mission from a YAML config | `cli.py:521` |
| `add-scope` | `--allow <pattern>`, `--deny <pattern>`, `--notes <text>` | Add an allow or deny scope rule (domain, IP, CIDR, `*.wildcard`) | `cli.py:526` |
| `list-scope` | `--mission-id` | Show all scope rules for the active mission | `cli.py:533` |
| `next-task` | `--mission-id` | Show the next pending task | `cli.py:537` |
| `list-tasks` | `--mission-id` | List open (and blocked) tasks | `cli.py:541` |
| `run-task` | `[task_id]` positional (empty = next pending), `--mission-id` | Execute a task through scope gate → risk controller → executor | `cli.py:545` |
| `summarize-target` | `--target <name>`, `--mission-id` | Target memory summary + target graph | `cli.py:550` |
| `list-findings` | `--mission-id` | List all findings with status icons | `cli.py:555` |
| `validate-finding` | `finding_id` positional (e.g. `F-00001`), `--mission-id` | Run validation, print JSON result | `cli.py:559` |
| `generate-report` | `finding_id` positional, `--mission-id` | Generate a markdown report for a finding | `cli.py:564` |
| `status` | `--mission-id` | Agent loop status: mission, risk, task counts, findings | `cli.py:569` |

Examples:

```powershell
python cli.py init-mission --config mission.yaml
python cli.py add-scope --allow "*.example.com" --notes "main scope"
python cli.py add-scope --deny "payments.example.com"
python cli.py next-task
python cli.py run-task T-00001
python cli.py next-task --mission-id M-001     # resume/reattach a paused mission
python cli.py status
```

Data lives in `research_workspace/research.db` (override with `RESEARCH_WORKSPACE`, `cli.py:39-48`).
Exit codes: 0 success, 1 error (including scope/risk blocks that set the task to
`needs_approval`, `cli.py:338-341`), 130 on Ctrl-C (`cli.py:588-590`). No command → help, exit 1
(`cli.py:582-584`).

## Exit Codes

| Code | Meaning | Source |
|------|---------|--------|
| 0 | Success / clean exit | throughout |
| 1 | Run failure, invalid config/target, aborted session, setup-only path | `main.py:622, 664, 681, 693, 778, 799`; `cli.py` errors |
| 2 | Daemon flag conflicts; non-loopback `--api-host`; `--eval` without `--target` | `main.py:518, 854`; `tools/eval_harness.py:367` |
| 130 | `KeyboardInterrupt` | `main.py:908-910`; `cli.py:588-590` |

## Example Workflows

```powershell
# Recon-only (read_only permission enforced — tools/cli_exploit_settings.py:157)
python main.py --target 10.0.0.50 --mode recon --goal initial_access

# Recon-first: scan, suggested rated goals, then operator picks
python main.py --target 10.0.0.50 --recon-first

# Full exploit (interactive ready-to-begin gate; --yes skips it)
python main.py --target 10.0.0.50 --mode attack --goal backdoor --yes

# Swarm mission with critic + reflection
python main.py --target 10.0.0.50 --mode attack --swarm --critic --reflection

# Long multi-hour run with checkpointed resume
python main.py --target 10.0.0.50 --mode attack --long-session

# WebUI: build, serve, and open the SPA
python main.py --web

# API daemon only (no SPA build)
python main.py --daemon --api-port 9000

# Diagnostics
python main.py --doctor
python main.py --self-test
python main.py --eval --target 10.0.0.50

# Demo against a local sandbox (Docker DVWA or synthetic server)
python main.py --demo

# Flow B mission workflow
python cli.py init-mission --config mission.yaml
python cli.py run-task; python cli.py status; python cli.py list-findings
```

## Environment Variables

### Target / allowlist (threaded into the MCP server)

| Variable | Effect | Source |
|----------|--------|--------|
| `EXPLOIT_TARGET` | Target IP lock for the exploit MCP server's terminal tool (`tools/mcp_tools/terminal.py:31`) | `tools/mcp_shared.py` |
| `EXPLOIT_TARGET_IP`, `EXPLOIT_TARGET_DOMAIN` | Resolved IP / original domain of the target | AGENTS.md rule 6 |
| `EXPLOIT_DISCOVERED_TARGETS` | Comma-separated discovered targets unioned into the allowlist matcher | `tools/mcp_shared.py:528-555` |
| `EXPLOIT_WORKSPACE` | Workspace root (e.g. `.kev_catalog.json` path) | `tools/cve_lookup.py:171` |

### API keys

| Variable | Effect | Source |
|----------|--------|--------|
| `OLLAMA_API_KEY` | Required for the Ollama Cloud default path; auto-attached to chat/generate requests | `tools/doctor.py:154`; AGENTS.md rule 7 |
| `SERPAPI_API_KEY` | Research web-search provider | `tools/api_key_store.py:51` |
| `NVD_API_KEY` | CVE lookup | `tools/api_key_store.py:52` |
| `GITHUB_TOKEN` | Exploit search / CVE GitHub lookups | `tools/exploit_search.py:224`; `tools/api_key_store.py:53` |
| `SHODAN_API_KEY` | Shodan recon (optional) | `tools/recon_pipeline.py:287` |

Keys are loaded from the `--api-key-file` JSON into `os.environ` when not already set
(`tools/api_key_store.py:110-118`). Missing-key names come from `configured_api_key_env_names`
(`tools/api_key_store.py:33`).

### WebUI API

| Variable | Effect | Source |
|----------|--------|--------|
| `NETATTACKAI_API_TOKEN` | Bearer token override for the API daemon (else `.webui_secret_key` file) | `app.py:69-73`; `tools/api/auth.py:46` |
| `NETATTACKAI_API_KEY_FILE` | API key file path used by the API routes | `tools/api/routes/system.py:144, 181` |

### Behavior / debug

| Variable | Effect | Source |
|----------|--------|--------|
| `AI_NMAP_DEBUG` | Verbose nmap/exploit loop logging (`--debug` sets it) | `tools/exploit_agent/loop.py:182`; `main.py:590` |
| `AI_NMAP_ACTIVE_MODEL_ALIAS` | Active model alias override for MCP registry/peer tools | `tools/mcp_tools/registry.py:201` |
| `AI_NMAP_MULTI_MODEL_ENABLED` | Force multi-model enablement for the MCP server | `tools/mcp_tools/registry.py:220` |
| `AI_NMAP_AUDIT_VERIFY_VERBOSE` | Verbose audit verification output | `tools/exploit_agent/policy.py:340` |
| `AI_NMAP_VAULT_KEY` | Credential-store vault key (else auto-generated) | `tools/credential_store.py:149` |
| `MCP_ALLOW_PUBLIC_BIND` | Allow MCP HTTP servers to bind non-loopback | `tools/mcp_shared.py:1022` |
| `MCP_HTTP_TOKEN` | Bearer token for MCP HTTP transport | `tools/mcp_shared.py:1081` |
| `RESEARCH_WORKSPACE` | Flow B workspace root (default `research_workspace`) | `cli.py:39-43`; `tools/logging_setup.py:18` |

## Windows vs Linux

- **Windows is the primary dev platform.** The Makefile is Unix-only — `make doctor` etc. do not
  run on Windows; use the equivalent `python main.py --doctor` commands (Makefile:1-3).
- `scripts/setup-linux.sh` is a one-shot Linux/macOS bootstrap: venv + requirements + external
  tool check (nmap, ollama, tmux, searchsploit, msfconsole, hydra, impacket) + `ollama pull` +
  `python main.py --doctor` (`scripts/setup-linux.sh:21-54`). There is no Windows equivalent.
- Makefile targets map to: `doctor` → `main.py --doctor`, `self-test` → `main.py --self-test`,
  `eval` → `main.py --eval`, `test` → `pytest tests/ -v`, `test-one F=...` → focused pytest,
  `run` → `main.py`, `mcp-defensive|exploit|engine` → the three MCP servers (Makefile:22-48).
- Linux nmap `-O`/`-sS` need root: set `nmap.sudo: true` (uses `sudo -n`) or run as root; else
  `nmap.priv_fallback` (default true) auto-downgrades. Windows attacker = Python-only exploits;
  Linux attacker = full Kali arsenal (searchsploit/metasploit/hydra/crackmapexec/impacket).
- ANSI colors are auto-enabled on Windows terminals via `_enable_windows_ansi`
  (`tools/attack_ui.py:122-141`); `--plain`/`--quiet`/`--json` disable them.
- The interactive menu renders a plain ASCII banner that works on Windows cmd
  (`tools/interactive_menu.py:524-533`); questionary fallbacks are numbered-input menus.
