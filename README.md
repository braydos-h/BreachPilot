# NetAttackAI

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![WebUI](https://img.shields.io/badge/WebUI-React%20%2B%20Vite%20%2B%20TypeScript-06b6d4?style=flat-square&logo=react&logoColor=white)
![LLM](https://img.shields.io/badge/LLM-Ollama%20Cloud%20%7C%20ChatGPT-22c55e?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-1.27%2B-f97316?style=flat-square)
![Skills](https://img.shields.io/badge/Skills-140%2B-8b5cf6?style=flat-square)
![MCP Tools](https://img.shields.io/badge/MCP%20Tools-90%2B-ec4899?style=flat-square)
![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)

<img width="1725" height="912" alt="NetAttackAI WebUI — Mission Control" src="https://github.com/user-attachments/assets/45b6af2f-91e2-4eaf-a4cd-1352dbd42e0c" />

### **The autonomous adversary that never sleeps.**

**Plan · Recon · Exploit · Prove · Report — end-to-end, against targets you own.**

An AI operator that **thinks in kill-chains, not checklists**. It discovers, it reasons, it chains, it proves — and it writes the report. Powered by Ollama Cloud (976K context), MCP, and 140+ advisory skills. Lab-only, target-locked, fully audited. The most complete open-source autonomous pentest engine you'll find.

[Quick Start — 60s](#quick-start--60-seconds) · [Live Demo](#the-webui--your-mission-control) · [Full Arsenal](#the-full-arsenal--what-it-actually-does) · [Safety Model](#safety) · [Docs](docs/)

</div>

---

> [!WARNING]
> **Authorized use only.** Only test systems you own or have explicit written permission to assess. Run on a throwaway operator box.
> **Attack mode = `full_access`** — every action is auto-approved. The only safety is the **target-IP allowlist lock** (a destination guard, not a sandbox). Recon stays fully scope-gated. See [Safety Model](#safety).

---

## Why NetAttackAI Hits Different

Most tools scan. A few exploit. **NetAttackAI runs the whole operation** — like handing a lab target to an elite operator and watching it work.

<table>
<tr>
<td width="33%" valign="top">

### 🧠 Thinks Like an Attacker
Not a script kiddie checklist. Builds a **real AttackPlan DAG** with prerequisites, hypotheses, and failure recovery. Retries with new params, switches capabilities, creates prerequisites on the fly. Every decision logged to `decision_log.jsonl`.

</td>
<td width="33%" valign="top">

### 🐝 Swarm Intelligence
**6 specialist agents** on a shared blackboard — `recon`, `vuln`, `exploit`, `post_exploit`, `critic`, `reflection`. Parallel dispatch, battle logs, cross-phase negotiation. Plus a persistent **Autonomous Orchestrator** for multi-phase campaigns that don't quit.

</td>
<td width="33%" valign="top">

### 🎯 Prove, Don't Claim
**Hypothesis-driven verdicts** via `OutcomeJudge`: every finding is `confirmed` / `refuted` / `exhausted`. Execution success ≠ evidential success. No hallucinations. Evidence or it didn't happen.

</td>
</tr>
<tr>
<td width="33%" valign="top">

### 🌐 Domain-Native
Feed it `example.com` — it **resolves, expands subdomains** (crt.sh + DNS bruteforce + subfinder/amass), auto-authorizes every discovered host, flags dangling-CNAME takeovers, and attacks the whole surface. Wildcard + CIDR allowlist support.

</td>
<td width="33%" valign="top">

### 🛡️ Lab-Grade, Target-Locked
`full_access` on the operator box, **hard-locked to your allowlist** at the MCP tool layer. Every destination extracted from every command — URL authorities, `/dev/tcp`, LHOST/RHOST, bare IPs, hostnames. Not in the allowlist = `BLOCKED`. Plus a **tamper-evident SHA256 audit chain** for every target-touching action.

</td>
<td width="33%" valign="top">

### 📚 140 Skills. 90 Tools. 15 Attack Families.
From **network penetration testing** to **AD CS ESC1**, **JWT confusion**, **SSTI**, **GraphQL**, **XXE**, **AD BloodHound**, **EternalBlue**, **Zerologon**, **noPac** — the brain has seen it. Deterministic + semantic skill selection, re-selected mid-run as new services/CVEs appear.

</td>
</tr>
</table>

---

## The Full Arsenal — What It Actually Does

NetAttackAI isn't a wrapper. It's a **full-spectrum autonomous assessment platform**. Here's everything crammed inside:

### 🔍 Recon That Doesn't Miss
- **Fast recon pipeline** — parallel TCP discovery, service fingerprinting, OS detection, vulnerability enrichment — all concurrent, all cached.
- **Nmap done right** — ping sweep → triage → service → vuln scans, with `priv_fallback` auto-downgrade and pre-flight reachability probes so firewalled hosts don't waste your time.
- **Extended enumerators** — UDP top-ports, SNMP, DNS zone transfer / DNSSEC / SPF / DMARC, ASN/WHOIS, cloud metadata probe, WAF fingerprinting, vhost discovery.
- **Domain recon** — `resolve_domain`, `enumerate_subdomains`, `dns_recon` (AXFR/DNSSEC), `vhost_enum` (Host-header rotation), `domain_whois` — all allowlist-gated.
- **Threat intel** — NVD + EPSS + CISA KEV + OSV + GHSA, with circuit breaker, rate limiting, and GitHub token support for PoC search.

### 💥 Exploit Engine That Chains
- **15 attack module families** (`tools/attack_modules/modules/`): `web`, `auth_creds`, `crypto_jwt`, `deserialize`, `network_smb`, `privesc`, `services`, `ssh`, `synthesis`, `supply_chain`, `persistence`, `ad`, `ics_iot`, `detection`, `orchestrator_phases` — each scores its own applicability (0–100) against your target's services/ports/CVEs.
- **Capability-aware planning** — every module declares `requires` / `produces` / `read_only` / `cost` / `phase_hint` so the planner can **dynamically compose prerequisites** (`find_producers(artifact)`) and gate execution.
- **Payload crafting & mutation** — `PayloadCrafter` + `ExploitMutator` with 5 strategies: parameter tweak, encoding change, delivery swap, context-aware. Auto-generates and mutates Python exploit scripts.
- **Metasploit bridge** — `run_msf_module`, `msfconsole` lifecycle, `msfvenom` payload generation, session/payload/post-module orchestration, resource scripts. Full Kali arsenal on Linux, Python-only on Windows.
- **Web scanning** — nikto / nuclei / sqlmap / gobuster / feroxbuster / whatweb / wpscan — argv-list execution, `which`-checked, parsed `WEB_SCAN_RESULT` blocks.

### 🧬 Intelligence That Learns
- **140+ advisory skills** — YAML + markdown prompt-context layer, scored by deterministic tags + lexical search + **cross-mission Bayesian feedback** + **semantic cosine similarity** over `nomic-embed-text` embeddings. Mid-run re-selection as new CVEs surface.
- **Semantic memory** — `nomic-embed-text` cross-mission learning via `SemanticMemoryManager` + `ExperienceStore`. The orchestrator stores lessons on every confirmed win.
- **Attack memory** — per-attempt context window management (6K chars), compaction every 50 rounds, persistent campaign state.
- **Model telemetry** — token counts, context utilization, duration, tokens/sec for every LLM call.
- **Multi-model war room** — consult Kimi K2.6, DeepSeek V4 Pro (1M context), GLM-5.2, Minimax M3 mid-run for advisory ideas without tool access. Configurable `consult_aliases`.

### 🏴 Post-Exploit & Lateral
- **Credential ops** — encrypted vault (`credential_store`), `lateral_exec` via Impacket, `dump_credentials`, `kerberoast`, `hash_crack` (hashcat/john with auto hash-type ID + `--show` recovery).
- **AD domination** — BloodHound CE, AD ACL abuse, AS-REP roast, pass-the-hash, ADCS/Certipy, Golden Ticket, Responder relay, SMB signing checks.
- **Operator connection** — persistent RCE beacons (netcat/TLS/DNS/HTTPS/SOCKS pivot) with `exploit_workspace` callback management.
- **ICS/IoT** — Modbus & S7 PLC modules (read-only by default; **destructive writes dual-gated** behind `ics.allow_write` + `ics.destructive_ics`).

### 🕵️ OPSEC & Evasion
- **Target-aware OPSEC** — auto-disabled on private/local targets (RFC1918/loopback/link-local) so the agent moves freely in your lab; full posture on public targets. UA rotation, DoH, pacing with jitter, rate limiting, quiet-command rewrites, noise budget — all **advisory, never a gate** (the command always executes, but you get `OPSEC_ADVISORY` blocks suggesting quieter alternatives).

### 📊 Report Like a Pro
- **MITRE ATT&CK Navigator** export — technique-mapped layer JSON for SOC handoff (`reports/mitre/`).
- **Ticketing** — auto-create Jira/GitHub issues from confirmed findings.
- **Enhanced reporting** — timelines, CVSS, exploit chains, Markdown + HTML, `decision_log.jsonl`, tamper-evident audit, loot & credential tables, graph evidence.

---

## The WebUI — Your Mission Control

Everything lives at **`http://127.0.0.1:8765`** — loopback-only, bearer-token gated, dark-mode, real-time.

| Page | What you get |
|------|-------------|
| **New Run Wizard** | Pick target → model → goal → power-ups → confirm & launch. Domain or IP. One click. |
| **Live Run** | Real-time event stream, tool calls, decisions, telemetry — WebSocket + SSE, token-gated, ring-buffered. |
| **Attack Graph** | Interactive **DAG** (ReactFlow) — pan, zoom, filter, find paths, inspect evidence. Powered by `AttackPlan` with `ready_steps()` / `blocked_steps()` / `graph_summary()`. |
| **Artifacts & Audit** | Reports, raw Nmap, findings, SHA256 audit chain — everything tamper-evident. |
| **Loot & Credentials** | Captured creds and loot per run, encrypted at rest. |
| **System** | Config editor, secrets, models/providers, skills, plugins, diagnostics — no YAML editing needed. |

Built as a **Vite + React + TypeScript SPA** (`webui/`) with TanStack Query, Radix UI, Tailwind. First run auto-builds `webui/dist/` if Node is present.

For dev hot-reload:

```bash
cd webui && npm install && npm run dev   # http://127.0.0.1:5173 proxies to :8765
```

Full reference: [docs/webui.md](docs/webui.md) · API: [docs/api.md](docs/api.md) · Live docs: http://127.0.0.1:8765/docs

---

## The Brains — Skills, Agents & Memory

### 140+ Skills — A Brain That Keeps Growing
Each skill is a curated `SKILL.md` under `skills/` — from `conducting-network-penetration-test` and `executing-red-team-engagement-planning` to `exploiting-jwt-algorithm-confusion-attack`, `exploiting-ssti`, `exploiting-nopac-cve-2021-42278-42287`, and `attacking-domains-end-to-end`. The engine deterministically selects the top 6 for your context, re-selects mid-run, and can do semantic matching via embeddings.

Categories include: **network pentest, web/API, auth/JWT/OAuth, deserialization, AD/BloodHound, SMB/network, privesc, crypto, supply chain, detection, persistence, ICS/IoT**, and more. See [docs/skills.md](docs/skills.md) and [docs/skill-authoring.md](docs/skill-authoring.md).

### Swarm — 6 Specialists, One Blackboard

| Agent | Job |
|-------|-----|
| `recon` | Scanning, fingerprinting, attack surface scoring |
| `vuln` | CVE / exploit correlation, module matching |
| `exploit` | Module selection, payload crafting, mutation |
| `post_exploit` | Credential/loot handling, lateral target generation |
| `critic` | Pre-execution scope, risk & policy review |
| `reflection` | Strategy review, lessons learned |

Orchestrated via `tools/swarm/orchestrator.py` with shared blackboard, battle log, parallel dispatch, and phase-aware skill hints. See [docs/swarm.md](docs/swarm.md).

### MCP Tool Arsenal — ~90 Tools Across 27 Families

| Family | Superpower |
|--------|-----------|
| `terminal` | Shell execution with target-IP allowlist lock + OPSEC advisory |
| `workspace` | `write_python_file` / `run_python_file` / `read_workspace_file` — workspace-contained file ops |
| `recon` | `check_os`, `quick_scan`, `run_full_recon`, `get_service_fingerprint` |
| `attack_modules` | `run_attack_module`, `craft_exploit`, `mutate_exploit` + hypothesis/state tools |
| `metasploit` | Full `msfconsole` lifecycle, sessions, payloads, post modules |
| `payloads` | `generate_payload` via msfvenom |
| `web_scan` | nikto/nuclei/sqlmap/gobuster/feroxbuster/whatweb/wpscan |
| `cracking` | hashcat/john with auto hash-type ID |
| `credentials` | Encrypted vault + Impacket lateral / Kerberoast |
| `sessions` | tmux / background jobs / listeners (beacons) |
| `research` | `search_exploit_db`, `search_web_exploit`, `deep_research`, `search_cve_intel` |
| `domain` | DNS, subdomain enum, AXFR, vhost, WHOIS — with auto-authorization |
| `peer_models` | `consult_peer_models` — advisory multi-model consultation |
| `runtime_skills` | `list/search/load` skills at runtime |
| + 13 more | `assessment_state`, `parallel_agents`, `poc_verifier`, `replay_simulator`, `mitre`, `ad`, `operator_connection` … |

All wired through `tools/mcp_tools/registry.py` with `@audit_tool` / `@require_allowlist()` decorators. Auto-discovered via `collect_tools()` — no manual registration. See [docs/mcp-tools.md](docs/mcp-tools.md).

---

## Safety

| Mode | What happens |
|------|--------------|
| **Recon** | Always `read_only` — gathers and proposes, never executes offensively |
| **Attack** | `full_access` — auto-approves everything, no command/scope inspection |
| **The lock** | **Target-IP allowlist** at the MCP tool layer — every destination is extracted and refused if not in the allowlist (supports `IP`, `domain`, `*.wildcard`, `CIDR`). Domain runs auto-authorize discovered subdomains. |

Operational guards that always apply: 300s/600s timeouts, full JSONL audit trail, OS-aware tooling.

This is **not** a sandbox or authorization proof. Only run against what you own.

Full model: [docs/safety-model.md](docs/safety-model.md)

---

## Quick Start — 60 seconds

### Windows — double-click install

```powershell
.\install.bat    # checks Python/Node/Nmap/Ollama, creates .venv, builds WebUI, pulls models, runs --doctor
.\START.bat      # launches the WebUI at http://127.0.0.1:8765
```

Or after install, from any terminal:

```powershell
python main.py   # opens the WebUI in your browser — that is it
```

### Linux / macOS

```bash
./install.sh              # or: ./scripts/setup-linux.sh
python3 main.py           # opens http://127.0.0.1:8765
```

That is the whole app. No CLI flags to memorize — everything happens in the WebUI.

### 1. Set your API key

The default model is Ollama Cloud (`glm-5.2:cloud`). You need one key:

```bash
python main.py --setup-api-keys   # prompts and saves to secr.json (gitignored)
# or set env:  OLLAMA_API_KEY=your_key_here
```

Get a free key at https://ollama.com/settings/keys — then `python main.py --doctor` should be all green.

> Prefer local Ollama or ChatGPT? Switch in the WebUI under **System → Models**, or see [docs/providers.md](docs/providers.md). Embeddings always stay local (`nomic-embed-text`).

---

## Requirements

| Need | Notes |
|------|-------|
| **Python 3.11+** | `python --version` — `--doctor` rejects 3.10 |
| **nmap** | On `PATH` or set `nmap.path` in `config.yaml` |
| **Ollama** | Cloud default (`https://api.ollama.com` + `OLLAMA_API_KEY`) or local daemon |
| **Node.js + npm** | Only for first WebUI build — auto-built on first launch if present |
| **Linux extras** | Metasploit/searchsploit/impacket/hydra only on Linux — Windows = Python-only exploits |

`python main.py --doctor` checks all of this. `python main.py --self-test` runs a safe localhost smoke test.

---

## API Keys

One command handles everything:

```bash
python main.py --setup-api-keys
```

| Variable | Purpose |
|----------|---------|
| `OLLAMA_API_KEY` | **Required** for Ollama Cloud (default) |
| `NVD_API_KEY` | Higher NVD CVE rate limit (optional) |
| `GITHUB_TOKEN` | Higher GitHub search limit for PoC search (optional) |
| `SERPAPI_API_KEY` | Fallback web research (optional) |

Keys live in env or `secr.json` (gitignored). The app does **not** auto-load `.env`.

---

## Configuration

Everything is in **`config.yaml`** — validated against `tools/config_manager.py::CONFIG_SCHEMA`.

For day-to-day use you do not need to touch it — the WebUI **System → Config** editor and **System → Secrets / Models** pages cover it. For the full key reference:

→ **[docs/config-reference.md](docs/config-reference.md)**

Switching providers (Ollama ↔ ChatGPT), models, skills, swarm, OPSEC, persistence, and API settings are all in there. Highlights:

- **Models** — cloud-first (`glm-5.2:cloud` 976K, `deepseek-v4-pro:cloud` 1M, `kimi-k2.6:cloud` 256K, `minimax-m3:cloud` 512K) with per-role routing (planner/executor/critic/etc.)
- **Swarm & Autonomous** — toggle agents, concurrency, persistence phases, adaptive replan
- **OPSEC** — target-aware pacing, UA rotation, DoH, noise budget
- **ICS** — destructive PLC writes dual-gated (`allow_write` + `destructive_ics`)
- **API** — concurrent runs (default 3), multi-operator, graph route, loopback auth

---

## Plugins — Extend Without Forking

Managed in `tools/plugins.py` — a plugin can add attack modules, MCP tools, skills, and config. Enable via `config.yaml` `plugins.enabled`. Reference example at `plugins/example_recon_report/`.

Shipped (enabled in lab build, require their API key to actually run):

| Plugin | What it adds |
|--------|-------------|
| `shodan_recon` | Shodan-powered recon enrichment |
| `github_dorks` | GitHub dork search for leaked creds |
| `webhook_notify` | Slack/Discord findings + state webhooks |
| `sliver_c2` | Sliver C2 integration |
| `bloodhound_ce` | BloodHound CE attack path mapping |
| `zap_scan` | OWASP ZAP active scanning |
| `browser_attack` | Browser-based attack surface |
| `mobile_attack` | Mobile app assessment |
| `wireless` | Wireless recon |
| `spiderfoot` | SpiderFoot OSINT |
| `atomic_red_team` | Atomic Red Team emulation |
| `caldera` | MITRE Caldera adversary emulation |
| `firmware_analysis` | Firmware extraction & analysis |

→ [docs/plugin-development.md](docs/plugin-development.md)

---

## Documentation

| Guide | For |
|-------|-----|
| [Getting Started](docs/getting-started.md) | Setup, first run, dev loop |
| [WebUI](docs/webui.md) | SPA pages, wizard, live view, graph |
| [WebUI API](docs/api.md) | `GET /api/v1` REST + WebSocket |
| [Safety Model](docs/safety-model.md) | Scope, permission, audit, allowlist |
| [Providers](docs/providers.md) | Ollama Cloud/local + ChatGPT (OAuth) |
| [Architecture](docs/architecture.md) | System shape, Flow A/B, persistence |
| [Skills](docs/skills.md) | 140-skill advisory pipeline |
| [Attack Modules](docs/attack-modules.md) | Pre-packaged exploit logic |
| [MCP Tools](docs/mcp-tools.md) | 90+ MCP tool reference |
| [Swarm](docs/swarm.md) | 6-agent blackboard architecture |
| [Plugin Development](docs/plugin-development.md) | Out-of-tree extensions |
| [Config Reference](docs/config-reference.md) | Every `config.yaml` key |
| [Evaluation](docs/evaluation.md) | Metrics & eval harness |

---

## Quality — Tested Like It Matters

- **~251 test files** in `tests/` — all mock subprocess/network, no live Nmap. Scope gates, safety review, recon, swarm, audit chains, credential storage, Metasploit, and more.
- **CI on every push/PR** — Python 3.11–3.13 matrix, coverage, CodeQL, dependency-review.
- **Lint is law** — `ruff check .` (0 errors) + `ruff format --check .` (0 diffs) + `mypy --follow-imports=skip tools` (216 files) — all CI-enforced.
- **WebUI tested** — `tsc -b && vite build` + `vitest` on every PR.

```bash
python -m pytest tests/ -v
ruff check . && ruff format --check .
mypy --follow-imports=skip tools
cd webui && npm ci && npm run build && npm run test
```

See [docs/testing-guide.md](docs/testing-guide.md).

---

## Architecture at a Glance

```
operator ──► main.py / app.py (WebUI @ :8765)
               │
               ├─ open_exploit_mcp_session()  ──► mcp_exploit_server.py (:8001)
               │     stdio or HTTP, 30s boot budget, EXPLOIT_TARGET allowlist lock
               │
               ├─ GoalEngine ──► resolves preset/custom goals, risk-gated (SAFE/GATED/HIGH)
               │
               ├─ run_exploit_session() ──► tools/exploit_agent/ (loop + policy + prompt)
               │     90+ MCP tools, 140+ skills, 15 attack module families
               │
               ├─ SwarmOrchestrator (6 agents, shared blackboard, parallel dispatch)
               │
               └─ AutonomousOrchestrator (persistent campaigns, adaptive aggression, vuln chaining)
```

Two flows: **Flow A** (modern, `main.py` → `tools/exploit_agent` / `tools/mcp_tools` / `tools/swarm`) is what you run. **Flow B** (legacy, frozen in `legacy/`) is the SQLite research loop — still tested, but frozen. See [docs/architecture.md](docs/architecture.md) and [docs/runtime-flows.md](docs/runtime-flows.md).

---

## Contributing

1. Read [AGENTS.md](AGENTS.md) — non-obvious rules you will otherwise break.
2. `python main.py --doctor && python main.py --self-test` after safety changes.
3. Before a PR:
   ```bash
   python -m pip install -e ".[dev]"
   python -m pytest tests/ -v
   ruff check . && ruff format --check .
   mypy --follow-imports=skip tools
   cd webui && npm ci && npm run build && npm run test
   ```
   CI runs the same on Python 3.11–3.13 + CodeQL + dependency-review.
4. Do not edit frozen Flow B safety files (`scope_gate.py`, `safety_reviewer.py`, `legacy/`).
5. New exploit MCP tools: just add `@audit_tool` / `@require_allowlist()` in `tools/mcp_tools/<family>.py` — auto-discovered via `tools/mcp_tools/registry.py`.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

<details>
<summary><strong>Advanced: CLI & headless use</strong> (most users do not need this)</summary>

The CLI still works for scripting and headless runs. The WebUI is the default (`python main.py` opens it); add flags only if you need them.

```bash
python main.py --help                              # full flag list
python main.py --target 10.0.0.50 --mode recon      # recon only
python main.py --target 10.0.0.50 --mode attack --goal backdoor
python main.py --target example.com --mode attack   # domain targeting
python main.py --demon                              # API only, no browser
python main.py --menu                               # legacy terminal menu
```

Legacy SQLite research loop (Flow B, frozen in `legacy/`):

```bash
python -m legacy.cli init-mission --config mission.yaml
python -m legacy.cli next-task
```

See `docs/runtime-flows.md` and `legacy/README.md`.

</details>
