# NetAttackAI

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![WebUI](https://img.shields.io/badge/WebUI-React%20%2B%20Vite-06b6d4?style=flat-square)
![Models](https://img.shields.io/badge/LLM-Ollama%20Cloud-22c55e?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-1.27%2B-f97316?style=flat-square)
![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)

<img width="1725" height="912" alt="web" src="https://github.com/user-attachments/assets/45b6af2f-91e2-4eaf-a4cd-1352dbd42e0c" />

**AI-driven penetration testing, entirely in your browser.**

Plan · Recon · Exploit · Prove · Report — end-to-end against targets you own. An autonomous operator that thinks in kill-chains, not checklists. Powered by Ollama, MCP, and 146 advisory skills. Lab-only, target-locked, fully audited.

[Quick Start](#quick-start--60-seconds) · [WebUI Guide](docs/webui.md) · [Safety Model](#safety) · [Docs](docs/)

</div>

---

> [!WARNING]
> **Authorized use only.** Only test systems you own or have explicit written permission to assess. Run on a throwaway operator box.
> **Attack mode = `full_access`** — every action is auto-approved. The only safety is the **target-IP allowlist lock** (a destination guard, not a sandbox). Recon stays fully scope-gated. See [Safety Model](#safety).

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

## The WebUI

Everything lives at **`http://127.0.0.1:8765`** (loopback-only, bearer-token gated).

| Page | What you do |
|------|-------------|
| **New Run wizard** | Pick target → model → goal → power-ups → confirm and launch |
| **Live Run** | Real-time event stream, tool calls, decisions, telemetry (WS + SSE) |
| **Attack Graph** | Interactive DAG — pan/zoom, filter, find paths, inspect evidence |
| **Artifacts & Audit** | Reports, raw Nmap, findings, tamper-evident SHA256 audit chain |
| **Loot & Credentials** | Captured creds and loot per run |
| **System** | Config editor, secrets, models/providers, skills, plugins, diagnostics |

First run builds `webui/dist/` automatically if Node.js is present. For dev hot-reload:

```bash
cd webui && npm install && npm run dev   # http://127.0.0.1:5173 proxies to :8765
```

Full reference: [docs/webui.md](docs/webui.md) · API: [docs/api.md](docs/api.md) · http://127.0.0.1:8765/docs

---

## What it does

- **Cloud-first, local-capable** — `glm-5.2:cloud` (976K context) by default; point `ollama.host` at `localhost:11434` and the same code runs locally.
- **Multi-model war room** — ask Kimi, DeepSeek, GLM, Minimax for advisory ideas mid-run (no tool access).
- **146-skill brain** — deterministic + semantic skill selection, re-selected mid-run as new services/CVEs appear.
- **Real attack graph** — `AttackPlan` DAG with prerequisites, hypotheses, and a failure taxonomy (retry / create-prereq / switch-capability / stop). Decisions logged to `decision_log.jsonl`.
- **Hypothesis-driven verdicts** — `OutcomeJudge` produces `confirmed` / `refuted` / `exhausted` — execution success is not evidential success.
- **Target-aware OPSEC** — pacing, UA rotation, DoH auto-disable on private/local targets.
- **Domain targeting** — `example.com` → resolves, expands subdomains (crt.sh + DNS + subfinder/amass), auto-authorizes each host.
- **Tamper-evident audit** — every target-touching action → `exploit_workspace/<ip>/exploit_audit.jsonl` with SHA256.
- **Swarm + Autonomous orchestrator** — 6 specialist agents on a shared blackboard, plus persistent multi-phase campaigns.

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

## Configuration

Everything is in **`config.yaml`** — validated against `tools/config_manager.py::CONFIG_SCHEMA`.

For day-to-day use you do not need to touch it — the WebUI **System → Config** editor and **System → Secrets / Models** pages cover it. For the full key reference:

→ **[docs/config-reference.md](docs/config-reference.md)**

Switching providers (Ollama ↔ ChatGPT), models, skills, swarm, OPSEC, and API settings are all in there.

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
| [Skills](docs/skills.md) | 146-skill advisory pipeline |
| [Attack Modules](docs/attack-modules.md) | Pre-packaged exploit logic |
| [Plugin Development](docs/plugin-development.md) | Out-of-tree extensions |

---

## Plugins

Managed in `tools/plugins.py` — a plugin can add attack modules, MCP tools, skills, and config. Enable via `config.yaml` `plugins.enabled`. Reference example at `plugins/example_recon_report/`.

Shipped (enabled in lab build, require their API key to actually run): `shodan_recon`, `github_dorks`, `webhook_notify`, `sliver_c2`, `bloodhound_ce`, `zap_scan`, `browser_attack`, `mobile_attack`, `wireless`, `spiderfoot`, `atomic_red_team`, `caldera`, `firmware_analysis`.

→ [docs/plugin-development.md](docs/plugin-development.md)

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
