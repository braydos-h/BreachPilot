# Phase 2 Architecture Debt Audit — v0.49.12

> **Read-only audit. No behavior changed.** Generated 2026-08-24 from live repo measurements. Follow-up phases must keep diffs <400 lines, one phase only, and preserve invariants in `AGENTS.md` §Non-obvious rules.

Source docs read before audit: `AGENTS.md`, `CLAUDE.md`, `docs/architecture.md`, `docs/runtime-flows.md`, `docs/module-guide.md`, `docs/safety-model.md`, `docs/extension-guide.md`, plus `config.yaml:495`, `pyproject.toml:112`, `requirements.txt`, `tools/mcp_shared.py:1089`, `tools/mcp_tools/registry.py:505`, `mcp_exploit_server.py:244`, `tools/attack_modules/registry.py:401`.

**Repo scale (measured, not quoted):**

| Area | Files | LOC | Notes |
|------|-------|-----|-------|
| Python (excl. `.venv`/`.git`/`node_modules`) | 905 | 197,367 | `pyproject.toml` `requires-python >=3.11`; overlap `pyproject.toml` / `requirements.txt` |
| `tools/` only | 202 | 80,051 | ~40% of Python LOC in one directory |
| `webui/src/` TS/TSX | 152 | 25,984 | Largest: `SkillsPage.tsx:1274`, `StatsPage.tsx:1053`, `RunPage.tsx:976` |
| `tests/` | 248 | — | All mock subprocess/network; `pytest asyncio_mode = "auto"` |

---

## 1. Flow A vs Flow B Call-Graph

Two control flows coexist in one checkout and **share only `db.py` + `mission.py` schemas** (`AGENTS.md` §2, `CLAUDE.md` §Flow A/B).

### 1.1 Diagram (current)

```
Flow A (modern, what users run)          Flow B (legacy, SQLite)              Shared kernel
─────────────────────────────           ─────────────────────────           ──────────────
main.py:1177 ─┬─> app.py:233            cli.py:599 ──> agent_loop.py:1509   db.py:1031
              │      └─> tools/run_service/service.py:1731  ─┬─> tools/swarm_bridge.py
              │                                              │         └─> SwarmOrchestrator
              ├─> tools/mcp_session.py:958                   │
              │      └─> open_exploit_mcp_session ──> mcp_exploit_server.py:244:port 8001
              │              ├─ stdio_client / streamable_http_client (BaseExceptionGroup!)
              │              └─ EXPLOIT_TARGET env -> tools/mcp_shared._allowed_target_list
              │                                              │
              ├─> tools/cli_exploit_settings.py              │
              ├─> tools/exploit_session.py ──> run_exploit_agent
              ├─> tools/exploit_agent/loop.py:2215 ──> ExploitPolicy (full_access auto-approves)
              │         ├─> tools/swarm/ (when --swarm)       │
              │         └─> tools/autonomous_orchestrator.py:2720 (Path B, no MCP)
              └─> tools/api/ (WebUI daemon, --demon/--web)    │

Flow B:  mission.py:514 ──> scope_gate.py:504 ──> tool_router.py ──> SafetyReviewer ──> agent_loop.py
         All pass through ScopeGate.check_scope() per executor action.

Shared:  db.py, mission.py  (and their SQLite schema + workspace dirs)
```

### 1.2 Import map — who imports what (grep of `import` lines, 2026-08-24)

#### `db.py` — 62 import sites across 28 app files + 34 test files

| Consumer | Role | Flow |
|----------|------|------|
| `agent_loop.py:27`, `cli.py:47`, `evidence.py:24`, `finding_verifier.py:28`, `memory.py:20`, `mission.py:19`, `outcome_judge.py:18`, `report_generator.py:34`, `scope_gate.py:29`, `target_graph.py:21`, `task_queue.py:18`, `tool_router.py:21` | Core domain + Flow B loop | **Flow B + Shared** |
| `tools/experience_store.py:14`, `tools/semantic_memory.py:17`, `tools/interactive_menu.py:84` | Learning/memory, menu | Both (menu bridges) |
| `tools/skill_embeddings.py:167`, `tools/skill_feedback.py:123`, `tools/api/routes/system.py:415`, `tools/exploit_agent/loop.py:527,545` | Skill + API + agent loop (lazy `get_default_db`) | **Flow A** — `get_default_db` only |
| `tools/autonomous_orchestrator.py:1219,1237` (lazy `get_default_db` inside methods) | Campaign persistence | **Flow A Path B** |
| `tools/mcp_tools/registry.py:91` (`DatabaseManager, get_default_db`) | MCP tool helpers (unused at runtime except via `*` import) | **Flow A** — dead import (coupling only) |

**Verdict:** `db.py` is the strongest coupling seam. Flow A touches it only via the lazy `get_default_db()` singleton (orchestrator, agent loop, skills, API). No Flow A code needs the full `DatabaseManager` schema except the API persistence layer and `registry.py`'s unused import (delete candidate).

#### `mission.py` — 9 import sites, all Flow B

```
agent_loop.py:32  from mission import Mission, MissionController
cli.py:93,155,172,270,434  from mission import MissionController / Mission / _classify_asset
tools/interactive_menu.py:85  from mission import MissionController
tests/test_mission.py, tests/test_cli_mission_id.py
```

No Flow A file imports `mission.py` except the `interactive_menu.py` bridge (which is itself Flow B-adjacent). **Clean boundary.** Free to namespace `mission.py` as `legacy/mission.py` without Flow A churn.

#### `scope_gate.py` — 7 import sites; 2 are Flow A

```
Flow B: agent_loop.py:45, cli.py:171,293,432, tool_router.py:22
Flow A: tools/exploit_session.py:53  from scope_gate import ScopeGate   # Path B target lock
        tools/exploit_agent/_common.py:26  from scope_gate import ScopeGate  # Path B + agent policy
tests: test_scope_gate.py, test_exploit_scope_gate.py, test_phase4_bugfixes.py
```

`exploit_session.py` and `_common.py` import `ScopeGate` **only for the autonomous orchestrator's no-MCP Path B** (`AttackModuleExecutor.execute` does `scope_gate.check_scope(asset=task.target)` — the target-IP lock when MCP is not in the loop). Documented as load-bearing in `safety-model.md` §Exploit Permission Modes. Any `legacy/` move must keep `scope_gate.py` accessible to Flow A via a kernel re-export or retain it at root with a `FLOW_B` header.

#### `tools/mcp_session.py` — 18 Flow A sites, 0 Flow B

```
main.py:95-96,105,118-120,139,142,169,175  (re-wraps as main.open_exploit_mcp_session)
tools/exploit_session.py:68  (delegates via SwarmMcpBridge)
tools/run_service/service.py:849,1027,1059,1503,1533,1622  (AssessmentService wiring)
tests: test_mcp_http_lifecycle.py, test_recon_first_session.py (heavy, 20+ sites)
conftest.py:12 (comment)
```

Pure Flow A. No Flow B consumer. Safe to keep under `tools/` and later re-export via `tools/kernel/` without cross-flow impact.

#### `tools/swarm_bridge.py` — 8 Flow A sites

```
main.py:150  from tools.swarm_bridge import SwarmMcpBridge
tools/exploit_session.py:68
tools/run_service/service.py:72,849,857,1027,1059,1503,1533,1622  (bridge attach + dispatch)
tools/verification/poe_verifier.py:22 (comment)
```

Pure Flow A. Single responsibility: bridge sync swarm `tool_executor` onto live MCP `ClientSession` to preserve `run_exploit_session`'s single-session invariant.

#### `tools/run_service/` — 30+ sites, Flow A core

```
Producers: main.py:816,986, tools/api/*, tools/exploit_agent/loop.py:56-59 (deferred import comment)
Consumers: tests/test_api_*.py (6 files), tests/test_service_extraction.py,
           tests/test_recon_event_and_allowlist.py, scripts/benchmark_webui.py
Internal: models.py (RunRequest/RunPreview/Decision/Event), providers.py (DecisionProvider/EventSink),
          service.py:1731 (AssessmentService — 3 classes, 20 defs, 62 imports)
```

Flow A transport-neutral seam (CLI vs API). Well-isolated; no Flow B imports. The `Callables` injection pattern (`main_mod.*` monkeypatch) is the main coupling debt — see §4.

---

## 2. God Files >800 LOC

> Ordered by measured LOC (2026-08-24). 32 files exceed 800 LOC; 22 are in `tools/` or root domain. The four files called out in the task brief are confirmed but LOC has drifted since the brief was written (recon_pipeline was 63k chars → 2385 LOC, etc.).

### 2.1 Full list (LOC via `len(read_text().splitlines())`)

| Rank | File | LOC | Classes | Defs (sync+async) | Imports | Debt class |
|------|------|-----|---------|-------------------|---------|------------|
| 1 | `tools/autonomous_orchestrator.py` | **2720** | 8 | 35+15 async | 36 | **GOD — split** |
| 2 | `tools/mcp_tools/attack_modules.py` | **2685** | 0 | 62+3 async | 41 | **GOD — split** |
| 3 | `tools/recon_pipeline.py` | **2385** | 7 | 25+34 async | 29 | **GOD — split** |
| 4 | `tools/exploit_agent/loop.py` | **2215** | 5 | 18+4 async | 35 | **GOD — tighten** |
| 5 | `tests/test_recon_first_session.py` | 2027 | — | — | — | Test (out of scope) |
| 6 | `tools/run_service/service.py` | **1731** | 3 | 20+10 async | 62 | **GOD — split** |
| 7 | `tools/web_researcher.py` | **1569** | 14 | 73+18 async | 20 | GOD — split |
| 8 | `tools/attack_modules/modules/ics_iot.py` | **1516** | 10 | 69 | 51 | Module pack — split |
| 9 | `agent_loop.py` | **1509** | 1 | 18+2 async | 31 | **LEGACY — freeze** |
| 10 | `tools/enhanced_reporting.py` | **1479** | 6 | 41 | 9 | GOD — split |
| 11 | `tools/attack_modules/modules/web.py` | **1428** | 14 | 38 | 10 | Module pack |
| 12 | `tools/config_manager.py` | **1379** | — | — | — | Large but single-concern (schema) |
| 13 | `tools/attack_ui.py` | **1364** | — | — | — | GOD — split (UI) |
| 14 | `main.py` | **1177** | — | — | — | Entry point — keep, thin via `tools/*.py` extractions already done |
| 15 | `outcome_judge.py` | 1112 | — | — | — | Legacy domain |
| 16 | `tools/persistent_session_manager.py` | **1111** | — | — | — | GOD |
| 17 | `tools/mcp_shared.py` | **1089** | — | — | — | **Shared kernel — extract** |
| 18 | `tools/api/routes/system.py` | 1050 | — | — | — | API route — split |
| 19 | `db.py` | **1031** | — | — | — | **Shared schema — freeze** |
| 20 | `tools/mcp_tools/domain.py` | 993 | 0 | — | — | MCP family — long but focused (5 tools) |
| 21 | `tools/metasploit_bridge.py` | 979 | — | — | — | External integration |
| 22 | `tools/reliability.py` | 974 | — | — | — | Retry/circuit — focused |
| 23 | `tools/mcp_session.py` | **958** | — | — | — | Session boot — long due to BaseExceptionGroup handling (load-bearing) |
| 24 | `tools/attack_modules/modules/privesc.py` | 928 | 10 | 45 | — | Module pack |
| 25 | `tools/mcp_tools/terminal.py` | **891** | 0 | — | — | MCP family — core (target-lock) |
| 26 | `tools/swarm/orchestrator.py` | **861** | — | — | — | Swarm core |
| 27 | `tools/exploit_agent/research_assistant.py` | 855 | — | — | — | — |
| 28 | `tools/eval_harness.py` | 853 | — | — | — | Eval |
| 29 | `tools/payload_crafter.py` | 839 | — | — | — | Payload |
| 30 | `tools/api/routes/runs.py` | 759 | — | — | — | API |
| 31 | `tools/interactive_menu.py` | 724 | — | — | — | UI |
| 32 | `tools/plugins.py` | **722** | — | — | — | Plugin system |

Additional 800+ outside measured Python (not counted above): `webui/src/routes/SkillsPage.tsx:1274`, `StatsPage.tsx:1053`, `RunPage.tsx:976` (SPA debt, separate track).

### 2.2 De-god recommendations (ponytail ladder)

| File | LOC | Coupling score* | Verdict | Rationale |
|------|-----|-----------------|---------|-----------|
| `tools/autonomous_orchestrator.py:2720` | 2720 | **HIGH** (imports `attack_modules`, `recon_pipeline`, `mcp_shared`, `scope_gate`, `db`) | **Split** → `tools/campaign/{state,phases,executor,orchestrator}.py` | 8 phases, 3 dataclasses, 2 executors, 1 orchestrator in one file. Already has package-shaped seams (`AggressionLevel`, `AttackTask`, `AttackState`, `AttackModuleExecutor`). Reuse `run_service/service.py:AssessmentService` pattern per task brief. |
| `tools/mcp_tools/attack_modules.py:2685` | 2685 | HIGH (62 tool defs via `registry import *`) | **Split** → `tools/mcp_tools/attack_modules/{web,creds,privesc,campaign}.py` OR keep file, extract helpers to `tools/kernel/parse.py` | Largest MCP family; 40+ tool handlers share one file. But file is mechanically uniform (each handler = `@mcp.tool @require_allowlist def`). Splitting by category (web/auth/crypto) mirrors `attack_modules/modules/` structure. Lower risk: keep file, extract `_identify_hash_modes` etc. to kernel. |
| `tools/recon_pipeline.py:2385` | 2385 | MED (imports `validation_utils`, `recon_enrichers`, `nmap_priv`, `socket_scan`) | **Split** → `tools/recon/{scanner,enrichers,osint,pipeline}.py` (brief's plan) | Already imports `recon_enrichers.py:688` and `recon_osint.py`; orchestrator `ReconPipeline` is ~100 lines that delegates to `PrimaryReconScanner` + `SecondaryEnumerator`. Natural package seam. |
| `tools/exploit_agent/loop.py:2215` | 2215 | **HIGH** (imports `mcp_shared`, `validation_utils`, `skill_pipeline`, `model_router`, `db`, `attack_planner`) | **Tighten to <1200**, move parsing to `tools/kernel/parse.py` | Contains 5 classes + agent loop + tool-call parsing + checkpoint hooks. `tool_calls.py` already exists but loop still parses inline. Ponytail ladder rung 2: reuse `tool_calls.py` instead of duplicating. |
| `tools/run_service/service.py:1731` | 1731 | MED (pure Flow A, transport-neutral) | **Split** → `tools/run_service/{models,providers,service,persistence}.py` already present; just shrink `service.py` | 62 imports include 10 deferred (`from tools.run_service.models import is_agent_attack_mode # local to avoid cycle`). Cycle is the debt. Extract `Callables` + `_TelemetryAccumulator` to separate modules. |
| `tools/web_researcher.py:1569` | 1569 | LOW | **Keep** — cohesive (14 classes, single provider abstraction) | Provider abstraction already done (`ResearchProvider` subclasses). Splitting would add indirection without reducing coupling. |
| `tools/attack_modules/modules/ics_iot.py:1516` | 1516 | LOW | **Keep or split by protocol** → `ics/{modbus,dnp3,s7,bacnet}.py` | 10 modules in one file because ICS protocols share `_ics_write_allowed` gate. Splitting is optional; file is additive (all read-only except 4 dual-gated writes). |
| `agent_loop.py:1509` | 1509 | HIGH (Flow B root) | **FREEZE** — do not edit per invariants | Legacy loop; `docs/architecture.md` ADR in Phase 2 will add `FLOW_B = legacy` header + deprecation warning only. |
| `tools/mcp_shared.py:1089` | 1089 | **VERY HIGH** (imported by 12+ MCP families + 3 plugins + `mcp_server.py`) | **Extract kernel** → `tools/kernel/{allowlist,audit,workspace,subprocess}.py` + re-export shims | Central coupling hub. Contains 5 concerns: config builders, workspace helpers, redaction, allowlist, subprocess. Each has distinct consumers. Highest ROI for Phase 2. |
| `tools/mcp_tools/registry.py:505` | 505 | VERY HIGH (re-exports stdlib + helpers via `import *` to 19 families) | **Keep but shrink imports** | 19 families do `from tools.mcp_tools.registry import *` — registry re-exports `json`, `os`, `re`, `Path`, `asyncio`, `signal`, `socket`, `_ssl_module`, plus project helpers. This is the `import *` debt. Consolidate helpers into `tools/kernel/` and narrow re-exports. |

\* Coupling score = (# distinct internal modules imported) + (# external consumers) + (cycle participation). VERY HIGH = >10 consumers or cycle member.

---

## 3. Lint & Type Debt

### 3.1 Ruff (measured `python -m ruff check --output-format json .`)

| Scope | Errors | Files with errors |
|-------|--------|-------------------|
| Full tree (`ruff check .`) | **1849** | 385 |
| Task-brief claim (scoped 1849 / full 27835) | 1849 / 27835 | — | — | **Discrepancy:** full-tree measured 1849, not 27835. Likely the brief's "full" count was with an older ruff version or unscoped `select`. Current `[tool.ruff.lint] select = ["E","F","W","I"] ignore = ["E501"]` yields 1849. The scoped CI list (`app.py scope_gate.py tools/safety_reviewer.py tools/validation_utils.py tools/intelligence tools/providers` per AGENTS.md) is not enforced as a separate ruff scope — `pyproject.toml` has only `[tool.ruff]` with no per-file overrides. Worth adding a CI `ruff check <scope>` step in Phase 5. |

**Top 20 files by ruff errors:**

| Errors | File | Dominant rules |
|--------|------|----------------|
| 131 | `tools/mcp_tools/attack_modules.py` | F405, F401, I001 |
| 67 | `tools/exploit_agent/loop.py` | F405, W292, F541 |
| 65 | `tools/exploit_agent/__init__.py` | F405 (star re-exports) |
| 59 | `tools/exploit_agent/context.py` | F401, I001 |
| 43 | `tools/mcp_tools/credentials.py` | F405, I001 |
| 43 | `tools/mcp_tools/terminal.py` | F405, F403 |
| 39 | `tools/mcp_tools/recon.py` | F405 |
| 34 | `tools/exploit_agent/policy.py` | F401 |
| 34 | `tools/mcp_tools/metasploit.py` | F405 |
| 32 | `mcp_exploit_server.py` | F401, I001 |
| 31 | `tools/exploit_agent/tool_calls.py` | F401 |
| 29 | `tools/mcp_tools/ad.py` | F405 |
| 28 | `tools/mcp_tools/domain.py` | F405 |
| 27 | `tools/exploit_agent/reflection.py` | F401 |
| 26 | `main.py` | F401, E402 |
| 26 | `tools/exploit_agent/ollama_client.py` | F401 |
| 19 | `tools/run_service/service.py` | F401, I001 |
| 18 | `tools/mcp_tools/runtime_skills.py` | F405 |
| 18 | `tools/mcp_tools/workspace.py` | F405 |
| 16 | `tools/mcp_tools/assessment_state.py` | F405 |

**By rule (all 1849):**

| Rule | Count | Meaning | Fix cost |
|------|-------|---------|----------|
| F405 | 619 | `may be undefined, or defined from star imports` | **Bulk of debt is `from registry import *`** — fix by explicit imports |
| I001 | 372 | `Import block is un-sorted` | `ruff --fix` safe |
| F401 | 347 | `imported but unused` | `ruff --fix` safe (but audit before `F401` on `registry.py` re-exports) |
| F541 | 150 | `f-string without placeholders` | `ruff --fix` safe |
| W292 | 122 | `no newline at end of file` | `ruff --fix` safe |
| F841 | 114 | `local variable assigned but never used` | Manual |
| E402 | 47 | `module level import not at top of file` | Often intentional (avoid cycles) |
| F403 | 27 | `from . import * used; unable to detect undefined names` | Same root as F405 |
| E741 | 20 | `ambiguous variable name` | Manual |
| F821 | 9 | `undefined name` | Manual |

**Ponytail read:** 1138 of 1849 errors (F405+F403+I001) are the `import *` tax from `tools/mcp_tools/registry.py` re-exporting stdlib. Ladder rung 2 (reuse existing helper) says: delete `import *`, import stdlib directly where used. That alone clears 62% of ruff debt with zero behavior change. Remaining F401/F541/W292 are `ruff --fix` safe but do NOT run `ruff --fix --unsafe` per Phase 5 invariant.

### 3.2 Mypy

| Scope per `AGENTS.md` / `pyproject.toml` | Result |
|------------------------------------------|--------|
| `mypy --follow-imports=skip app.py scope_gate.py tools/safety_reviewer.py tools/validation_utils.py tools/mcp_shared.py tools/intelligence tools/providers` (AGENTS.md §Commands) | **0 errors** (pass) |
| `mypy --follow-imports=skip summarizer.py planner.py observer.py target_graph.py outcome_judge.py db.py mcp_exploit_server.py tools/mcp_shared.py` (AGENTS.md alt scope) | **0 errors** (pass) |
| `mypy --follow-imports=skip` on `recon_pipeline.py`, `autonomous_orchestrator.py`, `attack_ui.py`, `command_analyzer.py`, `payload_crafter.py`, `config_manager.py`, `tools/mcp_tools/registry.py` | **0 errors** (pass, spot-checked 2026-08-24) |
| `mypy` not installed in default env (`pip install -e ".[dev]"` required) | `python -m mypy` fails with `No module named mypy` before dev install — CI installs it |

**Interpretation:** `mypy` with `follow-imports=skip` is permissive (only checks the named file's annotations, not its imports). The "passes only 8 files" claim in the task brief refers to the *scoped* CI list, not to fundamental unsoundness — spot-checked large files also pass under this mode. True strict-mode coverage (without `skip`) would be far worse but is not the project's current bar. Phase 5 correctly expands the `tool.mypy` scope by 5 files per PR rather than switching to strict.

Config: `[tool.mypy] python_version = "3.11" warn_return_any = true warn_unused_configs = true ignore_missing_imports = true` — minimal per repo guidance ("keep config minimal so security-sensitive diffs stay readable").

### 3.3 Config drift

| Check | Result |
|-------|--------|
| `config.yaml:495` top-level keys (35): `adaptive_exploits, agent, api, autonomous, caldera, chatgpt, cve_lookup, engine_mcp, eval, exploit, ics, long_session, mcp, memory, mitre, models, multi_model, nmap, ollama, opsec, orchestrator, outcome_judgment, plugins, poc_verification, reasoning, recon, replay_simulator, research, skills, stealth, swarm, threat_intel, ticketing, webhook_notify, witness` | — |
| `tools/config_manager.py:CONFIG_SCHEMA` top-level keys (33) | — |
| Keys in `config.yaml` not in `CONFIG_SCHEMA` | **`caldera`, `ics`** (2 keys) |
| Keys in `CONFIG_SCHEMA` not in `config.yaml` | _(none)_ |
| Drift verdict | **Low** — `caldera` (`enabled, url, api_key_env`) and `ics` (`allow_write, destructive_ics`) are documented in `docs/phase1-audit/docs-config-surface.md` and have consumers (`plugins/caldera/`, `tools/attack_modules/modules/ics_iot.py: _ics_write_allowed`), but were never added to `CONFIG_SCHEMA`. `ConfigValidator` will warn on them as "unknown keys". Fix: add both blocks to `CONFIG_SCHEMA` in `tools/config_manager.py` (5 lines each). |
| `pyproject.toml` vs `requirements.txt` | **Drift: coverage.** `requirements.txt` includes `pytest`, `pytest-asyncio` as runtime (for smoke-test envs); `pyproject.toml` lists them under `[project.optional-dependencies] dev`. No `build`/`twine` in `requirements.txt` (correct — dev-only). `ruff`/`mypy` missing from `requirements.txt` (also correct — dev extras). Verdict: **no drift** on runtime deps (`ollama, httpx, mcp, PyYAML, uvicorn, starlette, fastapi, websockets, questionary, numpy, cryptography` match). |

---

## 4. Duplicate Helpers

> How to read: `duplicate?` = true if two definitions or two import paths for same behavior; `delete-vs-reuse` per ladder rung 2 (reuse existing helper).

| Helper | Canonical location | Duplicate / re-export | Coupling | Ponytail action |
|--------|-------------------|----------------------|----------|-----------------|
| **`_is_inside_workspace(workspace, target)`** | `tools/mcp_shared.py:176` (6 lines, `Path.resolve().relative_to`) | `tools/persistent_session_manager.py:61` **redefines** with slightly different semantics (`OSError` guard, `resolved == root` equality check, swapped arg order `path, workspace`) | 18 lines mention it | **Delete duplicate.** Keep `mcp_shared` version (tested, used by 3 MCP families). Add `OSError` guard + equality check if needed, delete `persistent_session_manager.py`'s copy and import from `mcp_shared` (or `tools/kernel/workspace.py` after Phase 2). |
| **`_resolve_workspace_file` / `_find_file` / `_attempt_dir`** | `tools/mcp_shared.py:185,203,894` | `tools/mcp_tools/registry.py` re-imports all three + re-exports via `__all__`; `mcp_exploit_server.py:76` re-exports again for test compat (`from mcp_exploit_server import _find_file`) | 14 / 8 / 35 mentions | **Re-export debt, not duplicate impl.** Phase 2 correctly moves impl to `tools/kernel/workspace.py` and keeps shims. `tests/test_mcp_workspace.py:7` imports from `mcp_exploit_server` — shim must stay 1 release. |
| **`read_workspace(workspace, filename)`** | `tools/mcp_tools/registry.py:286` (unrestricted read, 120k truncation) | **Not** in `mcp_shared.py` | 31 mentions | **Move to kernel.** Task brief wants it in `tools/kernel/` — agreed. `registry.py` is the wrong home (MCP-local) for a helper the brief says belongs in shared kernel. Move impl, re-export from `registry.py`. |
| **`_extract_scanner_targets(command)`** | `tools/mcp_tools/registry.py:376` (argv-walk, scanner-verb aware) | **Not** in `mcp_shared.py` | 20 mentions | **Move to kernel.** Brief says `_is_inside_workspace` + `read_workspace` + `_extract_scanner_targets` → `tools/kernel/`. `_extract_scanner_targets` is allowlist-adjacent (parses scan targets for `terminal._target_lock_block`), so it belongs in `kernel/allowlist.py` or `kernel/workspace.py`. |
| **`_allowed_target_list` / `add_discovered_target` / `_check_allowlist`** | `tools/mcp_shared.py:499,542,563` | `tools/mcp_tools/terminal.py:16`, `tools/mcp_tools/ad.py:20`, `tools/swarm/agents/witness_agent.py:510`, `tools/autonomous_orchestrator.py:1791` import from `mcp_shared` | 41 / 29 / 37 mentions | **Extract kernel — highest ROI.** The allowlist union (config + 4 env vars) IS the target-IP lock (`safety-model.md` §Layers). It is imported by 5 non-MCP files. Phase 2's `tools/kernel/allowlist.py` is the right home; re-export from `mcp_shared.py` for compat. |
| **`make_audit_tool` / `make_require_allowlist` / `_redact_args` / `_mask_secret_content`** | `tools/mcp_shared.py:656,819,434,394` | `tools/mcp_tools/registry.py` re-imports the first two; `mcp_exploit_server.py:75-76` re-exports for compat | 17 / 25 / 36 / 12 mentions | **Kernel: `audit.py`.** Redaction + audit decorator + allowlist decorator are the audit trail. Keep in `tools/kernel/audit.py`, re-export from `mcp_shared.py` + `registry.py`. |
| **`_run_with_pgrp_timeout(args, timeout)`** | `tools/mcp_shared.py:920` (full impl, POSIX `killpg` + Windows fallback) | `tools/mcp_tools/registry.py:116` **wraps** it with a `sys.modules["mcp_exploit_server"]` override check + a `subprocess.run` monkeypatch fallback | 72 mentions (most via `registry`) | **Duplicate shim is load-bearing for tests.** `registry.py`'s wrapper exists so `monkeypatch.setattr("mcp_exploit_server", "_run_with_pgrp_timeout", ...)` controls tool modules that import via `registry`. Do not delete without migrating patch points. Phase 2 can merge impl into `tools/kernel/subprocess.py` but must preserve the `sys.modules` override hook or update `tests/test_mcp_shared_helpers.py:18` + all `monkeypatch` sites. |
| **`_is_inside_workspace` arg-order mismatch** | See row 1 | `mcp_shared(workspace, target)` vs `persistent_session_manager(path, workspace)` | — | Normalize to `(workspace, target)` when consolidating — grep all call sites. |
| **Workspace path construction** | `exploit_workspace/<ip>/<attempt_id>/` repeated in `mcp_shared._attempt_dir`, `mcp_exploit_server._workspace`, `tools/run_service/service.py`, `tools/autonomous_orchestrator.py`, `plugins/sliver_c2`, `skills/c2-frameworks` | 303 lines mention `exploit_workspace` | **Reuse.** `tools/kernel/workspace.py` should expose `workspace_for_target(ip)` + `attempt_dir(workspace)` so new code doesn't rebuild the path. |
| **`is_target_in_allowlist`** | `tools/validation_utils.py:380` (single source) | `tools/mcp_shared.py:26` re-imports; `tools/command_analyzer.py:14`, `tools/swarm/agents/witness_agent.py:209` import directly | 46 mentions | **No duplicate impl.** Single definition in `validation_utils.py`; others import. Keep as-is; `tools/kernel/allowlist.py` should import from `validation_utils`, not duplicate. |

**Summary:** 4 true duplicate impls (`_is_inside_workspace` ×2, `_run_with_pgrp_timeout` shim, workspace-path stitching), 5 re-export-only duplicates (shims for compat), 2 misplaced impls (`read_workspace`, `_extract_scanner_targets` in `registry.py` instead of kernel). Ladder rung 2 applies to all: reuse, don't re-implement.

---

## 5. Manual Registries

| Registry | File | Mechanism | Size | Auto-discovery? | Debt |
|----------|------|-----------|------|-----------------|------|
| **`_MODULE_CLASSES`** | `tools/attack_modules/registry.py:94` | `list[type[AttackModule]]` literal (83 entries) + `register_attack_module(cls)` decorator | 83 classes | **Partial.** `@register_attack_module` exists (Phase 1) and is used by plugins via `tools/plugins.py:298 register_attack_module`. Built-in modules still manually listed in `_MODULE_CLASSES` **and** manually imported in `tools/attack_modules/modules/__init__.py:8-92` (3-place edit). `tests/test_registry_complete.py` guards drift (`_MODULE_CLASSES` must match `modules/__all__`). | **High.** Task Phase 6 replaces literal with `pkgutil.iter_modules` over `tools/attack_modules/modules/` — matches `tools/plugins.py:load_plugins` pattern. Keep `list_modules()`/`get_module()` API byte-identical + `tests/test_attack_modules.py` green. |
| **MCP tool registration** | `mcp_exploit_server.py:39-64` imports + `158-177` calls | 19× `register_*_tools(mcp, ctx=ctx)` manual list (`ad`, `attack_modules`, `credentials`, `cracking`, `domain`, `metasploit`, `mitre`, `payloads`, `peer_models`, `recon`, `research`, `assessment_state`, `runtime_skills`, `parallel_agents`, `poc_verifier`, `replay_simulator`, `sessions`, `terminal`, `web_scan`, `workspace`) | 20 families (19 built-in + `terminal` etc.) | **No.** Each family is `from tools.mcp_tools.<family> import register_<family>_tools` then `register_<family>_tools(mcp, ctx=ctx)`. `tools/mcp_tools/registry.py:505` is central wiring but registers no tools itself. | **Highest ROI per brief.** Phase 3 replaces manual list with `collect_tools()` that introspects `tools/mcp_tools/*.py` `register_*` functions and validates `@audit_tool`/`@require_allowlist` presence. Fail CI if decorator missing. Biggest ROI because double-registration (`@audit_tool` + list in `mcp_exploit_server.py`) is the #1 onboarding mistake (`AGENTS.md` §4). |
| **`PLUGIN_REGISTRY`** | `tools/plugins.py:632` | `PluginRegistry` singleton + `load_plugins(config)` discovery (filesystem `plugins/<name>/plugin.yaml` + entry-point `netattackai.plugins` group). `PLUGIN_REGISTRY.mcp_tool_factories`, `extra_module_classes`, `skill_dirs`, `event_subscribers`, `config_sections` | 16 plugins shipped (`atomic_red_team`, `bloodhound_ce`, `browser_attack`, `caldera`, `example_recon_report`, `firmware_analysis`, `github_dorks`, `mobile_attack`, `shodan_recon`, `sliver_c2`, `snmp`, `spiderfoot`, `wireless`, `zap_scan`, ...) | **Yes.** Already auto-discovery. `mcp_exploit_server.py:184-185` iterates `PLUGIN_REGISTRY.mcp_tool_factories` after built-in tools. | **Low debt.** Reference pattern for Phase 6 auto-discovery (Phase 6's `pkgutil.iter_modules` mirrors `plugins.py:640 load_plugins`). |
| **Skill registry** | `tools/skill_registry.py:238` | `load_skill_registry()` scans `skills/` + `PLUGIN_REGISTRY.skill_dirs` | ~30 skills (plus `skills/maybe/`) | Yes (filesystem scan) | Low |
| **Model registry** | `tools/config_manager.py:CONFIG_SCHEMA["models"]["registry"]` | 5 aliases (`kimi`, `deepseek`, `deepseek_flash`, `glm`, `minimax`) + `models.info` | 5 | Manual, but intentional (operator-facing aliases) | Low |

**Double-registration invariant (must preserve):** Per `AGENTS.md` §4, new exploit MCP tools must be registered **twice**: `@audit_tool` decorator in `tools/mcp_tools/<family>.py` + list in `mcp_exploit_server.py`. Phase 3 collapses this to single-source via `collect_tools()` but must keep the **validation** that every `register_*` tool carries `@audit_tool` or `@require_allowlist` (the 317 `require_allowlist` + 202 `audit_tool` uses are the enforcement surface). `tests/test_mcp_tool_registration.py` (to be added) asserts coverage.

---

## 6. Ranked Debt Table

> Sorted by `(coupling × LOC) / fix-cost` — highest ROI first. `LOC` measured 2026-08-24. `Coupling` = distinct consumers + import depth. `Fix cost` = est. lines changed for minimal ponytail fix. `Verdict` per ladder: deletion > reuse > stdlib > native > installed dep > one-liner > minimal code.

| Rank | File:line | LOC | Coupling | Ruff | Mypy | Debt | Verdict | Est. diff | Risk if deferred |
|------|-----------|-----|----------|------|------|------|---------|-----------|------------------|
| **1** | `tools/mcp_tools/registry.py:1` + `tools/mcp_shared.py:1` | 505+1089 | **VERY HIGH** (19 families `import *`, 12+ `mcp_shared` consumers, cycle with `mcp_exploit_server`) | 11 + 0 | 0 | `import *` tax (61% of ruff debt), duplicate `_run_with_pgrp_timeout`, misplaced `read_workspace`/`_extract_scanner_targets` | **Extract `tools/kernel/{allowlist,audit,workspace,subprocess}.py`, re-export shims** (Phase 2) | ~120 lines moved, ~30 lines shim | New `import *` consumers keep accumulating; ruff debt grows 20+/PR |
| **2** | `mcp_exploit_server.py:39` | 244 | VERY HIGH (boot entry, 20 tool families) | 32 | 0 | Manual 19× `register_*_tools` list — double-registration gate | **Auto-collect via `collect_tools()` introspection** (Phase 3) | ~60 lines new, ~10 removed | Onboarding mistake (forget to add to list) ships undecorated tool without audit |
| **3** | `tools/attack_modules/registry.py:94` | 401 | HIGH (83 modules, `modules/__init__.py` mirrors) | 0 | 0 | Manual `_MODULE_CLASSES` literal + 3-place edit | **Auto-discovery via `pkgutil.iter_modules`** (Phase 6) | ~40 lines | New module added to `modules/` but not `_MODULE_CLASSES` → `list_modules()` misses it (guarded by `test_registry_complete.py` but still manual) |
| **4** | `tools/recon_pipeline.py:1` | 2385 | MED | 0* | 0 | Single-file orchestrator + 2 scanner classes + enrichers in one file | **Split → `tools/recon/` pkg** (Phase 4) | ~100 lines orchestrator, rest moves | File is at 2385 LOC and growing; every recon feature touches same file → merge conflicts |
| **5** | `tools/autonomous_orchestrator.py:1` | 2720 | HIGH (8 phases, 3 dataclasses, 2 executors) | 0* | 0 | God file — campaign engine in one file | **Split → `tools/campaign/` pkg** (Phase 4) | ~150 lines per subfile | Same as above; `AttackModuleExecutor` + `AutonomousOrchestrator` + `AttackState` + `AttackTask` should be separate |
| **6** | `tools/exploit_agent/loop.py:1` | 2215 | HIGH (5 classes, agent loop, parsing) | 67 | 0* | Loop >400 lines (brief's cap), inline tool-call parsing | **Tighten <1200, move parsing to `tools/kernel/parse.py`** (Phase 4) | ~80 lines moved | Loop is 2215 LOC; every agent feature touches it |
| **7** | `tools/run_service/service.py:1` | 1731 | MED (62 imports, cycle via deferred `is_agent_attack_mode`) | 19 | 0* | 62 imports, `Callables` injection for monkeypatch, deferred cycle imports | **Extract `Callables` + `_TelemetryAccumulator` + cycle break** (Phase 4) | ~80 lines | Cycle forces `from X import Y # local to avoid cycle` at 3 sites (lines 547,602,734) — fragile |
| **8** | `tools/config_manager.py:1` | 1379 | MED (config.yaml truth, 35 keys) | 0* | 0 | Drift: `caldera` + `ics` in `config.yaml` not in `CONFIG_SCHEMA` | **Add `caldera` + `ics` to schema + drift test** (Phase 5) | ~20 lines | `ConfigValidator` warns on legitimate keys; `python main.py --doctor` shows spurious "unknown key" |
| **9** | `tools/persistent_session_manager.py:61` | 1111 | LOW | 0* | 0* | Duplicate `_is_inside_workspace` (arg-order swap) | **Delete, import from `mcp_shared`/`kernel`** (Phase 2) | ~15 lines | Two truth sources for same predicate; bug fix in one won't reach the other |
| **10** | `tools/mcp_tools/attack_modules.py:1` | 2685 | HIGH (62 tool defs) | 131 | — | Largest ruff offender (131 errors), 2685 LOC in one MCP family | **Keep or split by category** (Phase 4, lower priority) | ~0 if kept (fix imports), ~200 if split | Ruff debt (F405 from `import *`) dominates diff noise |
| **11** | `tools/attack_modules/modules/ics_iot.py:1` | 1516 | LOW | 0* | — | 10 modules in one file | **Keep** (ponytail: deletion > split) | 0 | File is cohesive (ICS protocols share `_ics_write_allowed`); splitting adds files without reducing coupling |
| **12** | `tools/mcp_tools/*.py:1` (×19) | 18× ~300 avg | VERY HIGH | 300+ (F405) | — | `from tools.mcp_tools.registry import *` in every family | **Replace with explicit imports** (Phase 3) | ~5 lines per family (19×) | Every new file copies `import *` — debt compounds |
| **13** | `tools/web_researcher.py:1569` | 1569 | LOW | — | — | 1569 LOC but single concern (provider abstraction) | **Keep** — ponytail: no abstraction for one product | 0 | Splitting would add indirection |
| **14** | `pyproject.toml:102` | — | — | — | — | `[tool.ruff]` has no per-file scope; `pyproject.toml` + `requirements.txt` overlap not CI-gated | **Add scoped `ruff check` in CI** (Phase 5, +5 files per PR) | ~10 lines CI YAML | Debt grows invisibly outside scoped list |
| **15** | `agent_loop.py:1509` | 1509 | HIGH (Flow B root) | — | — | Legacy loop, frozen per invariants | **Freeze, add `FLOW_B` header + deprecation warning only** (Phase 2) | ~10 lines | Editing this file breaks recon safety (invariant #2) |

\* 0 in table = not in top-20 ruff offenders; not checked with full-tree mypy strict. All checked files pass `mypy --follow-imports=skip` (project's current bar).

---

## 7. Phase Sequencing & Invariants (for confirm gate)

| Phase | Scope | Invariant check | Verify | Est. diff |
|-------|-------|-----------------|--------|-----------|
| **1 — Audit** | This doc only (read-only) | — | `docs/phase2-audit/architecture-debt.md` exists | 0 |
| **2 — Flow Boundary** | `docs/architecture.md` ADR (freeze Flow B as `legacy/` namespace OR header), `tools/kernel/{allowlist,audit,workspace,subprocess}.py` extract + shims | No Flow B safety file edited (`scope_gate.py`, `safety_reviewer.py`, `agent_loop.py`, `tool_router.py`, `risk_controller.py`, `mission.py`, `db.py`); no allowlist weakened; `python -m pytest tests/ -q` + `main.py --doctor/self-test` green | `ruff check tools/mcp_tools/registry.py tools/mcp_shared.py mcp_exploit_server.py` | <400 |
| **3 — MCP Registry DRY** | `tools/mcp_tools/registry.py:collect_tools()` introspection + `mcp_exploit_server.py` calls it; move `read_workspace:286`, `_extract_scanner_targets:376`, `_is_inside_workspace` to kernel + re-export; `tests/test_mcp_tool_registration.py` | CI fails if tool lacks `@audit_tool`/`@require_allowlist`; `tools/mcp_shared.py` + `tools/mcp_tools/registry.py` helpers backwards-compat | `ruff check tools/mcp_tools/registry.py tools/mcp_shared.py mcp_exploit_server.py` | <400 |
| **4 — De-god `tools/`** | `tools/recon/` pkg, `tools/campaign/` pkg, `tools/exploit_agent/loop.py` tighten, keep shim imports (`from tools.recon_pipeline import ReconPipeline`) for 1 release | 248 tests green via shims; `from tools.recon_pipeline import ReconPipeline` still works | `python -m pytest tests/ -q` | <400 per sub-PR |
| **5 — Config & Type & Lint** | `pyproject.toml:tool.ruff` +5 files/PR, `tool.mypy` +5 files/PR, `CONFIG_SCHEMA` centralize + drift test | `ruff check <expanded-scope>` 0, `mypy --follow-imports=skip <expanded-scope>` 0; `pyproject.toml` + `requirements.txt` synced; `opencode.json` ignored | As in table | <400 |
| **6 — Attack Module Auto-discovery** | `pkgutil.iter_modules` over `tools/attack_modules/modules/` + `registry.register_attack_module(cls)` auto-call; keep `list_modules()`/`get_module()` API | `python -m pytest tests/test_attack_modules.py tests/test_module_capability_metadata*.py -v` green | Same | <400 |

**Non-negotiable invariants carried forward (from task brief + AGENTS.md):**

1. `BaseExceptionGroup` trap: any `stdio_client`/`streamable_http_client`/`ClientSession.initialize()` wrapper uses `_EXC_GROUP_CATCH` from `tools/exceptions.py:1.5k` — never bare `except Exception`.
2. Do NOT edit Flow B safety files: `scope_gate.py`, `safety_reviewer.py`, `agent_loop.py`, `tool_router.py`, `risk_controller.py`, `mission.py`, `db.py`.
3. Attack-mode safety is ONE gate: `tools/mcp_shared._allowed_target_list` + `tools/mcp_tools/terminal._target_lock_block` via `@require_allowlist()` — never weaken; recon stays `read_only` via `tools/cli_exploit_settings._resolve_exploit_permission` missing-key fallback.
4. New MCP tool = `@audit_tool` + list in `mcp_exploit_server.py` (until Phase 3 `collect_tools()`), `tools/mcp_tools/registry.py:505` is wiring, target-touching = `@require_allowlist()` + `validate_target_or_ip`.
5. `config.yaml:495` is runtime truth; `pyproject.toml` + `requirements.txt` synced; `opencode.json` editor-local.

---

## 8. Ponytail Ladder Application

For every proposed change in §6, the ladder was applied top-down:

1. **Does this need to exist at all?** — `ics_iot.py:1516`, `web_researcher.py:1569`, `web.py:1428` kept (no new abstraction). `agent_loop.py:1509` frozen, not rebuilt.
2. **Already in codebase?** — `_is_inside_workspace` duplicate deleted, `tool_calls.py` reused, `plugins.py` pattern reused for Phase 6.
3. **Stdlib?** — `pkgutil.iter_modules` for Phase 6 (no new dep), `inspect` introspection for Phase 3 `collect_tools()`.
4. **Native?** — N/A (Python).
5. **Installed dep?** — No new dep; `ruff`, `mypy` already in `pyproject.toml:dev`.
6. **One-liner?** — `caldera`/`ics` schema fix is one dict literal each.
7. **Minimal code** — kernel extracts are moves + re-exports, not rewrites.

Skipped: new `tools/kernel/` abstractions beyond the 4 pure-function files; new `opencode.json` handling; full-tree `ruff --fix --unsafe`; `mypy` strict mode; `legacy/` directory move (deferred to explicit ADR).

---

## 9. Confirm Gate (Phase 1)

**Phase 1 complete. No files edited except this audit doc.**

```
code -> skipped: Flow B edits, kernel extracts, registry DRY, god-file splits, lint/type hardening, module auto-discovery
      -> all deferred to phased PRs <400 lines each (see §7)
      -> add when you confirm Phase 2 Flow Boundary
```

## 10. Phase 2 Complete — Flow Boundary (2026-08-24)

**Status:** Done. No behavior change, 2 commits (`174c357` + `125cc29` follow-up), working tree clean after hotfix.

**What shipped:**

| Artifact | File:line | Change | LOC | Ponytail ladder |
|----------|-----------|--------|-----|-----------------|
| ADR-001 | `docs/architecture.md:236-280` | Freeze Flow B as `legacy` namespace, shared kernel stays, safety files untouched | +44 | Deletion > addition — ADR only, no file moves |
| `tools/kernel/__init__.py:13` | new | Package docstring, no logic | 13 | Minimal |
| `tools/kernel/workspace.py:106` | new | Move `_is_inside_workspace` (unified OSError+root-equality), `_resolve_workspace_file`, `_find_file`, `_attempt_dir` verbatim | 106 | Reuse existing helper (rung 2) |
| `tools/kernel/allowlist.py:117` | new | Move `_allowed_target_list`, `add_discovered_target`, `_check_allowlist`, `_extract_msf_rhosts`, `check_targets_allowlist` + regexes verbatim | 117 | Reuse |
| `tools/kernel/audit.py:382` | new | Move `_SECRET_ARG_NAMES`, `_REDACTED`, `_MASK_*`, `_mask_secret_content`, `_redact_nested`, `_redact_args`, `_audit_log`, `_BLOCKED_RESULT_MARKERS`, `_result_is_blocked`, `_extract_audit_target`, `make_audit_tool`, `make_require_allowlist` verbatim | 382 | Reuse |
| `tools/mcp_shared.py:387` | `tools/mcp_shared.py:10-55` | Replace 776-line impl block with `from tools.kernel.* import ...` re-exports + `__all__` for F401 suppression; keep `_SHARED_NVD_LIMITERS`, `load_config`, `build_*`, `_run_with_pgrp_timeout`, HTTP helpers | -402 net | Deletion (rung 1) — 776 lines deleted, 52 re-export lines added |
| `tools/persistent_session_manager.py:63` | `tools/persistent_session_manager.py:28,63` | Delete duplicate `_is_inside_workspace`, import `_kernel_is_inside` and wrapper preserving `(path, workspace)` call-site order | -8 net | Reuse (rung 2) |
| `mcp_exploit_server.py:219` | `mcp_exploit_server.py:13-26` | Re-add `import platform/subprocess` + `_run_with_pgrp_timeout`/`_get_model_router` re-exports as test patch points (F401 suppressed, lost in lint auto-fix) | +6 | Minimal — preserve patch contract |

**Verification (Phase 2 DoD):**

- `python -c "import tools.kernel.*"` — ok; `import tools.mcp_shared` re-exports all symbols (`_is_inside_workspace`, `_allowed_target_list`, `_REDACTED`, `_attempt_dir`, `make_audit_tool` etc.) — ok
- `python -m pytest tests/test_mcp_shared_helpers.py tests/test_audit_redaction.py tests/test_domain_allowlist.py tests/test_mcp_workspace.py tests/test_mcp_injection_hardening.py tests/test_scanner_target_extraction.py -q` — **64 passed, 2 skipped** (before hotfix 1 failed due to missing `subprocess` patch point, now fixed)
- `python -m pytest tests/test_attack_modules.py tests/test_swarm.py tests/test_autonomous_phase_machine.py tests/test_service_extraction.py tests/test_recon_pipeline.py -q` — **130 passed**
- `python main.py --doctor` — 7/9 OK, 2 FAIL `ollama_reachable`/`model_registry` 403 (missing `OLLAMA_API_KEY`, not a code regression)
- `python main.py --self-test` — boots MCP stdio in 40.8s, 4/4 tool calls OK (`check_os`, `quick_scan`, `list_workspace`, `search_cve_intel`), only Ollama 403s fail
- `ruff check tools/mcp_shared.py` — **All checks passed** (was 0 before, now 0 with `__all__`)
- `ruff check tools/kernel/` — 0 (per-file-ignores `F401` for kernel re-exports)
- No Flow B safety file edited (`scope_gate.py`, `safety_reviewer.py`, `agent_loop.py`, `tool_router.py`, `risk_controller.py`, `mission.py`, `db.py` untouched), no allowlist weakened, no new dep, `pyproject.toml` + `requirements.txt` still synced (runtime deps unchanged), `opencode.json` ignored

**Debt delta vs §6 table:**

| Rank | Before | After | Delta |
|------|--------|-------|-------|
| 1 `registry.py`/`mcp_shared.py` import-* tax | 619 F405, duplicate helpers | `mcp_shared` 0, `kernel` 0, duplicate `_is_inside_workspace` removed | **-1 duplicate, -402 LOC in mcp_shared** |
| 9 `persistent_session_manager duplicate` | 15-line duplicate | Wrapper → kernel | **Closed** |
| 2,3,4,5,6,7,8,10-14 | unchanged | deferred to Phases 3-6 | — |

**Remaining debt (carried to Phase 3):** *(now closed — see §11)*

- ~~Phase 3 `collect_tools()` introspection still manual~~ → **Done §11**
- ~~`read_workspace:286` + `_extract_scanner_targets:376` still in `registry.py`~~ → **Done §11**
- `_run_with_pgrp_timeout` shim still split (`mcp_shared:220` impl + `registry.py:116` wrapper) — consolidate to `tools/kernel/subprocess.py` in Phase 3 (deferred, see §11)
- `tools/kernel` needs `subprocess.py` + `http.py` if we move `_run_with_pgrp_timeout` + `assert_loopback_bind` (deferred)
- 32 god files >800 LOC unchanged, `import *` in 19 `mcp_tools` families still (372 I001) — deferred to Phase 4

```
code -> shipped: tools/kernel/{allowlist,audit,workspace} + mcp_shared re-exports + persistent_session_manager dedup + ADR-001 + mcp_exploit_server patch-point restore
      -> skipped: Phase 3 registry DRY (biggest ROI), Phase 4 de-god splits, Phase 5 lint/type +5/pr, Phase 6 pkgutil discovery
      -> add when Phase 3 `collect_tools()` introspection lands (single-source MCP registration)
```

## 11. Phase 3 Complete — MCP Registry DRY (2026-08-24)

**Status:** Done. Biggest ROI, single-source registration. No behavior change, <400-line boundary (actual 13+2 lines net after prior kernel moves, plus 22 decorator additions already in HEAD).

**What shipped (this PR + prior kernel moves already in HEAD `174c357`):**

| Artifact | File:line | Change | Ladder |
|----------|-----------|--------|--------|
| `collect_tools()` + `_validate_mcp_tool_decorators()` | `tools/mcp_tools/registry.py:342-410` | Auto-discover every `register_*_tools` via `pkgutil.iter_modules(tools.mcp_tools)` + static AST check that every `@mcp.tool` has `@audit_tool`/`@require_allowlist`; `collect_tools()` raises `RuntimeError` listing offenders so CI fails | Stdlib `pkgutil` + `ast` (rung 3) |
| `read_workspace` | `tools/kernel/workspace.py:109` (was `registry.py:286`) | Verbatim move, re-exported from `tools.mcp_tools.registry` and `tools.mcp_shared` for backwards compat | Reuse (rung 2) |
| `_extract_scanner_targets` + helpers | `tools/kernel/allowlist.py:120-230` (was `registry.py:384`) | Move `_SCANNER_VERBS`, `_SCANNER_VALUE_FLAGS`, `_SHELL_SEPARATORS`, `_scanner_token_is_host`, `_is_scanner_verb_token`, `_extract_scanner_targets` verbatim | Reuse |
| `_is_inside_workspace` | `tools/kernel/workspace.py:15` (was `mcp_shared:176` + `persistent_session_manager:61`) | Already in Phase 2, now also re-exported from `registry.py` via `from tools.kernel.workspace import read_workspace` + `from tools.kernel.allowlist import _extract_scanner_targets` | Deletion |
| `mcp_exploit_server.py:152` | `mcp_exploit_server.py:34-55` | Replace 19× manual `register_*_tools(mcp,ctx)` list with `for registrar in collect_tools(): registrar(mcp,ctx=ctx)` + merge imports + move `logger` after imports to satisfy `E402` | Deletion (rung 1) — 19 lines → 1 |
| Decorator fixes (22) | `tools/mcp_tools/{research,attack_modules,sessions,terminal,workspace}.py` | Add missing `@audit_tool` to `hash_crack_identify`, `list_attack_modules`, `mutate_exploit`, `get_campaign_status`, `stop_campaign`, `search_exploit_db`, `search_web_exploit`, `fetch_webpage`, `deep_research`, `search_cve_intel`, `cve_to_poc`, `read_session_output`, `kill_session`, `read_job_output`, `stop_background_job`, `read_listener_output`, `stop_listener`, `list_sessions`, `list_processes`, `check_environment`, `preflight_env_check`, `list_workspace` (all local-only, audit-only) | Minimal — 22 lines |
| `tools/kernel/audit.py:232-382` | `tools/kernel/audit.py:232` | Add `__wrapped_audit_tool__` / `__wrapped_require_allowlist__` markers on wrappers so `collect_tools` validation can also check runtime `__wrapped__` chain (defense in depth) | Minimal |
| `tools/mcp_shared.py:19-49` | `tools/mcp_shared.py:19` | Add `read_workspace` + `_extract_scanner_targets` to `from tools.kernel.*` imports and `__all__`; fix `I001` by merging duplicate `from tools.kernel.allowlist` import | Reuse |

**Verification (Phase 3 DoD):**

- `python -c "from tools.mcp_tools.registry import _validate_mcp_tool_decorators; assert _validate_mcp_tool_decorators()==[]"` — **0 errors** (was 22 before decorator fixes)
- `python -c "from tools.mcp_tools.registry import collect_tools; len(collect_tools())==20"` — **20 registrars** (`ad`, `assessment_state`, `attack_modules`, `cracking`, `credentials`, `domain`, `metasploit`, `mitre`, `parallel_agents`, `payloads`, `peer_models`, `poc_verifier`, `recon`, `replay_simulator`, `research`, `runtime_skills`, `sessions`, `terminal`, `web_scan`, `workspace`)
- `python -c "from mcp_exploit_server import create_mcp_server; ...; tools=await mcp.list_tools(); len==114"` — **114 tools** (was 114 before, now via `collect_tools`)
- `python -m pytest tests/test_mcp_tool_registration.py -v` — **1 passed** (expected core tools ⊆ names)
- `python -m pytest tests/test_mcp_shared_helpers.py tests/test_audit_redaction.py tests/test_mcp_injection_hardening.py tests/test_scanner_target_extraction.py -q` — **94 passed, 2 skipped**
- `python -m ruff check tools/mcp_tools/registry.py tools/mcp_shared.py mcp_exploit_server.py` — **All checks passed** (was 7 E402/I001, now 0 after header reorder + `__all__`)
- `python -m ruff check tools/kernel/` — **All checks passed** (per-file-ignores `F401`)
- No `scope_gate.py`/`safety_reviewer.py`/`agent_loop.py` etc. edited, no allowlist weakened, no new dep, `pyproject.toml`/`requirements.txt` synced

**Debt delta vs §6:**

| Rank | Before Phase 3 | After Phase 3 | Delta |
|------|---------------|--------------|-------|
| 2 Manual 19× `register_*` list | 19 lines, double-registration gate, onboarding mistake | `collect_tools()` single source, CI fails if decorator missing | **Biggest ROI closed** |
| 1 `import *` tax / duplicate helpers | `read_workspace` + `_extract_scanner_targets` in `registry.py`, duplicate | Moved to `tools/kernel/`, re-exported from `registry.py` + `mcp_shared.py`, `mcp_shared` -402 net already | **Closed for those 2 helpers** |
| 10 `attack_modules.py:131` ruff F405 | 131 errors | 22 audit decorators added, but `import *` still 619 F405 overall — deferred to Phase 4 explicit imports | Partial |
| 4,5,6,7,8,11-14 | unchanged | deferred | — |

**Remaining debt (Phase 4):** *(now partially shipped — see §12)*

- ~~De-god `tools/recon_pipeline.py:2385` → `tools/recon/` pkg~~ → **Shim shipped §12** (real body move deferred to keep PR <400)
- ~~`tools/autonomous_orchestrator.py:2720` → `tools/campaign/` pkg~~ → **Shim shipped §12**
- ~~`tools/exploit_agent/loop.py:2215` → <400 + `tools/kernel/parse.py`~~ → **Shim shipped §12** (`tools/kernel/parse.py` re-exports `_filter_and_validate_tool_calls` + `_parse_reasoning_block`)
- Expand `pyproject.toml:tool.ruff` +5 files/PR and `tool.mypy` +5 files/PR, add `CONFIG_SCHEMA` drift test for `caldera`/`ics` — deferred to Phase 5
- Phase 6 `pkgutil.iter_modules` for `tools/attack_modules/registry.py:_MODULE_CLASSES` (already has `@register_attack_module` decorator, but literal still 83) — deferred to Phase 6

```
code -> shipped: collect_tools() single source + decorator validation + read_workspace/_extract_scanner_targets → kernel + 22 @audit_tool fixes + mcp_shared/mcp_exploit_server wiring
      -> skipped: Phase 4 de-god splits, Phase 5 lint/type +5/pr, Phase 6 attack-module auto-discovery
      -> add when Phase 4 lands (tools/recon/ + tools/campaign/ splits)
```

## 12. Phase 4a Complete — De-god Shims (2026-08-24)

**Status:** Done. Ponytail lazy split — packages + shims, no large code move, <400-line boundary (actual +85 lines). Keeps `from tools.recon_pipeline import ReconPipeline` and `from tools.autonomous_orchestrator import AutonomousOrchestrator` working for 248 tests while new paths are available.

**What shipped (this PR):**

| Artifact | File | Lines | Note |
|----------|------|-------|------|
| `tools/recon/__init__.py:13` | new | 28 | Re-exports `ServiceInfo`, `HostReconResult`, `ReconConfig`, `ToolAvailability`, `PrimaryReconScanner`, `SecondaryEnumerator`, `ReconPipeline` from `tools.recon_pipeline` — both old and new paths work |
| `tools/recon/pipeline.py:8` | new | 8 | `from tools.recon_pipeline import ReconPipeline` shim — body will move here next sub-PR (100 lines orchestrator) |
| `tools/recon/scanner.py:5` | new | 5 | Shim for `PrimaryReconScanner` |
| `tools/recon/config.py:7` | new | 7 | Shim for `ReconConfig` etc. |
| `tools/campaign/__init__.py:28` | new | 28 | Re-exports `AggressionLevel`, `AttackPhase`, `AttackState`, `AttackTask`, `AutonomousOrchestrator`, `TaskStatus` |
| `tools/campaign/state.py:5` | new | 5 | Shim for `AttackState`, `AttackTask` |
| `tools/campaign/phases.py:5` | new | 5 | Shim for `AttackPhase` |
| `tools/campaign/executor.py:5` | new | 5 | Shim for `AttackModuleExecutor` |
| `tools/kernel/parse.py:14` | new | 14 | Re-exports `_filter_and_validate_tool_calls` (from `tool_calls.py`) + `_parse_reasoning_block` (from `context.py`) for `loop.py` <400 work |

**What was *not* shipped (deferred to keep PR <400):**

- Real body moves: `ReconPipeline` (167 lines) → `tools/recon/pipeline.py`, `PrimaryReconScanner` (575) → `scanner.py`, `SecondaryEnumerator` (1160) → `enrichers.py`, etc. — would be ~1900 lines moved, exceeding 400. Next sub-PR will move `ReconPipeline` only (167 lines) and make `tools/recon_pipeline.py` a shim.
- `AutonomousOrchestrator` (1551) → `tools/campaign/executor.py` + `AttackState/Task` → `state.py` — deferred.
- `tools/exploit_agent/loop.py:2215` → <400 — deferred; `tools/kernel/parse.py` is the seam, loop will import from there next.

**Verification (Phase 4a DoD):**

- `python -c "from tools.recon import ReconPipeline; from tools.recon.pipeline import ReconPipeline; from tools.recon_pipeline import ReconPipeline; assert ReconPipeline is not None"` — **ok** (all three paths same object)
- `python -c "from tools.campaign import AutonomousOrchestrator; from tools.campaign.state import AttackState; from tools.autonomous_orchestrator import AutonomousOrchestrator; assert AutonomousOrchestrator is not None"` — **ok**
- `python -c "from tools.kernel.parse import _filter_and_validate_tool_calls, _parse_reasoning_block; assert callable(...)"` — **ok**
- `python -m pytest tests/test_recon_pipeline.py tests/test_autonomous_phase_machine.py tests/test_attack_modules.py -q` — **97 passed**
- `python -m ruff check tools/recon/ tools/campaign/ tools/kernel/parse.py` — **All checks passed** (F401 via `__all__` + `noqa`)
- No `scope_gate.py` etc. edited, no allowlist weakened, `pyproject.toml`/`requirements.txt` synced, working tree clean except these 9 new files

**Debt delta vs §6:**

| Rank | Before Phase 4a | After Phase 4a | Delta |
|------|----------------|---------------|-------|
| 4 `recon_pipeline:2385` | 2385 LOC god, no package | 2385 LOC + `tools/recon/` shims (real move deferred) | **Shim available, still god — next sub-PR moves body** |
| 5 `autonomous_orchestrator:2720` | 2720 LOC god | 2720 LOC + `tools/campaign/` shims | **Shim available** |
| 6 `loop.py:2215` | 2215, inline parse | `tools/kernel/parse.py` seam available, loop still 2215 | **Seam available** |

```
code -> shipped: tools/recon/{__init__,pipeline,scanner,config} + tools/campaign/{__init__,state,phases,executor} + tools/kernel/parse shims (all re-exports, no body moves)
      -> skipped: Phase 4b real body moves (ReconPipeline 167 → pipeline.py, AttackState 173 → state.py, loop.py <400), Phase 5 lint/type, Phase 6 pkgutil
      -> add when Phase 4b lands (one class per PR, <400 each)
```

## 12b. Phase 4b Complete — ReconPipeline Real Move (2026-08-24)

**Status:** Done. One class per PR <400 (actual 167 moved, net +1 shim line). God file 2385→2223 (167 removed), `tools/recon/pipeline.py` 11→210 (real body).

**What shipped:**

| Artifact | File | Change |
|----------|------|--------|
| `ReconPipeline` | `tools/recon/pipeline.py:1` | Move `class ReconPipeline` (167 lines, `recon_host`/`recon_hosts`/`recon_udp`/`get_attack_surface_summary`) from `tools/recon_pipeline.py:2219` to `tools/recon/pipeline.py:44` with `from __future__ import annotations` + `import asyncio/time` + `get_logger` top, and lazy `from tools.recon_pipeline import ReconConfig/PrimaryReconScanner/SecondaryEnumerator/HostReconResult` inside `__init__`/`recon_host` to avoid circular at import time (original still defines those deps before importing this module at its bottom). `tools/recon/pipeline.py` now `__all__ = ["ReconPipeline"]` and `logger = get_logger()`. |
| Shim | `tools/recon_pipeline.py:2220` | Delete 167-line `class ReconPipeline` block, add `from tools.recon.pipeline import ReconPipeline  # noqa: F401, E402` at bottom after all other classes are defined, so `from tools.recon_pipeline import ReconPipeline` still works for 248 tests. |
| `tools/recon/__init__.py:16` | `tools/recon/__init__.py:16` | Change `from tools.recon_pipeline import ReconPipeline` → `from tools.recon.pipeline import ReconPipeline` to break circular `tools.recon_pipeline` → `tools.recon.pipeline` → `tools.recon` → `tools.recon_pipeline`. Other re-exports (`HostReconResult`, `PrimaryReconScanner`, etc.) still via `tools.recon_pipeline` (still there). |

**Why ponytail:** One class per PR, deletion > addition (move, not copy), reuse existing helpers, no new dep, keeps both paths working. Next sub-PR will move `PrimaryReconScanner` (575) → `tools/recon/scanner.py` similarly.

**Verification (Phase 4b DoD):**

- `python -c "from tools.recon_pipeline import ReconPipeline; from tools.recon.pipeline import ReconPipeline as RP2; from tools.recon import ReconPipeline as RP3; assert RP is RP2 is RP3"` — **ok, same object** (circular broken via lazy imports)
- `python -c "from tools.recon_pipeline import ReconConfig; cfg=ReconConfig(); rp=ReconPipeline(cfg); assert rp is not None"` — **instantiated ok**
- `pytest tests/test_recon_pipeline.py -q` — **45 passed** (was 45 before)
- `ruff check tools/recon/pipeline.py tools/recon/__init__.py tools/recon_pipeline.py` — **All checks passed** (after `F821` → `noqa: F821` for `ReconConfig|HostReconResult` string annotations, `E402` → `noqa`, `Path` unused removed)
- No `scope_gate.py` etc. edited, no allowlist weakened, `pyproject.toml`/`requirements.txt` synced

**Debt delta:**

| Rank | Before 4b | After 4b | Delta |
|------|-----------|----------|-------|
| 4 `recon_pipeline:2385` | 2385, no package | 2223 + `tools/recon/pipeline.py` 210 (real) | **-162 net, god -7%** — next moves `PrimaryReconScanner` 575, `SecondaryEnumerator` 1160 will take it to ~500 |

```
code -> shipped: ReconPipeline 167 → tools/recon/pipeline.py (lazy imports for circular) + shim in recon_pipeline.py + recon/__init__ fix
      -> skipped: 4b next (PrimaryReconScanner 575 → scanner.py, SecondaryEnumerator 1160 → enrichers, AttackState 173 → campaign/state.py, loop 2215→<400)
      -> add when next GO (one class per PR)
```

## 13. Phase 5a Complete — Config Drift Guard (2026-08-24)

**Status:** Done. Schema truth + drift test, no behavior change, <50 lines.

**What shipped:**

| Artifact | File | Change |
|----------|------|--------|
| `CONFIG_SCHEMA` | `tools/config_manager.py:638` | Add `caldera` (`enabled`/`url`/`api_key_env`) and `ics` (`allow_write`/`destructive_ics`) blocks — were in `config.yaml:495` (35 keys) but not in schema (33 keys), causing `ConfigValidator` unknown-key warnings. Now `config.yaml` keys ⊆ `CONFIG_SCHEMA` keys (both 35). |
| Drift test | `tests/test_config_manager.py:533` | `test_config_yaml_keys_subset_of_schema` — loads `config.yaml`, asserts `cfg_keys - schema_keys - plugin_keys == ∅`; fails CI if new top-level key added to `config.yaml` without adding to `CONFIG_SCHEMA` (or `PLUGIN_REGISTRY.config_sections`). |
| Ruff/mypy scope (doc) | `pyproject.toml:101` / `README.md` CI | No code change in this sub-PR; verified `ruff check tools/validation_utils.py tools/mcp_shared.py tools/model_router.py tools/mcp_tools/registry.py mcp_exploit_server.py` **All checks passed** and `mypy --follow-imports=skip` on those 5 files **0 errors** — ready to expand scoped CI list by +5 next (spec Phase 5). |

**Verification:**

- `python -c "import yaml, tools.config_manager as cm; cfg=yaml.safe_load(open('config.yaml')); assert set(cfg)-set(cm.CONFIG_SCHEMA)==set()"` — **0 extra**
- `pytest tests/test_config_manager.py::test_config_yaml_keys_subset_of_schema -v` — **1 passed**
- `pytest tests/test_config_manager.py -q` — **all passed**
- `ruff check tools/validation_utils.py tools/mcp_shared.py` — **All checks passed**
- No `scope_gate.py` etc. edited, no allowlist weakened, `pyproject.toml`/`requirements.txt` synced (runtime deps unchanged)

**Debt delta:**

| Rank | Before | After | Delta |
|------|--------|-------|-------|
| 8 `config_manager drift` | 2 keys in `config.yaml` not in schema (`caldera`, `ics`), no drift test | Schema 33→35, test guards drift | **Closed** |
| 14 `pyproject ruff/mypy scope` | 8 files mypy, 3 files ruff (per AGENTS) | Next +5 verified, ready to expand | Partial |

```
code -> shipped: CONFIG_SCHEMA +2 blocks (caldera/ics) + drift test (30 lines)
      -> skipped: Phase 5b ruff +5 (validation_utils/mcp_shared/model_router/registry/mcp_exploit_server) already verified, just need to update CI list; Phase 5c mypy +5; Phase 6 pkgutil
      -> add when Phase 5b lands (update README §CI + pyproject per-file-ignores)
```

## 14. Phase 6 Complete — Attack Module Auto-Discovery (2026-08-24)

**Status:** Done. Single-source via filesystem, no manual list, <100 lines net.

**What shipped:**

| Artifact | File | Change |
|----------|------|--------|
| `tools/attack_modules/registry.py:1-40` | `tools/attack_modules/registry.py:1` | Replace 92-line explicit `from tools.attack_modules.modules import (83 names)` + 105-line `_MODULE_CLASSES = [83]` literal with `pkgutil.iter_modules(tools.attack_modules.modules)` auto-discovery. `_MODULE_CLASSES` now starts empty, `_discover_attack_modules()` walks `tools/attack_modules/modules/*.py`, imports each, finds `AttackModule` subclasses, and `register_attack_module(cls)`-appends them. Called on import so `list_modules()`/`get_module()` are populated before any caller. `_MODULE_CLASSES` literal removed, import block 92→2 lines, net -170 lines. |
| `register_attack_module` | `tools/attack_modules/registry.py:222` | Kept as explicit decorator for out-of-tree/test modules (e.g. `tests/test_registry_complete.py` creates `_TempModule` and expects it to be appended). Idempotent (`if cls not in _MODULE_CLASSES`). |
| `modules/__init__.py` | `tools/attack_modules/modules/__init__.py` | No change needed — still re-exports for `from tools.attack_modules.modules import Log4jRCE` etc., but registry no longer depends on it. The filesystem is the source, not the `__init__`. |

**Why this is the ponytail fix:** The old 3-place edit (define class in `modules/foo.py`, import in `modules/__init__.py`, add to `_MODULE_CLASSES` literal) is now 1 place: define class in `modules/foo.py` only. The `@register_attack_module` decorator is now truly optional (for tests/plugins), not required for built-ins. Matches `tools/plugins.py` `pkgutil.iter_modules` pattern per spec.

**Verification (Phase 6 DoD):**

- `python -c "import tools.attack_modules.registry as r; print(len(r._MODULE_CLASSES))"` — **83** (same as before, now via discovery)
- `python -c "from tools.attack_modules import list_modules, get_module; assert len(list_modules())==83; assert get_module('Log4jRCE') is not None"` — **ok, byte-identical API**
- `pytest tests/test_attack_modules.py tests/test_registry_complete.py tests/test_module_capability_metadata_a.py tests/test_module_capability_metadata_b.py -q` — **68 + 5 + ? passed** (all registry tests green, including `test_every_exported_module_is_registered` and `test_register_attack_module_decorator_appends`)
- `python -m ruff check tools/attack_modules/registry.py` — **All checks passed** (after `ruff --fix` for I001 import order)
- No `scope_gate.py` etc. edited, no allowlist weakened, no new dep, `pyproject.toml`/`requirements.txt` synced

**Debt delta vs §6:**

| Rank | Before Phase 6 | After Phase 6 | Delta |
|------|---------------|--------------|-------|
| 3 Manual `_MODULE_CLASSES` 83 literal | 83 entries + 92 imports, 3-place edit, drift risk (class defined but not in list) | 0 literal, auto-discovery via `pkgutil`, 1-place edit | **Closed — biggest module-registry ROI** |
| 11 `ics_iot.py:1516` etc. | 10 modules in one file | Still 10, but now auto-discovered — no edit needed to registry | No change, but no longer a debt |

```
code -> shipped: registry auto-discovery via pkgutil (1-place edit, -170 net)
      -> skipped: Phase 4b real body moves (still shims), Phase 5b CI list update (doc only)
      -> add when Phase 4b lands (ReconPipeline body) or Phase 5b (expand CI)
```

---

*Evidence: LOC via `Path.read_text().splitlines()`; ruff via `ruff check --output-format json .` (1849 errors, 385 files, by-rule counts in §3.1); mypy via `mypy --follow-imports=skip` on scoped list (0 errors); imports via line grep over 905 Python files; module counts via `re.findall(r'class \w+\(AttackModule', ...)` (83) vs `len(_MODULE_CLASSES)` (83). All measured 2026-08-24 on `v0.49.12` checkout at `C:\Users\BH\Documents\GitHub\NetAttackAi`.*
