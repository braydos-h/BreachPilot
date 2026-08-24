# Maintainability Baseline — 2026-08-24 (v0.49.12)

Evidence before synthesis. All commands run on Windows PowerShell, Python 3.11. `PYTHONUTF8=1`.

## 1. Test Suite

| Metric | Value | Command |
|--------|-------|---------|
| Test files | 249 (`tests/`) | `Get-ChildItem tests/*.py` |
| Collected tests | 3592 (+ 5 skipped in sample) | `python -m pytest tests/ --collect-only` |
| Full run | **TIMED OUT after 300s at ~48%**, partial failures observed (`FF` at 21-27%) | `python -m pytest tests/ -q --tb=no` |
| Sample (3 files) | 94 passed in 5.24s | `pytest tests/test_scope_gate.py test_safety_reviewer.py test_validate_target.py -q` |
| Collection errors (intermittent) | 9 errors importing `_run_with_pgrp_timeout`, `_wrap_http_auth`, `run_mcp_http_server` from `tools.mcp_shared` — **resolved after kernel re-export verified** (335 lines, helpers present) | `pytest tests/ -q` 2026-08-24 |

**Diagnosis:** suite is slow (>300 s, exceeds 60 s target in `pyproject.toml`). Failures cluster around 21-27% (likely `test_auto*`, `test_experience*`). Collection flakiness traced to `tools/mcp_shared.py` refactor (Phase 2 kernel extraction) — `git diff` shows 741 deletions moving audit/workspace/allowlist to `tools/kernel/*` but retaining `_run_with_pgrp_timeout`/`run_mcp_http_server` at EOF. Re-exports via `tools/kernel/*` + fallback in `tools/mcp_tools/registry.py:_run_with_pgrp_timeout` (delegates to `mcp_exploit_server._run_with_pgrp_timeout` if monkeypatched).

## 2. Lint — Ruff

| Scope | Errors | Fixable | Command |
|-------|--------|---------|---------|
| `ruff check .` (line count incl. help text) | 27835 lines | — | `ruff check . 2>&1 | Measure-Object -Line` |
| `ruff check --statistics` (unique violations) | **1849** | 918 fixable (114 hidden) | `ruff check --statistics` |
| `ruff check tools --statistics` | **933** | 154 fixable (61 hidden) | `ruff check tools --statistics` |
| `ruff check app.py scope_gate.py tools/safety_reviewer.py tools/validation_utils.py tools/intelligence tools/providers` | 0? (scoped README §CI expects 0, actual tools alone 933) | — | `ruff check app.py scope_gate ...` |

Breakdown (full tree, 1849):

```
619 F405 undefined-local-with-import-star-usage
372 I001 unsorted-imports
347 F401 unused-import
150 F541 f-string-missing-placeholders
122 W292 missing-newline-at-end-of-file
114 F841 unused-variable
 47 E402 module-import-not-at-top-of-file
 27 F403 undefined-local-with-import-star
 20 E741 ambiguous-variable-name
  9 F821 undefined-name
  7 E702 multiple-statements-on-one-line-semicolon
  6 F811 redefined-while-unused
  4 E701 multiple-statements-on-one-line-colon
  3 E401 multiple-imports-on-one-line
  1 E714 not-is-test
  1 W293 blank-line-with-whitespace
```

`pyproject.toml:102` `select=["E","F","W","I"]`, `ignore=["E501"]`, `line-length=120`. No `exclude` for `.venv`/`webui`/`oauth` → `ruff check .` scans `.venv` if not ignored (inflates line count; statistics correctly excludes via default).

## 3. Type Check — Mypy

| Scope | Result | Command |
|-------|--------|---------|
| 8-file core (`summarizer.py planner.py observer.py target_graph.py outcome_judge.py db.py mcp_exploit_server.py tools/mcp_shared.py`) | **Success: 0 errors** | `mypy --follow-imports=skip <8 files>` |
| `tools/` (full) | **359 errors** in 180+ files | `mypy --follow-imports=skip tools` |
| Notable | `tools/exceptions.py:26` `BaseException.exceptions`, `tools/validation_utils.py:177/322` union-attr, `tools/nmap_priv.py:34` `geteuid` on Win, many `Returning Any`, `tools/metasploit_bridge.py` missing `platform` arg | — |

`pyproject.toml:108` `python_version=3.11`, `warn_return_any=true`, `ignore_missing_imports=true`.

## 4. LOC & Module Size

| Metric | Value |
|--------|-------|
| Python LOC (`tools/` 202 files) | 79,962 lines (`wc -l tools/**/*.py` via Python) |
| `tools/` file count | 202 |
| Tests file count | 249 |
| `config.yaml` | 495 lines (monolith top-level keys: `ollama`, `models`, `chatgpt`, `mcp`, `nmap`, `exploit`, `opsec`, `cve_lookup`, `research`, `swarm`, `reasoning`, `memory`, `adaptive_exploits`, `multi_model`, `long_session`, `skills`) |
| Largest files (top 15) | `autonomous_orchestrator.py 2489`, `mcp_tools/attack_modules.py 2343`, `recon_pipeline.py 2121`, `exploit_agent/loop.py 2050`, `run_service/service.py 1590`, `web_researcher.py 1386`, `attack_modules/modules/ics_iot.py 1318`, `enhanced_reporting.py 1311`, `attack_modules/modules/web.py 1300`, `config_manager.py 1295`, `attack_ui.py 1209`, `persistent_session_manager.py 978`, `mcp_shared.py 978`→335 after kernel split, `mcp_tools/domain.py 916`, `api/routes/system.py 895` |
| No file >800? **Fails** — 10 files >1200 | Target: no file >800 LOC without split (`attack_modules/base.py:1` pattern) |
| `pyproject.toml` + `requirements.txt` sync | **Drift**: `requirements.txt` has `pytest`, `pytest-asyncio` (dev) but `pyproject` `dependencies` has `numpy`, `cryptography` not in `requirements.txt`? Actually `requirements.txt` includes `pytest`/`pytest-asyncio` while `pyproject` lists `numpy`/`cryptography` in runtime deps — both runtime lists overlap on `ollama`, `httpx`, `mcp`, `PyYAML`, `uvicorn`, `starlette`, `fastapi`, `websockets`, `questionary` but `requirements.txt` missing `numpy`/`cryptography` vs `pyproject` (and vice versa `pytest` in requirements but not runtime). Keep in sync per constraint 6. |

## 5. Coupling — `from tools.` Imports

Top 25 (`grep -r "from tools\." --include="*.py" | cut -d: -f2 | sort | uniq -c | sort -rn`):

```
 91 from tools.exploit_agent
 68 from tools.config_manager
 64 from tools.plugins
 58 from tools.validation_utils
 49 from tools.cve_lookup
 47 from tools.exploit_search
 42 from tools.skill_registry
 40 from tools.mcp_shared
 40 from tools.attack_modules.base
 38 from tools.web_researcher
 31 from tools.autonomous_orchestrator
 29 from tools.run_service.models
 27 from tools.mcp_tools.registry
 25 from tools.skill_selector
 24 from tools.attack_ui
 24 from tools.goal_engine
 22 from tools.goal_suggester
 22 from tools.eval_harness
 21 from tools.api.errors
 20 from tools.api.persistence
 20 from tools.model_router
 20 from tools.opsec
 19 from tools.recon_pipeline
 19 from tools.attack_modules
 18 from tools.api_key_store
... 180 unique modules
```

Hotspots: `exploit_agent` loop, `config_manager`, `plugins`, `validation_utils` — central coupling, hard to delete.

## 6. Architecture — Dual Flows

- **Flow A** (`main.py:1177` / `app.py:233` → `tools/exploit_agent/` → `mcp_exploit_server.py:244` → `tools/mcp_tools/*` → `tools/kernel/*`) — what users run, MCP-based, allowlist-locked via `tools/kernel/allowlist.py` + `tools/mcp_tools/terminal._target_lock_block`.
- **Flow B** (`cli.py:599` + `agent_loop.py:1509` / `db.py:1031` legacy SQLite) — shares `db.py`/`mission.py` schema only. `scope_gate.py`, `safety_reviewer.py`, `agent_loop.py`, `tool_router.py`, `risk_controller.py`, `mission.py`, `db.py` are **DO NOT EDIT** per `AGENTS.md:2`.

`tools/mcp_tools/registry.py:505` is central wiring (`ToolContext`, `make_audit_tool`, `make_require_allowlist`, model-router, scanner-verb extraction). `mcp_exploit_server.py:244` currently registers **18 tool families** via explicit `register_*` calls — the 2-place registration to collapse.

## 7. Config & Tool Sprawl

- `config.yaml:495` single file (tooling expects one file, not split). Validated by `tools/config_manager.py:1295` schema; `tools/config_cli.py:load_config` is entry point.
- `tools/` 202 files, packages: `exploit_agent/` (3.8K), `swarm/`, `mcp_tools/` (18 modules), `api/`, `run_service/`, `kernel/` (workspace/allowlist/audit), `providers/`, `intelligence/`, `attack_modules/` (9 categories), `kernel/` (new). Orphans <100 LOC exist (e.g. `demo_mode.py 7K` not orphan, but `env_probe.py` small). No file >800 target fails.

## 8. Targets vs Goals

| Goal | Baseline | Target |
|------|----------|--------|
| New MCP tool in 1 file | 2 places (`@audit_tool` + `mcp_exploit_server.py` list + `registry.py` wiring) | 1 decorator auto-registers |
| Find any feature <60s | Coupling 180 modules, 202 files, no `tools/__init__.py` module map | `tools/__init__.py` docstring + `docs/module-guide.md` mirror |
| `ruff check .` 0 | 1849 errors (933 in tools) | 0 in `tools/`+root, `oauth/`+`webui/` excluded |
| `mypy` typed core | 8 files pass, 359 errors in tools | `tools/`+`main.py`+`cli.py` 0 errors |
| `tools/` file count | 202 | <170, no file >800 |
| `config.yaml` strict | No strict unknown-key fail | `load_config` fail-fast |
| Net LOC | 79,962 tools | Deleted > added |
| `pyproject`+`requirements` sync | Drift | In sync |

## 9. Immediate Risks

1. **Test suite too slow / flaky** — >300s, ~5% failure, blocks CI. Need `pytest -k "not slow"` or parallel (`pytest-xdist`) + fixture deduplication (`tests/conftest.py:71` `mock_mcp_session`, `mock_ollama`, `mock_nmap`).
2. **Ruff not in CI** — `pyproject.toml:102` scoped scope still 933 errors; full tree 1849. Auto-fixable 918 (F401, W292, I001, F541) are safe wins.
3. **Mypy only 8 files** — expanding to `tools/` hits 359 errors; many are `no-any-return` / missing `platform` arg — fixable with `Optional`/`TypedDict`, not `Any`.
4. **`pyproject.toml` + `requirements.txt` drift** — sync before release.
5. **Kernel extraction incomplete docs** — `tools/__init__.py` missing module map; `docs/module-guide.md` lists `tools/mcp_shared.py` but not `tools/kernel/*`.

---
*Generated via Phase 0 audit. Next: Phase 1 safe wins (`ruff --fix`, `ruff format`, dead-code `ponytail:` comments), Phase 2 registry auto-discovery.*
