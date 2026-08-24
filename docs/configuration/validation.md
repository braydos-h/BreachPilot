---
title: Config Validation
description: How config.yaml is validated, what fails hard vs warns, and how to diagnose.
source: [tools/config_manager.py, tools/kernel/config.py, tools/doctor.py, tools/self_test.py, tools/api/routes/system.py]
---

# Config Validation

Validates the checked-in operator config (`config.yaml`) against `tools/config_manager.py::CONFIG_SCHEMA` and surfaces type/range errors before a run. Validation is **lenient by design** — most issues are warnings so a partial config degrades rather than crashes.

## Entry points

| Entry | Call | Behavior |
|-------|------|----------|
| `ConfigValidator.load` | `config_manager.py:720` | `path.exists()==False` → `self._config = _build_defaults()` (warn). `yaml.safe_load(...) or {}`. Non-dict root → `raise ValueError` |
| `ConfigValidator.validate` | `config_manager.py:736` | Populates `ConfigValidationResult.errors / warnings / unknown_keys`. No I/O. |
| `ConfigValidator.load_and_validate` | `config_manager.py:1186` | `load()` then `validate()` → `(config, result)` |
| `ConfigValidator.apply_defaults` | `config_manager.py:1200` | Deep-merge `self._config` over `copy.deepcopy(CONFIG_SCHEMA)`; file wins |
| `load_validated_config` | `config_manager.py:1281` | `load_and_validate()`; `raise ValueError` on `errors`; `logger.warning` on `warnings/unknown_keys`; `return apply_defaults()` |
| `tools/kernel/config.load_config` | `tools/kernel/config.py:11` | Pure: `path.exists()==False` → `{}`; non-dict → `ValueError`. Re-exported as `tools/config_cli.load_config` & `tools/mcp_shared.load_config` |
| `validate_config_file` | `config_manager.py:1274` | Quick `load_and_validate` returning `result` only |
| `PATCH /api/v1/system/config` | `tools/api/routes/system.py:110` | Atomic deep-merge + re-validate; rejects on `errors`; loopback `allowed_origins` enforced |
| `run_doctor` | `tools/doctor.py:388` | Loads raw yaml via `yaml.safe_load`, then `ConfigValidator.load_and_validate` via `_check_config`; reports `errors/warnings/unknown_keys` |
| `run_self_test` | `tools/self_test.py:89` | `load_validated_config`; any exception → `overall_ok=False` |

## Result shape

`ConfigValidationResult` (`config_manager.py:678`):

```python
class ConfigValidationResult:
    errors: list[str]        # hard failures — is_valid == False
    warnings: list[str]      # soft — has_warnings == True
    unknown_keys: list[str]  # top-level keys not in KNOWN_TOP_KEYS nor PLUGIN_REGISTRY
    @property is_valid -> bool   # len(errors)==0
    @property has_warnings       # warnings or unknown_keys
```

## What is checked

### Top-level unknown keys

`KNOWN_TOP_KEYS = set(CONFIG_SCHEMA.keys())` (`config_manager.py:671`). Any `key not in KNOWN_TOP_KEYS ∪ PLUGIN_REGISTRY.config_sections` → `unknown_keys` warn (not error). This prevents drift where `config.yaml` adds a block not in schema (tested in `tests/test_config_manager.py:542`).

### Required sections (warn only)

Missing `ollama` / `models` / `mcp` / `exploit` → `warnings.append("Missing section '...' . Defaults will be used.")` (`config_manager.py:758`). Never an error — defaults fill in.

### Per-section rules

| Section | Key | Check | Mode |
|---------|-----|-------|------|
| `ollama` | — | must be mapping; `host` missing → warn | warn |
| `models` | `registry`/`default_alias` | missing → warn | warn |
| `models` | `provider` | must be `ollama`\|`chatgpt` else warn | warn |
| `models` | `roles.*` | `roles` must be mapping; each value string; non-empty alias must be in `registry` else warn; empty string = default_alias | warn |
| `chatgpt` | `port` | int 1–65535 else warn | warn |
| `chatgpt` | `enabled`/`auto_start` | bool else warn | warn |
| `chatgpt` | `request_timeout_seconds`/`context_window`/`login_timeout_seconds`/`start_timeout_seconds`/`discover_cache_seconds` | non-negative number else warn | warn |
| `chatgpt` | `runtime` | `auto`\|`bun`\|`node` else warn | warn |
| `chatgpt` | `models` | must be list else warn | warn |
| `mcp` | `default_transport` | `stdio`\|`http`\|`""` else warn | warn |
| `mcp` | `http_port` | int 1–65535 else warn | warn |
| `exploit` | — | must be mapping | **error** |
| `cve_lookup` | `circuit_failure_threshold` | positive int else warn | warn |
| `cve_lookup` | `circuit_recovery_timeout` | positive number else warn | warn |
| `cve_lookup` | `search_rate_limit_per_minute` | non-negative number else warn | warn |
| `research` | `provider` | `ollama`\|`serpapi`\|`stdlib` else warn; `fallback_provider` `ollama`\|`serpapi`\|`stdlib`\|`""` | warn |
| `research` | `timeout_seconds`/`max_results`/`max_fetch_depth`/`max_content_chars`/`cache_max_entries` | positive int else warn | warn |
| `research` | `cache_ttl_seconds` | non-negative number else warn | warn |
| `research` | `min_source_quality` | `low`\|`medium`\|`high` else warn | warn |
| `research` | `require_api_key_for_mcp_tools` | bool else warn | warn |
| `research` | `ollama`/`serpapi`/`assistant` | must be mapping else warn (assistant sub-checks bools/ints + `model_alias` in `registry`) | warn |
| `memory` | `experience_min_samples` | positive int else warn | warn |
| `memory` | `experience_time_decay_days` | number (≤0 disables) else warn | warn |
| `memory` | `attack_memory_enabled` | bool else warn | warn |
| `memory` | `attack_memory_max_context_chars` | int ≥1000 else warn | warn |
| `outcome_judgment` | `max_inconclusive_attempts` | int ≥2 else warn | warn |
| `outcome_judgment` | `confirmation_threshold`/`refutation_threshold` | 0.5–1.0 else warn | warn |
| `outcome_judgment` | `min_evidence_references` | positive int else warn | warn |
| `outcome_judgment` | `flow_a`/`peer_review` | bool else warn | warn |
| `reasoning` | `ultrathink`/`llm_reflection` | bool else warn | warn |
| `reasoning` | `ultrathink_reflection_interval` | positive int else warn | warn |
| `reasoning` | `peer_consult_on_failure_threshold` | int ≥0 else warn | warn |
| `multi_model` | `enabled` | bool else warn | warn |
| `multi_model` | `consult_aliases` | list of non-empty strings else warn | warn |
| `multi_model` | `max_consultations`/`max_question_chars`/`max_answer_chars` | positive int else warn | warn |
| `skills` | `enabled/maybe_enabled/allow_model_lookup/inject_startup_context/reselect_mid_run/.../semantic_matching/...` | bool else warn | warn |
| `skills` | `reselect_max_per_run/.../diversity_penalty` | non-negative int else warn | warn |
| `skills` | `semantic_model` | non-empty string else warn | warn |
| `skills` | `semantic_min_similarity` | 0–1 else warn | warn |
| `skills` | `roots/default_enabled/include_tags/exclude_names` | list of non-empty strings else warn | warn |
| `skills` | `max_active_skills/max_chars_per_skill/max_total_chars/min_contextual_skills/default_skill_weight/context_skill_weight` | positive int else warn | warn |
| `orchestrator` | `semantic_memory` | bool else warn | warn |
| `agent` | toggles `task_graph_enabled/.../reflection_enabled` | bool else warn | warn |
| `agent` | `max_retries_per_task`/`max_actions`/`generated_code_repair_attempts` | non-negative int (bool rejected) else warn | warn |
| `eval` | `enabled` | bool else **error** | **error** |
| `eval` | `output_dir` | non-empty string else **error** | **error** |
| `eval` | `max_rounds` | non-negative int else **error** | **error** |
| `eval` | `write_markdown`/`write_html` | bool else **error** | **error** |
| `api` | `host` | loopback `127.0.0.1/localhost/::1` else **error** | **error** |
| `api` | `port` | int 1–65535 else **error** | **error** |
| `api` | `token_file` | non-empty string else **error** | **error** |
| `api` | `allowed_origins` | list of strings else **error** | **error** |
| `api` | `event_buffer_size`/`shutdown_timeout_seconds` | non-negative int else **error** | **error** |
| `api` | `serve_webui` | bool else **error** | **error** |

Sections `stealth`, `threat_intel`, `witness`, `autonomous`, `recon`, `opsec`, `poc_verification`, `replay_simulator`, `adaptive_exploits`, `plugins`, `webhook_notify`, `mitre`, `ticketing`, `caldera`, `ics` have schema defaults but no dedicated validation branch — unknown nested keys inside them are not flagged; top-level missing is silently defaulted.

Lab extras present in `config.yaml:200` not in `CONFIG_SCHEMA` defaults — `autonomous.dedup_targets/skip_non_routable/hard_target_max_rounds`, `recon.preflight_*`, `recon.max_retries/retry_delay/timeout_seconds/domain_resolution/fast`, `api.max_concurrent_runs/multi_operator/graph_route` — are carried verbatim; they are not validated and remain opt-in (see `docs/configuration/config-reference-generated.md`).

## Error vs warn vs unknown

- **Error** — `load()` non-mapping `ValueError`; nested `must be a mapping` for `ollama/models/mcp/exploit/chatgpt/...`; `api` loopback/port/file/origin type failures; `eval` type failures. `is_valid==False`; `load_validated_config` raises; `--doctor` reports `[FAIL] config_valid` with `errors`.
- **Warn** — type/range mismatches for everything else (bool/int/range/enum/alias-not-in-registry). Run continues; `has_warnings==True`; `--doctor` still `[OK]` but lists warnings.
- **Unknown key** — top-level key not in `CONFIG_SCHEMA` nor plugin registry. Warn only; never blocks. Use to catch drift after adding a checked-in block without schema entry.

## How `--doctor` and `--self-test` surface it

`_check_config(path)` (`tools/doctor.py:345`) constructs `ConfigValidator(path)` and calls `load_and_validate()` — not the old dict misuse. Reports:

```
[OK/FAIL] config_valid  path
      -> errors: [...]
      -> warnings: [...]
      -> unknown_keys: [...]
```

Any exception (YAML parse, non-mapping) → `{ok: False, error: str(exc)}`. Overall `failed +=1` on `ok==False` only; warnings alone do not fail doctor.

`self_test.py:89` calls `load_validated_config`; any exception sets `overall_ok=False` and stage `config_load`.

## Common failure modes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `config.yaml must contain a YAML mapping, got list` | Root is a list/scalar, not a mapping | Ensure file starts with `ollama:` etc., not `- item` |
| `load_validated_config: Config validation failed: ...` | `api.host` non-loopback, `api.port` out of range, `eval` type | Set `api.host: 127.0.0.1`, `api.port: 8765`, fix `eval.*` type |
| `Unknown config key: foo` | Typo or new block not yet in `CONFIG_SCHEMA` | Add to `CONFIG_SCHEMA` in `tools/config_manager.py` or `PLUGIN_REGISTRY.config_sections` |
| `models.roles.<role> 'xyz' is not in models.registry` | Alias typo | Add to `models.registry` or use empty `""` (=default_alias) |
| `research.assistant.model_alias 'abc' is not in models.registry` | Assistant alias typo | Same |
| `api.host must be loopback` on startup (`create_app`) | `api.host` set to public IP | Use loopback; public bind not supported in v1 (`app.py:70`, `config_manager.py:1161`) |
| `Config is empty or not loaded` | Empty file or `load()` not called before `validate()` | Ensure file has content or rely on defaults for missing file |
| Silent no-op for new key | Key under `recon` / `autonomous` etc. not in schema | Expected — those blocks have lab extras carried verbatim; add validation branch if you want warnings |

## Verifying a change

```powershell
python main.py --doctor          # env + nmap + Ollama + config + ports
python main.py --self-test       # localhost smoke; boots MCP server
python -m pytest tests/test_config_manager.py -v  # validates schema vs file drift
```

The phase-5 drift guard `tests/test_config_manager.py:542` asserts every top-level key in `config.yaml` is in `CONFIG_SCHEMA` (or plugin registry). Add new top-level blocks to `CONFIG_SCHEMA` before checking in `config.yaml`.

## Related

- `docs/configuration/overview.md` — loading and precedence.
- `docs/configuration/config-reference-generated.md` — every key with type/default/consumer.
