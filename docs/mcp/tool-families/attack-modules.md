---
title: "Tool Family: attack-modules"
sources:
  - tools/mcp_tools/attack_modules.py
  - tools/attack_modules/
  - tools/attack_planner.py
  - tools/exploit_mutator.py
  - tools/payload_crafter.py
  - tools/kernel/audit.py
tests:
  - tests/test_mcp_tool_registration.py
  - tests/test_mcp_injection_hardening.py
subsystem: mcp
---

# Tool Family: attack-modules

- **Registration source:** `tools/mcp_tools/attack_modules.py:131 register_attack_module_tools(mcp, *, ctx)` — auto-discovered. Holds module dispatch, CVE synthesis, campaign orchestration, and web-attack probes.
- **Gate:** target-touching tools `@require_allowlist()`; no-target tools plain (no decorator needed; audit-only is implicit when no target). `run_campaign_step` re-validates target from `state.json` via `check_targets_allowlist`.
- **Shared helper:** `_identify_hash_modes(h)` (`tools/mcp_tools/attack_modules.py:22-128`) — single source for `hash_crack_identify` + `run_hash_crack` (cracking family) mapping hash→hashcat mode.

## Tools Exported (20)

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `jwt_tamper` | `target_ip`, `jwt_token=""` | `JWT_TAMPER_RESULTS: ...\nHeader: ...\n--- alg:none attack ---\nNone-alg token: ...\n--- Weak HMAC secret brute-force ---\nWEAK SECRET FOUND? ...\n--- HMAC-to-RSA confusion` | Auto-discovers JWT via 16 HTTP paths when `jwt_token` empty; tests `alg:none`, weak secrets (32-word rockyou/jwt-secrets list), RSA confusion. |
| `ssti_probe` | `target_ip`, `port=80` | `SSTI_PROBE_RESULTS: ...` + `[DETECTED] engine at path?param` or `No SSTI` | Tests 10 math payloads (`{{7*7}}`, `${7*7}`, etc.) across 18 endpoints × 19 params via raw socket. |
| `graphql_introspect` | `target_ip`, `port=80` | `GRAPHQL_INTROSPECT_RESULTS` + `[+] endpoint found`, types, batching test | 14 endpoints, introspection query; batch attack test sends 5 queries. |
| `race_request` | `target_ip`, `port=80`, `endpoint="/api/redeem"`, `concurrent=20` (2..200) | `RACE_REQUEST_RESULTS: ... Concurrent: ... Completed in Xs Success: N Failure: M Mixed? [!]` | `ThreadPoolExecutor(max 50)` fires `POST {"code":"TEST100"}` concurrently; detects TOCTOU via mixed status / multiple successes. |
| `timing_oracle` | `target_ip`, `port=80` | `TIMING_ORACLE_RESULTS` + Login/reset timing means + `[+] TIMING ORACLE DETECTED` | Measures `valid vs invalid user` on `/api/login` and existing vs non-existing on `/api/reset-password` (8 samples, 150ms sleep, 50ms diff threshold). |
| `request_smuggling_probe` | `target_ip`, `port=80` | `REQUEST_SMUGGLING_RESULTS` + Baseline / CL.TE / TE.CL / TE.TE sections | Sends raw CL.TE, TE.CL, TE.TE probes, flags smuggling when `GPOST` leaks or baseline differs >200B. |
| `password_spray` | `target_ip`, `port=80`, `password="Password1"` | `PASSWORD_SPRAY_RESULTS: ... + per-user SUCCESS` | 43 usernames (service/cloud defaults), `POST /api/login` per user, 1.5s delay. |
| `cve_to_exploit_synth` | `target_ip`, `cve_id`, `service_name=""`, `version=""` | Writes `exploits/<cve>_<svc>.py` under attempt dir, returns `CVE_TO_EXPLOIT_SYNTH_RESULT: ... PATH: ... SHA256: ...` + rendered CVE-family template | Validates IP + CVE format, service/version strict regex (no newline/quote injection); dispatches to 14 `_render_*_template` (log4j, eternalblue, smbghost, bluekeep, regresshion, xz, activemq, confluence, ivanti, panos, citrix, connectwise, jenkins, joomla, text4shell, php_cgi, http2-rapid-reset, generic). Uses verified `cve_to_poc` (never invents URL). |
| `hash_crack_identify` | `hash_value` | `HASH_IDENTIFY_RESULT: ...\nNTLM: mode 1000\nMD5: ...` or `Unknown` | Delegates to `_identify_hash_modes`; reports all matching modes (32-hex → NTLM + MD5). |
| `create_attack_plan` | `target_ip`, `target_os=""`, `known_cves=""` | `ATTACK_PLAN_CREATED: ... STEPS: N` + serialized plan preview | `AttackPlanner.create_plan(target_ip, target_os, known_cves.split(","))` → persists `plans/<ip>_plan.json`. |
| `get_current_plan` | `target_ip` | `CURRENT_PLAN: ...` or `NO_PLAN_FOUND` | `AttackPlanner.load_plan(target_ip)` → `plan.to_dict()` preview. |
| `replan` | `target_ip`, `failure_reason` | `REPLAN_RESULT: ...` + new/mutated plan | `AttackPlanner.replan(target_ip, failure_reason)` (via `build_replanning_prompt` + `parse_replan_json`). |
| `list_attack_modules` | — | `ATTACK_MODULES: N ... - name | services | phase | read_only` | `list_modules()` capability records. |
| `run_attack_module` | `module_name`, `target_ip`, `options=""` | `MODULE_RESULT: ... OUTPUT: ...` | `get_module(name).run(ModuleContext(target_ip, options))` dispatched per module. |
| `craft_exploit` | `target_ip`, `service_name`, `version=""`, `os_hint=""`, `module_name=""` | `CRAFT_RESULT: ... PATH: ...` | Selects module by service/CVE + renders exploit file; similar template routing to synth. |
| `mutate_exploit` | `script_id`, `failure_output` | `MUTATE_RESULT: ... NEW_PATH: ...` | `ExploitMutator.mutate(script_id, failure_output)` — code-aware rewrite loop. |
| `start_autonomous_campaign` | `target_ip`, `goal="initial_access"`, `aggression_level="normal"` | `CAMPAIGN_STARTED: id=... + running background task` | Creates `AutonomousOrchestrator` task, holds strong ref in `_running_campaign_tasks` + `_campaign_orchestrators[campaign_id]`; `done` callback drops refs (`tools/mcp_tools/attack_modules.py:9-19, 2239-2410`). |
| `get_campaign_status` | `campaign_id` | `CAMPAIGN_STATUS: running|completed|failed + state.json preview` or `CAMPAIGN_NOT_FOUND` | Reads `campaigns/<id>/state.json` + orchestrator live state. |
| `run_campaign_step` | `campaign_id` (async) | `CAMPAIGN_STEP_RESULT: ...` or `BLOCKED: Host ... not in allowlist` | Loads `campaigns/<id>/state.json`, re-validates `target_ip` from state via `check_targets_allowlist` before executing one orchestrator step; audit-gated. |
| `stop_campaign` | `campaign_id` | `CAMPAIGN_STOPPED: id=... SUCCESS: ...` | Signals `AutonomousOrchestrator.stop()` via `_campaign_orchestrators[campaign_id]`. |

## Parameters

- Target IPs via `validate_target_or_ip`; CVE IDs strict; service/version quoted-regex gated for synthesis (newline/quote injection blocked — `tests/test_mcp_injection_hardening.py:672-707`).
- `concurrent` 2..200; `port` 1..65535.

## Dependencies

- `tools/attack_modules` (module registry), `tools/attack_planner`, `tools/exploit_mutator`, `tools/autonomous_orchestrator`, `tools/payload_crafter`
- `tools/validation_utils`, `tools/kernel/allowlist`

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets`
- `attack_modules.*` / `autonomous_orchestrator` aggression settings

## Auditing

- Target-touching: `@require_allowlist()` + `started/completed|blocked` records.
- `run_campaign_step` uses `@audit_tool` + manual `check_targets_allowlist` on target from `state.json` (LLM-influenced path).
- `list_attack_modules`/`mutate_exploit` no target, no audit gate needed.
- Secrets in `options` masked via `_mask_secret_content` before audit.

## Tests

- `tests/test_mcp_injection_hardening.py:672` — `cve_to_exploit_synth` rejects invalid IP/newline/quote
- `tests/test_mcp_tool_registration.py` — expects `list_attack_modules`, `run_attack_module`, `create_attack_plan`, `start_autonomous_campaign`, `get_campaign_status`, `run_campaign_step`, `stop_campaign`

## Related Docs

- `docs/attack-modules.md`
- `docs/mcp/tool-families/credentials.md` (post-exploit chain)
