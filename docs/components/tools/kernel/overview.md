---
title: Kernel — Overview
package: tools/kernel
files: [allowlist.py, audit.py, config.py, workspace.py, parse.py]
---

# Kernel — Overview (`tools/kernel/`)

Extracted safety/portability shims re-exported by `tools/mcp_shared` for backwards compatibility (Phase 2 kernel).

## Package map

| File | LOC | Role | Re-export via |
|---|---|---|---|
| `allowlist.py` | 238 | Target-IP allowlist union + extraction | `tools.mcp_shared._allowed_target_list`, `_check_allowlist` |
| `audit.py` | 374 | Credential redaction + audit decorators | `tools.mcp_shared.make_audit_tool`, `make_require_allowlist` |
| `config.py` | 25 | YAML `load_config(path)` | `tools.mcp_shared` / `tools.config_cli` |
| `workspace.py` | 132 | Path containment + per-attempt dirs | `tools.mcp_shared._resolve_workspace_file` |
| `parse.py` | 15 | Re-export shim | `tools.exploit_agent.context._parse_reasoning_block` + `tool_calls._filter_and_validate_tool_calls` |

## `allowlist.py` — The ONE attack-mode safety gate (`allowlist.py:1`, `config.yaml:83-86`, `safety-model.md`)

| Symbol | Kind | Line | Description |
|---|---|---|---|
| `_allowed_target_list(config)` | def | 35 | `exploit.allowed_targets` ∪ `EXPLOIT_TARGET`/`_IP`/`_DOMAIN`/`DISCOVERED_TARGETS` env vars (order-preserving dedupe) |
| `_check_allowlist(target_ip, config)` | def | 67 | `(allowed, reason)`; enforces `require_explicit_allowlist` + `is_target_in_allowlist` |
| `check_targets_allowlist(targets, config)` | def | 101 | Batch check for multi-target tools |
| `add_discovered_target(host, ip)` | def | 55 | Appends to `EXPLOIT_DISCOVERED_TARGETS` env |
| `_extract_msf_rhosts(text)` | def | 83 | Regex `RHOSTS/RHOST` + `portfwd/route/autoroute` hosts |
| `_extract_scanner_targets(command)` | def | 208 | `shlex` walk over `_SCANNER_VERBS` (nmap etc.), skipping `_SCANNER_VALUE_FLAGS` + `_SHELL_SEPARATORS`; host-shaped via `_scanner_token_is_host` |
| `_SCANNER_VERBS` | const | 128 | `{nmap,masscan,rustscan,nikto,nuclei,gobuster,…}` 16 verbs |
| `_SCANNER_VALUE_FLAGS` | const | 153 | 27 flags whose value is filename/IP not target |

`_allowed_target_list` is the allowlist union the lab build relies on (sole attack-mode safety when `exploit.permission=full_access` bypasses `policy.py`). `EXPLOIT_TARGET` family threaded by `tools/mcp_session.py:255-266` (`EXPLOIT_TARGET`/`_IP`/`_DOMAIN`/`DISCOVERED_TARGETS`). Matcher `tools/validation_utils.is_target_in_allowlist` supports domains + `*.wildcard` + CIDR (`validation_utils.py:380-420`).

`_check_allowlist` logic: `!require_explicit_allowlist → (True,"allowlist not required")`; else if `allowed_targets==[] → (False, "empty")`; else `is_target_in_allowlist(target, allowed) → (True) else (False,"Add it to exploit.allowed_targets")`.

## `audit.py` — Redaction + decorators (`audit.py:1`)

| Symbol | Kind | Line | Description |
|---|---|---|---|
| `_SECRET_ARG_NAMES` | frozenset | 27 | 30 names: `password, ntlm_hash, private_key, api_key, creds, …` |
| `_REDACTED` | const | 62 | `"***REDACTED***"` |
| `_MASK_RES` | tuple | 107 | 10 regexes: `_MASK_URL_AUTH_RE`, `_MASK_U_FLAG_RE`, `_MASK_LONG_PW_RE`, `_MASK_HYDRA_P_RE`, `_MASK_MSF_SET_RE`, `_MASK_HASHES_RE`, `_MASK_NTLM_FLAG_RE`, `_MASK_KV_SECRET_RE`, `_MASK_AUTH_HDR_RE`, `_MASK_PY_AUTH_TUPLE_RE` |
| `_mask_secret_content(value)` | def | 123 | Applies `_MASK_RES` over string value |
| `_redact_nested(value)` | def | 137 | Dict key redaction + string mask |
| `_redact_args(args)` | def | 148 | Per-arg redaction + `_WHOLESALE_REDACT_FIELDS={"input_text","notes"}` |
| `_audit_log(audit_path, target_ip, tool_name, approved, status, command, args, attempt_id, code_sha256, duration)` | def | 165 | Append `{timestamp,target_ip,tool_name,approved,status,command(mask),args(redacted),…}` JSONL |
| `_result_is_blocked(result)` | def | 200 | `upper().startswith(("BLOCKED:", "TERMINAL_RESULT: BLOCKED", …))` |
| `_extract_audit_target(bound)` | def | 208 | From `command/script_content` + `lhost` via `_extract_msf_rhosts` |
| `make_require_allowlist(workspace, config)` | def | 228 | Factory → `require_allowlist(target_param,audit)` decorator |
| `make_audit_tool(workspace)` | def | 310 | Factory → `audit_tool` decorator |

Decorators (`make_require_allowlist`/`make_audit_tool`):

- `require_allowlist(target_param="target_ip", audit=True)` wraps async or sync `fn` via `inspect.signature` + `functools.wraps`; pre-logs `status="blocked"|"started"` with `_redact_args(bound.arguments)`; on `!allowed` returns `BLOCKED: <reason>\nATTEMPT_ID: preflight\nTOOL: <fn>\nTARGET: <ip>` string; post-logs `blocked` if `_result_is_blocked(result)`. Preserves `__wrapped_require_allowlist__` / `__wrapped_audit_tool__` flags.
- `audit_tool` always logs `started` then `completed|blocked`, target from `_extract_audit_target(bound)`.

Lab build: no additional command-content gates; `full_access` bypass is intentional – allowlist is the lock.

## `config.py` (`config.py:11`)

```python
def load_config(path: Path) -> dict[str, Any]
```

Pure: `{} ` if missing, `yaml.safe_load` + `isinstance(dict)` check else `ValueError`. Shared by `tools.config_cli`, `tools.mcp_shared`, `tools.exploit_session`; no global state.

## `workspace.py` (`workspace.py:15`)

| Symbol | Kind | Line | Description |
|---|---|---|---|
| `_is_inside_workspace(workspace, target)` | def | 15 | `resolved.relative_to(root) or == root`, `OSError→False` |
| `_resolve_workspace_file(workspace, filename, suffix)` | def | 35 | Absolute vs. relative vs. basename → candidate resolve → inside check → `is_file && suffix` → `rglob` newest mtime fallback → `root/safe_name` |
| `_find_file(workspace, filename)` | def | 88 | `_resolve_workspace_file` + exists + inside |
| `_attempt_dir(workspace)` | def | 101 | `{workspace}/{YYYYMMDD_HHMMSS_ffffff}_{hex4}/` + `mkdir` |
| `read_workspace(workspace, filename)` | def | 109 | Operator-box unrestricted read: `Path(filename)` absolute vs. `workspace/` relative, `FILE_NOT_FOUND`, `read_text` with 120K truncation |

Workspace layout (lab build): `exploit_workspace/<ip>/<attempt_id>/` per `loop.py` via `_attempt_dir` shape; `loot/` subdir under PostExploitAgent. Operator-box FS unrestricted (path-traversal protection removed; allowlist is lock).

## `parse.py` (`parse.py:1`, shim)

```python
from tools.exploit_agent.context import _parse_reasoning_block
from tools.exploit_agent.tool_calls import _filter_and_validate_tool_calls
```

No new behavior; single import point for both flows and future `loop.py<400` refactor. `loop.py:52` still imports from `context`/`tool_calls` directly; `parse.py` is the canonical kernel surface.

## Config keys (read by `allowlist.py` via `config` dict)

| Key | Default | Effect |
|---|---|---|
| `exploit.allowed_targets` | `[127.0.0.1]` (`config.yaml:84`) | Base allowlist |
| `exploit.require_explicit_allowlist` | `true` (`config.yaml:83`) | Enforces allowlist |
| `EXPLOIT_TARGET` / `_IP` / `_DOMAIN` / `EXPLOIT_DISCOVERED_TARGETS` | env vars (`mcp_session.py:255`) | Runtime union |
| `exploit.workspace_dir` | `exploit_workspace` | `workspace.py` root |
| `exploit.loot_workspace` | `exploit_workspace/loot` | Loot dir |

No kernel-specific block; kernel reads the same `exploit.*` keys.

## Tests

| File | Verified | Covers |
|---|---|---|
| `tests/test_domain_allowlist.py` | yes | `_allowed_target_list`, CIDR/wildcard/domain matching |
| `tests/test_scanner_target_extraction.py` | yes | `_extract_scanner_targets` argv-walk + value-flag skip |
| `tests/test_audit_redaction.py` | yes | `_mask_secret_content`, `_redact_args`, 10 regexes |
| `tests/test_audit_chain.py` | yes | `verify_audit_chain` (policy) + kernel audit log append |
| `tests/test_mcp_shared_helpers.py` | yes | `load_config`, `_extract_msf_rhosts` |
| `tests/test_mcp_workspace.py` | yes | `_resolve_workspace_file`, `_is_inside_workspace`, `_find_file` |
| `tests/test_workspace_binary_write.py` | yes | `read_workspace` truncation + binary flag |
| `tests/test_mcp_tool_registration.py` | yes | `@require_allowlist` / `@audit_tool` decorator wiring |
| `tests/test_mcp_tool_scope.py` | yes | Allowlist gating on target-touching tools |
| `tests/test_validate_target.py` | yes | `is_target_in_allowlist`, `validate_target`, `is_fqdn` |
