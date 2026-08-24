---
title: "Tool Family: metasploit"
sources:
  - tools/mcp_tools/metasploit.py
  - tools/metasploit_bridge.py
  - tools/mcp_shared.py
  - tools/kernel/allowlist.py
tests:
  - tests/test_mcp_tool_scope.py
  - tests/test_mcp_injection_hardening.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: metasploit

- **Registration source:** `tools/mcp_tools/metasploit.py:11 register_metasploit_tools(mcp, *, ctx)` — auto-discovered. Bridges `msfconsole` (resource-file argv + persistent tmux bridge).
- **Gate:** structured targets `@require_allowlist()`; free-text / callback tools `@audit_tool` + manual `check_targets_allowlist` on extracted `RHOSTS/RHOST` + pivot hosts.

## Tools Exported (19)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `run_msf_module` | `@require_allowlist()` | `module: str`, `target_ip: str`, `options: str=""` | `MSF_RESULT: completed|failed|timed_out (exit_code, duration)\nATTEMPT_ID: ...\nMODULE: ...\nTARGET: ...\nOPTIONS: ...\nLOG_TAIL:` | Validates `module` `^[A-Za-z0-9_./-]{1,120}$`, target via `validate_target_or_ip`; options `shlex.split` + `key=value` with `^[A-Za-z0-9_]{1,60}$` keys, rejects `;|&$` `()<>\\\n` in values; builds resource file `use <module> / set RHOSTS <ip> / set k v / run / exit -y` and runs `[_msf_bin -q -r rc]` via argv list (no shell, C1). Windows `CREATE_NEW_CONSOLE`, POSIX `start_new_session` + `killpg` on timeout (600s). `msfconsole_path` from `exploit.msfconsole_path`. |
| `msfconsole_start` | `@audit_tool` | — | `MSFCONSOLE_STARTED\nNAME: ...\nMESSAGE: ...\nINITIAL_OUTPUT:` or `MSFCONSOLE_FAILED` | `MetasploitBridge(workspace).start_console()` in tmux session (persistent). Bridge cached on `mcp._msf_bridge` lazy (`metasploit.py:143-149`). |
| `msfconsole_stop` | `@audit_tool` | — | `MSFCONSOLE_STOPPED\nSUCCESS: ...\nMESSAGE: ...` | `bridge.stop_console()` |
| `msfconsole_command` | `@audit_tool` + `check_targets_allowlist(_extract_msf_rhosts(cmd))` | `command: str`, `wait_seconds=2.0`, `read_lines=100` | `MSFCONSOLE_COMMAND: <cmd>\nWAIT: ...\nOUTPUT:` or `BLOCKED: ... TOOL: msfconsole_command` | Scope gate extracts RHOSTS/RHOST from free-text cmd; blocked before bridge call. |
| `msf_run_exploit` | `@require_allowlist()` | `module`, `target_ip`, `options=""`, `payload=""`, `wait_seconds=30.0` | `MSF_EXPLOIT_RESULT: ...\nMODULE: ...\nTARGET: ...\nDURATION: ...\nSESSION_OPENED? ...\nOUTPUT:` | Parses `options` `k=v` split; `bridge.run_exploit(...)`. |
| `msf_run_auxiliary` | `@require_allowlist()` | `module`, `target_ip`, `options=""`, `wait_seconds=15.0` | `MSF_AUXILIARY_RESULT: ... OUTPUT:` or `MSF_AUXILIARY_FAILED` | Scanner/fuzzer via `bridge.run_auxiliary`. |
| `msf_list_sessions` | `@audit_tool` | — | `MSF_SESSIONS: N active` + per-session `[id] type platform — ip:port (via exploit)` or `No active sessions.` | `bridge.list_sessions()` |
| `msf_interact_session` | `@audit_tool` + `check_targets_allowlist(_extract_msf_rhosts(cmd))` | `session_id: int`, `command: str`, `wait_seconds=3.0` | `MSF_SESSION_INTERACT: session ...\nCOMMAND: ...\nOUTPUT:` or `BLOCKED` / `MSF_SESSION_INTERACT_FAILED` | Pivot-aware gate on command. |
| `msf_run_post_module` | `@audit_tool` | `module`, `session_id: int`, `options=""` | `MSF_POST_RESULT: ...\nSESSION: ...\nOUTPUT:` | `bridge.run_post_module`. |
| `msf_kill_session` | `@audit_tool` | `session_id: int` | `MSF_SESSION_KILLED: id\nSUCCESS: ...\nOUTPUT:` | `bridge.kill_session`. |
| `msf_generate_payload` | `@audit_tool` + `check_targets_allowlist([lhost])` | `payload_type`, `lhost`, `lport=4444`, `fmt="exe"`, `platform="windows"`, `arch="x64"`, `options=""`, `encoder=""`, `iterations=1` | `MSF_PAYLOAD_GENERATED\nTYPE: ...\nFORMAT: ...\nPLATFORM/ARCH\nFILE: ...\nSIZE: ...\nCOMMAND: ...\nOUTPUT:` or `MSF_PAYLOAD_FAILED` / `BLOCKED` | `lhost` is callback — allowlist gated; mirrors egress check. |
| `msf_run_resource_script` | `@audit_tool` + `check_targets_allowlist(_extract_msf_rhosts(content))` | `script_content: str` | `MSF_RESOURCE_SCRIPT_EXECUTED\nOUTPUT:` or `BLOCKED` / `MSF_RESOURCE_FAILED` | Free-text msfconsole commands — extracts every RHOSTS/RHOST and refuses off-list. |
| `msf_run_recipe` | `@audit_tool` + `check_targets_allowlist([target_ip] + RHOSTS from options)` | `name`, `target_ip=""`, `session_id=0`, `options=""` | `MSF_RECIPE_RESULT: name\nMODULE: ...\nKIND: ...\nOUTPUT:` or `BLOCKED: msf.recipes_enabled disabled` / unknown | Config `msf.recipes_enabled` must be true; `get_msf_recipe(name)` validates kind; `MSF_RECIPES` list. |
| `msf_start_handler` | `@audit_tool` + `check_targets_allowlist([lhost])` | `lhost`, `lport=4444`, `payload="windows/meterpreter/reverse_tcp"`, `options=""` | `MSF_HANDLER_STARTED\nLHOST: ...\nOUTPUT:` | Backgrounded `exploit/multi/handler` job; pairs with `msf_generate_payload`. |
| `msf_stop_handler` | `@audit_tool` | — | `MSF_HANDLER_STOPPED\nSUCCESS: ...\nOUTPUT:` | `jobs -K` via `bridge.stop_handler()`. |
| `msf_post_hashdump` | `@audit_tool` | `session_id: int` | `MSF_POST_RESULT: hashdump\nSESSION: ...\nOUTPUT:` | Wraps `post/windows/gather/hashdump` via `_post_module`. |
| `msf_post_getsystem` | `@audit_tool` | `session_id: int` | `MSF_POST_RESULT: getsystem\nSESSION: ...\nOUTPUT:` | `post/windows/escalate/getsystem`. |
| `msf_post_portfwd` | `@audit_tool` + `check_targets_allowlist([remote_host])` | `session_id`, `remote_host`, `remote_port`, `local_port=0` | `MSF_POST_RESULT: portfwd ...` | Pivot lock — `remote_host` must be in allowlist. |
| `msf_post_route` | `@audit_tool` + `check_targets_allowlist([subnet network])` | `session_id`, `subnet` | `MSF_POST_RESULT: route ...` | Extracts network address `subnet.split("/")[0]` and gates it; `post/multi/manage/autoroute`. |

## Parameters

- `module` strict regex; `options` key=value + metachar rejection; `lhost` validated via `check_targets_allowlist`.
- `session_id` must be `>0` for post modules.

## Dependencies

- `tools/metasploit_bridge.MetasploitBridge`, `get_metasploit_bridge(workspace)`, `MSF_RECIPES`, `get_msf_recipe`
- `tools/kernel/allowlist._extract_msf_rhosts`, `check_targets_allowlist`, `_allowed_target_list`
- `tools/mcp_shared._run_with_pgrp_timeout` (for `run_msf_module` log path) and `workspace._attempt_dir`

## Config

- `exploit.msfconsole_path: str` — msfconsole binary (default `msfconsole`)
- `exploit.msf.recipes_enabled: bool` — gates `msf_run_recipe`
- `exploit.require_explicit_allowlist`, `exploit.allowed_targets`

## Auditing

- `run_msf_module` / `msf_run_exploit` / `msf_run_auxiliary` → `@require_allowlist` (structured `target_ip`).
- Free-text / callback / pivot tools → `@audit_tool` + manual `check_targets_allowlist` inside; `BLOCKED:` result flips audit to `blocked`.
- Bridge sessions lazy-cached on `mcp._msf_bridge` — one per MCP server process.

## Validation

- Module path `/` separated, bounded `120` chars; no shell metachars.
- Options value filter `;|&$`()<>\\\n` prevents msfconsole string injection (previous `bash -c "msfconsole -x ..." ` replaced by resource-file argv).
- All payload callbacks and pivot hosts allowlist-gated (the pivot lock).

## Tests

- `tests/test_mcp_tool_scope.py:27,122,133,143,154` — `extract_msf_rhosts`, `msfconsole_command` / `msf_run_resource_script` / `msf_generate_payload` scope blocks
- `tests/test_mcp_injection_hardening.py:129,140,151,163,175,510` — module sanitization, opts without equals, metachar rejection, argv-list no shell, portfwd rhosts block

## Related Docs

- `docs/mcp/security.md`
- `docs/mcp/tool-families/payloads.md` — payload generation counterpart
