---
title: "Tool Family: sessions"
sources:
  - tools/mcp_tools/sessions.py
  - tools/persistent_session_manager.py
  - tools/kernel/audit.py
  - tools/kernel/workspace.py
tests:
  - tests/test_mcp_tool_registration.py
  - tests/test_persistent_session_manager.py
subsystem: mcp
---

# Tool Family: sessions

- **Registration source:** `tools/mcp_tools/sessions.py:9 register_session_tools(mcp, *, ctx)` — auto-discovered. Thin wrappers over `PersistentSessionManager` (`tools/persistent_session_manager.py`).
- **Gate:** free-text command/session creation via `@audit_tool` + manual `_target_lock_block(command, config)`; pure read/stop/list via `@audit_tool` only or no lock.

## Tools Exported (13)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `start_tmux_session` | `@audit_tool` + `_target_lock_block(command)` | `name: str`, `command: str` | `SESSION_STARTED: name\nTYPE: tmux\nCOMMAND: ...\nPID: ...\nSTATUS: running` or `SESSION_FAILED: ...` or `BLOCKED: target-IP lock — ...` | Delegates to `PersistentSessionManager(workspace).start_tmux_session(name, cmd, cwd=workspace)`; manager cached lazily on `mcp._session_mgr`. |
| `send_to_session` | `@audit_tool` + `_target_lock_block(input_text)` | `name`, `input_text: str` | `SENT_TO_SESSION: name\nINPUT: ...[:200]` or `SEND_FAILED: ...` or `BLOCKED` | Defense-in-depth: keystrokes can pivot host (`ssh evil`) so input text is gated. |
| `read_session_output` | `@audit_tool` | `name`, `lines: int=100` | `SESSION_OUTPUT: name\nLINES: ...\nOUTPUT:` or `READ_FAILED` | `mgr.read_session_output(name, lines)`. |
| `kill_session` | `@audit_tool` | `name` | `SESSION_KILLED: name\nSUCCESS: bool\nMESSAGE: ...` | `mgr.kill_session(name)` (tmux/background/listener). |
| `start_background_job` | `@audit_tool` + `_target_lock_block(command)` | `name`, `command` | `JOB_STARTED: name\nTYPE: background\nCOMMAND: ...\nPID: ...\nLOG: ...\nSTATUS: running` or `JOB_FAILED` / `BLOCKED` | `nohup` detached job via `mgr.start_background_job(name, cmd, cwd=workspace)`. |
| `read_job_output` | `@audit_tool` | `name`, `lines=100` | `JOB_OUTPUT: name\nRUNNING: bool\nLINES: ...\nOUTPUT:` | `mgr.read_job_output(name, lines)`. |
| `stop_background_job` | `@audit_tool` | `name` | `JOB_STOPPED: name\nSUCCESS: ...\nMESSAGE: ...` | `mgr.stop_background_job`. |
| `start_listener` | `@audit_tool` + conditional pivot gate | `name`, `port: int`, `listener_type="netcat"` (`netcat|socat|http|tls|dns|https-beacon|socks_pivot`), `protocol="tcp"`, `directory=""`, `upstream_host=""`, `upstream_port=0` | `LISTENER_STARTED: name\nTYPE: ...\nPORT: port/proto\nPID: ...\nLOG: ...\nSTATUS: running` or `LISTENER_FAILED` / `BLOCKED: exploit.listeners.tls is disabled` / `BLOCKED: Host ... not in allowlist` | New C2 types `tls/dns/https-beacon/socks_pivot` require `exploit.listeners.<key>: true` (keys `tls, dns, https_beacon, socks_pivot`); `socks_pivot` `upstream_host` must be allowlist-gated via `check_targets_allowlist`. |
| `read_listener_output` | `@audit_tool` | `name`, `lines=100` | `LISTENER_OUTPUT: name\nRUNNING: bool\nLINES: ...\nOUTPUT:` | `mgr.read_listener_output`. |
| `stop_listener` | `@audit_tool` | `name` | `LISTENER_STOPPED: name\nSUCCESS: ...\nMESSAGE: ...` | `mgr.stop_listener`. |
| `list_sessions` | `@audit_tool` | — | `SESSIONS: N active` + `● [type] name — status (pid=..., cmd=...)` or `No active sessions.` | `mgr.list_all_sessions()` — tmux + background + listeners unified. |
| `list_processes` | `@audit_tool` | `pattern: str=""` | `PROCESSES: N matching 'pat'\n  PID pid (user) CPU:.. MEM:.. — command` or `No processes matching` | `mgr.list_processes(pattern)`; error entries shown. |
| `kill_process` | `@audit_tool` | `name_or_pid: str` | `KILL_RESULT: ...\nSUCCESS: ...\nMESSAGE: ...` | `mgr.kill_process(name_or_pid)` — tracked name or raw PID. |

## Dependencies

- `tools/persistent_session_manager.PersistentSessionManager`, `get_session_manager(workspace)`
- `tools/mcp_tools/terminal._target_lock_block`, `tools/kernel/allowlist.check_targets_allowlist`
- `tools/kernel/workspace._attempt_dir` (indirect via manager)

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets` — lock for command/session creation
- `exploit.listeners.{tls,dns,https_beacon,socks_pivot}: bool` — per-new-type gate (legacy `netcat/socat/http` ungated)
- No session-specific timeout config; timeouts handled by `PersistentSessionManager`.

## Auditing

- Creation tools write `started`/`completed|blocked` with command masked; free-text commands are `input_text`-wholesale not applicable here but `password` etc. still masked if present in args.
- Read/stop/list tools still audit (`@audit_tool`) — consistent trail even for local reads.
- Manager state under workspace; `mcp._session_mgr` singleton lazy-initialized.

## Validation

- Free-text dests gated before manager call — off-allowlist host → `BLOCKED: target-IP lock — ...` without reaching `tmux`/`nohup`.
- `socks_pivot` upstream host allowlist-gated (the pivot lock); `tls/dns/https-beacon` config-gated.
- Input text in `send_to_session` gated (defense-in-depth against in-session pivot).

## Tests

- `tests/test_persistent_session_manager.py` — session CRUD, listeners
- `tests/test_mcp_tool_registration.py` — expects `start_tmux_session`, `start_background_job`, `start_listener`

## Related Docs

- `docs/mcp/tool-families/terminal.md` — terminal's `_target_lock_block` reused here
- `docs/mcp/security.md` — pivot lock
