---
title: "Tool Family: workspace"
sources:
  - tools/mcp_tools/workspace.py
  - tools/kernel/workspace.py
  - tools/mcp_shared.py
  - tools/mcp_tools/terminal.py
tests:
  - tests/test_mcp_workspace.py
  - tests/test_mcp_injection_hardening.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: workspace

- **Registration source:** `tools/mcp_tools/workspace.py:20 register_workspace_tools(mcp, *, ctx)` — auto-discovered.
- **Purpose:** Python exploit synthesis + operator-box filesystem access (LAB BUILD: unrestricted operator-box filesystem). `write_python_file` + `run_python_file` are the primary exploit development path on Windows.

## Tools Exported (4)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `write_python_file` | `@audit_tool` | `filename: str`, `code: str`, `binary: bool=False` | `PYTHON_FILE_WRITTEN: <name>\nATTEMPT_ID: ...\nPATH: ...\nMODE: text|binary\nSHA256: ...\nSIZE: N chars|bytes` | LAB BUILD: unrestricted. Absolute `filename` writes anywhere on operator box; bare/relative name writes into `_attempt_dir` as `attempt_dir / basename`. Creates parent dirs. `binary=True`: `code` is base64 payload → `base64.b64decode(validate=True)` → `write_bytes` (byte-exact for keys/PEM, no shell heredoc, no UTF-8 re-encoding). Else `write_text`. Validates non-empty `filename`/`code`; binary decode error → `BLOCKED: binary=True requires valid base64`. No length cap. |
| `run_python_file` | `@require_allowlist()` + static body scan | `target_ip: str`, `filename: str` | `PYTHON_RUN_RESULT: completed|failed|timed_out (exit_code, duration)\nATTEMPT_ID: ...\nSCRIPT: ...\nTARGET: ...\nLOG_TAIL: <3000>` | Validates `target_ip` via `validate_target_or_ip`, filename `^[A-Za-z0-9_.-]{1,80}\.py$` after basename-stripping `\\` → `/`. Resolves script across entire workspace via `_resolve_workspace_file(workspace, cleaned, suffix=".py")` (most recent `rglob` match), copies to current attempt dir. **Body scan:** `_target_lock_block(script_body, config)` on file content — literal IPs/URLs off-list → `BLOCKED: ... TOOL: run_python_file SCRIPT: ...`. Windows: `run_python.ps1` with `ps_quote`'d title + `powershell Tee-Object`; POSIX: direct `Popen([sys.executable, script, ip, --target, ip], env={ACTIVE_CHECK_TARGET, EXPLOIT_WORKSPACE}, start_new_session)`, 300s timeout with `killpg`. Target passed as `sys.argv[1]` bare, `--target <ip>`, and `ACTIVE_CHECK_TARGET` env — scripts should read `sys.argv[1]` or `parse_known_args`. |
| `read_workspace_file` | `@audit_tool` | `filename: str` | File text or `BLOCKED: empty filename.` / `FILE_NOT_FOUND: <name>` | Delegates to `read_workspace(workspace, filename)` (`tools/kernel/workspace.py:109-131`): absolute path used verbatim, relative under workspace; caps 120k chars; `read_text(errors=replace)`. LAB BUILD: unrestricted. |
| `list_workspace` | `@audit_tool` | — | `WORKSPACE: empty.` or `WORKSPACE:\n  rel/path (N bytes, modified iso)` | `os.walk(workspace)` up to 5000 entries, sorted by mtime reverse, renders first 50. |

## Validation

- `write_python_file`: non-empty name/code; binary base64 validated; path basename-stripped of quotes.
- `run_python_file`: target IP syntax + allowlist + filename regex + existence via `_resolve_workspace_file` + static body lock.
- No allowlist on `write/read/list` (LAB BUILD); `run_python_file` is the only execution gate.

## Dependencies

- `tools/kernel/workspace._attempt_dir`, `_resolve_workspace_file`, `_is_inside_workspace`, `read_workspace`, `ps_quote`
- `tools/validation_utils.validate_target_or_ip`, `is_target_in_allowlist`
- `tools/mcp_tools/terminal._target_lock_block` (script body scan)

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets` — only for `run_python_file`
- No workspace-specific config; operator-box filesystem is unrestricted.

## Auditing

- `write_python_file` / `read_workspace_file` / `list_workspace` via `@audit_tool` (records `started`/`completed|blocked` with `args` redacted; `input_text`-style not present).
- `run_python_file` via `@require_allowlist()` + add-on body-scan block — `BLOCKED` from body scan is a result string starting `BLOCKED:` so audit flips to `blocked` (`_result_is_blocked`).

## Tests

- `tests/test_mcp_workspace.py` — workspace read/write/containment
- `tests/test_mcp_injection_hardening.py:435,456,616,627` — blocks off-target script body, passes both positional+flag, rejects invalid IP, psquotes window title
- `tests/test_mcp_tool_registration.py` — expects `write_python_file`, `run_python_file`, `read_workspace_file`, `list_workspace`

## Related Docs

- `docs/mcp/tool-families/terminal.md` — terminal counterpart (`write_python_file` + `run_python_file` chain)
- `docs/mcp/security.md` — body-scan lock + workspace containment
