---
title: "Tool Family: terminal"
sources:
  - tools/mcp_tools/terminal.py
  - tools/mcp_shared.py
  - tools/kernel/audit.py
  - tools/kernel/workspace.py
  - tools/validation_utils.py
  - tools/command_analyzer.py
  - tools/kernel/allowlist.py
tests:
  - tests/test_mcp_injection_hardening.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: terminal

- **Registration source:** `tools/mcp_tools/terminal.py:185 register_terminal_tools(mcp, *, ctx)` — discovered via `collect_tools()` / `register_*_tools` naming; no edit to `mcp_exploit_server.py` needed.
- **Workspace:** per-attempt dirs via `_attempt_dir(workspace)` (`tools/kernel/workspace.py:101`).
- **Subprocess:** `_run_with_pgrp_timeout` (`tools/mcp_shared.py:235`) with POSIX `killpg` on timeout.

## Tools Exported (10)

| Tool | Decorator | Params | Result Shape | Notes |
|------|-----------|--------|--------------|-------|
| `run_exploit_terminal` | `@audit_tool` + manual `_target_lock_block` | `command: str` | `TERMINAL_RESULT: completed|failed|timed_out|blocked (exit_code, duration)\nATTEMPT_ID: ...\nCOMMAND_ORIGINAL: ...\nCOMMAND_SANITIZED: ...\nPREFLIGHT_WARNING? / PREFLIGHT_CORRECTIONS?\nOPSEC_ADVISORY? (advisory)\nWORKSPACE: <attempt_dir>\nOUTPUT: <tail4000>` | Preflight `preflight_command_check` (sanitize + missing-tool warn) then allowlist lock on extracted dests + IPs + scanner targets (`terminal.py:60-97`). Windows prefers Git Bash (`_find_windows_bash`, `terminal.py:162`) for pipelines, else cmd.exe; Linux via bash wrapper. Deadlock-free via `communicate`, header never echoes shell metachars. |
| `apt_install` | `@audit_tool` | `packages: str` (space-separated) | `APT_INSTALL_RESULT: completed|failed|timed_out (exit_code=...)\nPACKAGES: ...\nOUTPUT:` | Regex `^[A-Za-z0-9_.+-]{1,60}$` per package; `_require_sudo_or_pivot` short-circuits when no passwordless sudo → `BLOCKED: ... PIVOT: call preflight_env_check` (`terminal.py:100-132`). |
| `git_clone` | `@audit_tool` | `repo_url: str`, `target_dir: str=""` | `GIT_CLONE_RESULT: completed|failed|timed_out (exit_code)\nREPO: ...\nPATH: ...\nOUTPUT:` (+ `PREFLIGHT_WARNING` if URL 404 probe fails) | Validates `https?://...\.git` or `github.com/...`; `target_dir` must match `^[A-Za-z0-9._-]{1,80}$`, workspace containment via `_is_inside_workspace`; HTTP existence preflight via `url_exists` (warn only, never hard-block private repos). Runs via argv list (`git clone -- url dir`) with `_run_with_pgrp_timeout`. |
| `pip_install` | `@audit_tool` | `packages: str` | `PIP_INSTALL_RESULT: ...` | Regex `^[A-Za-z0-9_.\-]{1,60}$` per package; `pip install` via bash -c. |
| `run_as_root` | `@audit_tool` + `_target_lock_block` | `command: str` | `ROOT_CMD_RESULT: completed|failed|timed_out|blocked (target lock: ...)` | Same lock as terminal; `_require_sudo_or_pivot` gate; runs `sudo <command> 2>&1` via `_run_with_pgrp_timeout` (no double audit log). |
| `check_environment` | `@audit_tool` | `tools: str=""` | `ENVIRONMENT_CHECK:\nOS: ...\nPython: ...\n[+/-] tool: path (version)\nSUMMARY: N/M\nMISSING: ...\nHINT: ...` | Default list from `_check_env_default_tools` = `tools.env_probe.ENV_TOOLS` union extras (masscan/nuclei/... + language runtimes). `shutil.which` + `--version` / `-version` probe per tool; sudo-aware hint. |
| `preflight_env_check` | `@audit_tool` | — | `render_env_context(preflight_env_probe())` or `ENV_OK: ...` or `PREFLIGHT_ENV_CHECK_ERROR: ...` | Local-only, probes sudo/pip + per-tool fallback `install_via_apt / pip / write_python_fallback`. |
| `install_package` | `@audit_tool` | `manager: str`, `packages: str` | `INSTALL_RESULT: completed|failed|timed_out (exit_code)\nMANAGER: ...\nPACKAGES: ...\nOUTPUT:` | `mgr in apt/pip/gem/npm/go/cargo/snap`; packages `^[A-Za-z0-9_.+\-/@]{1,80}$`; `sudo` branches gated by `_require_sudo_or_pivot`. |
| `download_and_install` | `@audit_tool` | `url: str`, `install_type: str="auto"`, `target_name: str=""` | `DOWNLOAD_RESULT: failed` or `INSTALL_RESULT: ... TYPE: deb|tarball|zip|binary` | URL `^https?://[A-Za-z0-9._/\-:@%+?=~&]+$`; `target_name` basename `^[A-Za-z0-9._-]{1,120}$`; `curl -fsSL -o`; then deb `dpkg -i + apt-get install -f`, tarball `tar -xzf`, zip `unzip -q`, binary `shutil.move -> /usr/local/bin else chmod`. All via argv + `_run_with_pgrp_timeout`. |
| `update_system` | `@audit_tool` | `upgrade: bool=True` | `UPDATE_RESULT: completed|failed (apt update only|update/upgrade)` | `sudo apt update 2>&1` then optionally `sudo apt upgrade -y 2>&1` (timeouts 300/600). |

## Parameters — Constraints

- `command` length capped 4000; empty rejected with `BLOCKED: empty command.`.
- Package names regex-validated; invalid → `BLOCKED: invalid package names.`.
- `repo_url` / `url` https-only; traversal `target_dir`/`target_name` basename-stripped and regex-gated.

## Result Shape — Common

`attempt_id` from `_attempt_dir`; `terminal.log` / `run_exploit.sh|cmd` / `msfvenom.log` per attempt; outputs truncated to last 3000–4000 chars.

## Dependencies

- `tools/validation_utils.preflight_command_check`, `extract_ips_from_command`, `is_target_in_allowlist`
- `tools/command_analyzer._extract_destinations`, `_endpoint_ips`
- `tools/kernel/allowlist._extract_scanner_targets`, `_allowed_target_list`, `_is_inside_workspace`
- `tools/opsec.OpsecManager` (advisory block only, never blocks execution)
- `tools/env_probe.ENV_TOOLS`, `_can_passwordless_sudo`, `preflight_env_probe`

## Config

- `exploit.shell: str` (default `bash`) — honors `shutil.which` and Windows Git Bash fallbacks
- `exploit.require_explicit_allowlist: bool` — when true, terminal lock is active
- `exploit.allowed_targets: list[str]` — extra allowed hosts

## Auditing

All 10 use `@audit_tool` (records `started`/`completed|blocked` with `_redact_args`; `input_text` wholesale-redacted; command masked by `_mask_secret_content`). `run_exploit_terminal`/`run_as_root` add explicit allowlist check inside; blocked result is `TERMINAL_RESULT: blocked` / `ROOT_CMD_RESULT: blocked` which flips audit to `approved=False`.

## Validation

- `preflight_command_check` sanitizes trailing-garbage IPs (`sanitize_target_in_command`); `run_exploit_terminal` runs against sanitized command.
- Target lock via `_target_lock_block` with host extraction: command-analyzer dests + bare IPs + scanner verb targets.

## Tests

- `tests/test_mcp_injection_hardening.py:340,350,360,379,400,413,435,527,554` — IPv6/hostname lock, allowlisted pass, destructive-in-lab allow, off-target block, script body lock, argv-no-shell, traversal neutralize
- `tests/test_mcp_tool_registration.py:9` — core tools presence (`run_exploit_terminal`)
- `tests/test_mcp_shared_helpers.py` — `_run_with_pgrp_timeout` helper behavior

## Related Docs

- `docs/mcp/security.md` — target lock + redaction
- `docs/mcp/registration.md` — decorator contract
