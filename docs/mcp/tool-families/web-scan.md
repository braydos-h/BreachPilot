---
title: "Tool Family: web-scan"
sources:
  - tools/mcp_tools/web_scan.py
  - tools/mcp_shared.py
  - tools/kernel/allowlist.py
tests:
  - tests/test_mcp_web_scan.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: web-scan

- **Registration source:** `tools/mcp_tools/web_scan.py:18 register_web_scan_tools(mcp, *, ctx)` — auto-discovered. First-class wrapper around scanners otherwise shelled via `run_exploit_terminal`; gives parsed output + consistent audit record with the same target-IP lock.
- **Gate:** `@require_allowlist()` on `target_ip` (the one lock).

## Tools Exported (1)

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `run_web_scan` | `scanner: str`, `target_ip: str`, `port: int=80`, `path: str=""`, `options: str=""`, `timeout: int=300` | `WEB_SCAN_RESULT: completed|failed|timed_out\nATTEMPT_ID: ...\nSCANNER: ...\nTARGET: ip:port\nCOMMAND: <argv join>\nEXIT_CODE: N\nDURATION: Xs\nOUTPUT: <4000 tail>` + persists raw log to `<attempt_dir>/<scanner>.log` | Validates scanner in `_SCANNERS = {nikto,nuclei,sqlmap,gobuster,feroxbuster,whatweb,wpscan,dirb,dirbuster}`, target via `validate_target_or_ip`, port `1..65535`; allowlist on `target_ip`. `options` rejected if `;|&$` `` `()<>\\n `` else `shlex.split`. Checks `shutil.which(scanner)` → `SCANNER_NOT_INSTALLED: ... is not on PATH`. Builds argv via `_build_argv(scanner, ip, port, path)` (`web_scan.py:30-45`): nikto `-h ip -p port`, nuclei `-u url`, sqlmap `-u url --batch`, gobuster/feroxbuster/dirb/dirbuster `dir -u url -w /usr/share/wordlists/dirb/common.txt`, whatweb `url`, wpscan `--url url --enumerate u`; appends extra args; runs via `_run_with_pgrp_timeout(argv, timeout)`. |

## `_SCANNERS` and `_build_argv`

- `nikto`: `["nikto", "-h", target_ip, "-p", port]`
- `nuclei`: `["nuclei", "-u", url]`
- `sqlmap`: `["sqlmap", "-u", url, "--batch"]`
- `gobuster/feroxbuster/dirb/dirbuster`: `[scanner, "dir", "-u", url, "-w", _DEFAULT_WORDLIST]`
- `whatweb`: `["whatweb", url]`
- `wpscan`: `["wpscan", "--url", url, "--enumerate", "u"]`

`url = http://ip:port + path` (path appended verbatim when non-empty; port always explicit). `_DEFAULT_WORDLIST = /usr/share/wordlists/dirb/common.txt`.

## Validation

- Unsupported scanner → `BLOCKED: unsupported scanner '...' . Allowed: ...`
- Missing target / invalid IP → `BLOCKED: target_ip is required.` / `BLOCKED: target_ip must be valid...`
- Shell metachars in `options` → `BLOCKED: options contains forbidden ...` — never reaches shell (argv list only).

## Dependencies

- `tools/kernel/allowlist.check_targets_allowlist` (via `@require_allowlist`)
- `tools/validation_utils.validate_target_or_ip`
- `tools/mcp_shared._run_with_pgrp_timeout`, `_attempt_dir`
- `shutil.which` for binary presence

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets`
- No per-scanner config; relies on Kali wordlist location and binaries on `PATH`.

## Auditing

- `@require_allowlist()` → `started` then `completed|blocked` (blocked flips `approved=False`). Raw scan log persisted to workspace for `read_workspace_file` retrieval and audit trail.

## Tests

- `tests/test_mcp_web_scan.py` — scanner allowlist / metachar rejection / not-installed case (mocked `shutil.which` + `_run_with_pgrp_timeout`)
- `tests/test_mcp_tool_registration.py` — expects `run_web_scan` presence

## Related Docs

- `docs/mcp/tool-families/recon.md` — recon pipeline counterpart
- `docs/mcp/security.md` — allowlist and validation detail
