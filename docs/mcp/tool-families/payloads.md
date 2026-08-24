---
title: "Tool Family: payloads"
sources:
  - tools/mcp_tools/payloads.py
  - tools/payload_crafter.py
  - tools/mcp_shared.py
  - tools/kernel/allowlist.py
tests:
  - tests/test_mcp_injection_hardening.py
  - tests/test_mcp_tool_scope.py
subsystem: mcp
---

# Tool Family: payloads

- **Registration source:** `tools/mcp_tools/payloads.py:10 register_payload_tools(mcp, *, ctx)` — auto-discovered.
- **Purpose:** Generate `msfvenom` payloads as workspace artifacts. Pairs with `msf_start_handler` (metasploit family) for reverse callbacks.

## Tools Exported (1)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `generate_payload` | `@audit_tool` + `check_targets_allowlist([lhost])` | `payload_type: str`, `lhost: str`, `lport: int=4444`, `format: str="exe"`, `platform: str="windows"`, `arch: str="x64"`, `options: str=""` | `PAYLOAD_RESULT: completed|failed|timed_out\nATTEMPT_ID: ...\nCOMMAND: msfvenom -p plat/arch/type LHOST=... LPORT=... -f fmt ... -o <path>\nFILE: <attempt_dir>/payload_...\nFILE_SIZE: N bytes\nDURATION: Xs\nOUTPUT: <3000 tail>` | `lhost` is allowlist-gated callback egress check; validates `validate_target_or_ip(lhost)` before construction. Whitelists `payload_type` (`reverse_tcp/reverse_https/bind_tcp/bind_tcp_rc4/reverse_http`), `format` (13: exe/elf/raw/python/csharp/dll/ps1/vba/jsp/war/asp/aspx/macho), `platform` (8: windows/linux/android/osx/unix/php/java/python), `arch` (6: x64/x86/armle/aarch64/mipsle/mipsbe). `options` rejected if `;|&$` `` `()<>\\n `` else `shlex.split` + argv extend. Runs `msfvenom` via `_run_with_pgrp_timeout` (300s), no shell. `out_file` naming normalizes `python→py`, `csharp→cs`. |

## Validation

- Empty `payload_type`/`lhost` → `BLOCKED`; `lport` `1..65535`; unsupported enum → `BLOCKED: unsupported ... Allowed: ...` listing allowed.
- Shell metachars in `options` → `BLOCKED: options contains forbidden shell metacharacters.`; unbalanced quotes → `BLOCKED: options string could not be parsed`.
- Allowlist gate refuses out-of-scope `lhost` before `msfvenom` is invoked.

## Dependencies

- `tools/kernel/allowlist.check_targets_allowlist`, `tools/validation_utils.validate_target_or_ip`
- `tools/mcp_shared._run_with_pgrp_timeout` + `_attempt_dir`

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets` — callback target lock
- No msfvenom-specific config; binary expected on `PATH`.

## Auditing

- `@audit_tool` records `started` then `blocked`/`completed` with redacted `lhost` not masked (it's the allowlist identity); `BLOCKED` result flips to `approved=False`.
- `_extract_audit_target` derives hosts from `lhost` for audit trail.

## Tests

- `tests/test_mcp_injection_hardening.py:275,288` — rejects metachar options, uses argv list no shell (`msfvenom -p ... LHOST ... -f ...` argv verified)
- `tests/test_mcp_tool_scope.py` — payload callback scoping (shared with metasploit payload path)

## Related Docs

- `docs/mcp/tool-families/metasploit.md` — `msf_generate_payload`/`msf_start_handler` counterpart
- `docs/mcp/security.md` — callback allowlist as egress gate
