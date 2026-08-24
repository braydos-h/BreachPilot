---
title: "Tool Family: ad"
sources:
  - tools/mcp_tools/ad.py
  - tools/mcp_shared.py
  - tools/kernel/allowlist.py
  - tools/validation_utils.py
tests:
  - tests/test_ad_mcp.py
  - tests/test_mcp_tool_scope.py
subsystem: mcp
---

# Tool Family: ad

- **Registration source:** `tools/mcp_tools/ad.py:93 register_ad_tools(mcp, *, ctx)` — auto-discovered. Active Directory / Kerberos post-exploit vertical (Phase 1).
- **Gate:** all 7 tools `@require_allowlist()` on `target_ip`; secondary IPs (`dc_ip`, relay targets) additionally allowlist-gated; every command runs as argv list via `_run_with_pgrp_timeout`; outputs land under `exploit_workspace/<ip>/<attempt_id>/`.
- **Master + per-tool flags:** all keys under `exploit.ad_kerberos.*` default OFF (unchanged first-run behavior) except `smb_signing_check` detection-only default ON. Helpers `_ad_cfg`, `_ad_enabled(config, key, default)`, `_gate_dc`, `_nt_hash_arg`, `_run(argv, timeout)` in `ad.py:23-91`.

## Tools Exported (7)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `asrep_roast` | `@require_allowlist()` + `check_targets_allowlist([dc])` when off-target DC | `target_ip`, `domain` (required), `username=""`, `password=""`, `ntlm_hash=""`, `dc_ip=""` (defaults to target_ip), `users_file=""` | `ASREP_ROAST_RESULT: completed|failed|timed_out\nATTEMPT_ID: ...\nDOMAIN: ...\nDC_IP: ...\nTARGET: ...\nHASHES_FILE: <attempt_dir>/asrep_hashes.txt\nHASHES_SIZE: N bytes\nCRACK_COMMAND: hashcat -m 18200 file rockyou.txt\nOUTPUT:` | Guard `_ad_enabled(config,"asrep_roast")` else `BLOCKED: asrep_roast disabled`. Requires `domain`; when `users_file` empty, requires `username` + (`password` or `ntlm_hash`). Validates target IP and `dc_ip` via `_gate_dc` (off-target DC allowlist-gated). Builds `["impacket-GetNPUsers","-dc-ip",dc,"-request","-format","hashcat", "-usersfile?" , "-hashes :NT"?, auth_target or domain, "-outputfile", out_file]`. |
| `pass_the_hash` | `@require_allowlist()` | `target_ip`, `username` (required), `ntlm_hash: 32 hex or LM:NT 64`, `service="smb"` (`smb|winrm`), `command=""` | `PASS_THE_HASH_RESULT: completed ...\nATTEMPT_ID: ...\nSERVICE: ...\nTARGET: ...\nUSER: ...\nOUTPUT:` | Guard `pass_the_hash` flag. Validates `ntlm_hash` `^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?`, service whitelist. Prefers `nxc`/`crackmapexec` → `[nxc, svc, ip, -u user, -H NT, -x cmd?]` else fallback `["impacket-wmiexec","-hashes",":NT","user@ip", cmd?]`. 300s via `_run`. |
| `adcs_enum` | `@require_allowlist()` + `_gate_dc` | `target_ip`, `username` + `domain` (both required), `password|ntlm_hash` one required, `dc_ip=""` | `ADCS_ENUM_RESULT: ...\nATTEMPT_ID: ...\nDOMAIN: ...\nDC_IP: ...\nTARGET: ...\nOUTPUT:` | Guard `adcs_enum`. `certipy find -u user@domain -dc-ip dc [-p pass | -hashes] -target ip -output <attempt_dir>/adcs`. 300s. |
| `bloodhound_collect` | `@require_allowlist()` + `_gate_dc` | `target_ip`, `domain`, `username` (all required), `password|ntlm_hash`, `dc_ip=""` | `BLOODHOUND_COLLECT_RESULT: ...\nATTEMPT_ID: ...\nDOMAIN: ...\nDC_IP: ...\nTARGET: ...\nOUTPUT:` | Guard `bloodhound`. `bloodhound-python -u user -d domain -dc dc [-p pass | -hashes] -c All --zip -o <attempt_dir>/bloodhound`. 600s. |
| `responder_relay` | `@require_allowlist()` + relay list built **only** from allowlist | `target_ip`, `iface=""`, `command=""` | `RESPONDER_RELAY_RESULT: ...\nATTEMPT_ID: ...\nTARGETS_FILE: <attempt_dir>/relay_targets.txt\nRELAY_TARGETS: ...\nOUTPUT:` | Guard `responder_relay`. Builds `targets = dedup(_allowed_target_list(config) filter validate_ipv4) + target_ip` — off-list hosts never appear; when empty → `BLOCKED: no allowlisted relay targets`. Writes `relay_targets.txt`, runs `ntlmrelayx.py -tf file -smb2support [-i iface] [-c cmd]` 300s. `iface` is operator's interface, no target IP. |
| `smb_signing_check` | `@require_allowlist()` | `target_ip` | `SMB_SIGNING_CHECK_RESULT: ...\nATTEMPT_ID: ...\nTARGET: ...\nOUTPUT:` | **Detection-only, default ON** — guard `_ad_enabled(config,"smb_signing_check", default=True)`. Uses `nxc|crackmapexec smb ip --signing` when present else `nmap --script smb2-security-mode -p 445 ip` 120s. No creds sent. |
| `golden_ticket` | `@require_allowlist()` | `target_ip`, `domain`, `username` (both required), `krbtgt_hash: 32-hex NT`, `sid: str` (required), `duration="10d"` | `GOLDEN_TICKET_RESULT: ...\nATTEMPT_ID: ...\nDOMAIN: ...\nUSER: ...\nTARGET: ...\nCCACHE: <attempt_dir>/user.ccache\nUSE: export KRB5CCNAME=...; impacket-psexec -k -no-pass domain/user@ip\nOUTPUT:` | Guard `golden_ticket`. Validates `krbtgt_hash` 32-hex, `sid` required; runs `impacket-ticketer -nthash H -domain dom -domain-sid sid -user user -duration dur user` 120s. Ccache in `attempt_dir`; auth with `KRB5CCNAME` against owned target only. |

## Validation

- `target_ip` via `validate_target_or_ip` (IP or domain) before any subprocess; invalid → `ERROR: Invalid target_ip`.
- `ntlm_hash` / `krbtgt_hash` strict hex; `_nt_hash_arg` returns `["__INVALID_HASH__"]` sentinel checked before argv.
- `dc_ip` validated and off-target gated via `_gate_dc`; `_allowed_target_list` unions runtime `--target` so opbox-portable.

## Dependencies

- `tools/mcp_shared._run_with_pgrp_timeout`, `_attempt_dir`, `_allowed_target_list`
- `tools/kernel/allowlist.check_targets_allowlist`, `_extract_msf_rhosts` not needed (AD tools have their own DC gate)
- `tools/validation_utils.validate_target_or_ip`, `validate_ipv4`, `is_target_in_allowlist`
- `shutil.which` for binary presence (`certipy`, `bloodhound-python`, `nxc|crackmapexec`, `ntlmrelayx.py`, `impacket-ticketer`, `nmap`)

## Config

- `exploit.ad_kerberos.enabled: bool` (default false) — master switch for offensive tools
- `exploit.ad_kerberos.asrep_roast, pass_the_hash, adcs_enum, bloodhound, responder_relay, smb_signing_check, golden_ticket: bool` — per-tool flags (default false except `smb_signing_check: true`)
- `exploit.require_explicit_allowlist`, `exploit.allowed_targets`

## Auditing

- All `@require_allowlist()` → `started`/`completed|blocked` records with redacted `password` but not `ntlm_hash`? (hash is also in `_SECRET_ARG_NAMES` → redacted). `BI` note: `responder_relay`'s `TARGETS_FILE` path appears in result but not in audit `args`.

## Tests

- `tests/test_ad_mcp.py` — per-tool disabled gate, validation, dc_ip off-target block, nxc fallback, relay allowlist-only list, smb_signing default-on, golden ticket sid/hash validation
- `tests/test_mcp_tool_registration.py` — total count when `exploit.ad_kerberos.*` enabled

## Related Docs

- `docs/mcp/tool-families/credentials.md` — `kerberoast` vs `asrep_roast`, vault
- `docs/mcp/security.md` — pivot lock for secondary IPs
