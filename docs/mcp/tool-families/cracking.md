---
title: "Tool Family: cracking"
sources:
  - tools/mcp_tools/cracking.py
  - tools/mcp_tools/attack_modules.py
  - tools/mcp_shared.py
  - tools/kernel/audit.py
tests:
  - tests/test_mcp_cracking.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: cracking

- **Registration source:** `tools/mcp_tools/cracking.py:18 register_cracking_tools(mcp, *, ctx)` — auto-discovered. First-class hashcat/john execution wrapper; `hash_crack_identify` only suggests commands, this tool runs the cracker locally and returns plaintext.
- **Gate:** `@audit_tool` only (local-only — no target touch, no allowlist). Advisory; never reaches network.

## Tools Exported (1)

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `run_hash_crack` | `hash_value: str`, `tool: str="hashcat"` (`hashcat|john`), `hash_mode: str=""`, `wordlist: str=""`, `rules: str=""`, `timeout: int=600` | `CRACK_RESULT: completed|failed|timed_out\nATTEMPT_ID: ...\nTOOL: ...\nHASH_TYPE: name (mode M)\nCOMMAND: ...\nEXIT_CODE: ...\nDURATION: Xs\nCRACKED: N\n<left> : <plain> (up to 50)\nSHOW_OUTPUT: <1500 tail>\nOUTPUT: <3000 tail>` | Auto-identifies mode via `_identify_hash_modes(h)` (`tools/mcp_tools/attack_modules.py:22`) when `hash_mode` empty — 32-hex → NTLM 1000 + MD5 0, Kerberos TGS `13100/19900`, bcrypt `3200`, etc. If no match → `BLOCKED: could not identify hash type; pass hash_mode=...`. Checks `shutil.which(tool)` → `CRACKER_NOT_INSTALLED: ... is not on PATH`. Writes hash to `<attempt_dir>/hash.txt`, resolves wordlist via `_resolve_wordlist` (`config["exploit"]["wordlist"]` else `/usr/share/wordlists/rockyou.txt`). Hashcat: `hashcat -m mode -a 0 hashfile wl [-r rules]` + `hashcat -m mode hashfile --show`; John: `john --wordlist=wl hashfile` + `john --show`. Runs via `_run_with_pgrp_timeout` (timeout configurable, 600 default), then `_run_with_pgrp_timeout` for `--show` (60s). Parses `--show`: hashcat `hash:plain` (rsplit), john `username:password` skipping `Ng 0:00...` summary. |

## `_identify_hash_modes` Mapping

Single source shared with `hash_crack_identify`: NTLM 1000 (32-hex), NetNTLMv2 5600, Kerberos TGS 13100/19900, AS-REP 18200/19900, MD5 0, SHA1 100, SHA256 1400, SHA512 1700, bcrypt 3200, sha512crypt 1800, md5crypt 500, Cisco 9/4, MSSQL 132/1731, Argon2 N/A (john), scrypt 8900, Django PBKDF2 12100, PDF 10400, Office 9400, WPA 22000, LM 3000 (only when nothing else matched).

## Dependencies

- `tools/mcp_tools/attack_modules._identify_hash_modes`
- `tools/kernel/workspace._attempt_dir`, `tools/mcp_shared._run_with_pgrp_timeout`
- `shutil.which`

## Config

- `exploit.wordlist: str` — default wordlist path override
- `exploit.require_explicit_allowlist` not applicable (local-only)
- No hash-specific config; wordlist/rules paths are caller-supplied.

## Auditing

- `@audit_tool` records `started`/`completed|blocked` with redacted args (no secrets in this family's args — `hash_value` itself is hashed material, not a password, but still logged; `wordlist`/`rules` paths not redacted). No target IP; `_extract_audit_target` finds nothing so audit has empty `target_ip`.

## Validation

- Empty `hash_value` → `BLOCKED: hash_value is required.`
- Unsupported `tool` → `BLOCKED: unsupported tool '...' Allowed: hashcat, john.`
- Unidentifiable hash without explicit `hash_mode` → `BLOCKED: could not identify...`
- Not installed → `CRACKER_NOT_INSTALLED`

## Tests

- `tests/test_mcp_cracking.py:21-202` — hash-type identification (NTLM, bcrypt, Kerberos TGS/ASREP, SHA256, unknown, 32-hex precedence), registration via `list_tools`, auto-resolve NTLM mode mock, `--show` parsing for hashcat/john, block on unknown, reject unsupported tool, not-installed path
- `tests/test_mcp_tool_registration.py` — expects `run_hash_crack`

## Related Docs

- `docs/mcp/tool-families/attack-modules.md` — `hash_crack_identify` advisory counterpart
- `docs/mcp/tool-families/credentials.md` — dump → crack flow
