---
title: "Tool Family: credentials"
sources:
  - tools/mcp_tools/credentials.py
  - tools/credential_store.py
  - tools/kernel/allowlist.py
  - tools/kernel/audit.py
  - tools/mcp_shared.py
  - tools/validation_utils.py
tests:
  - tests/test_mcp_tool_scope.py
  - tests/test_mcp_injection_hardening.py
  - tests/test_credential_store.py
subsystem: mcp
---

# Tool Family: credentials

- **Registration source:** `tools/mcp_tools/credentials.py:11 register_credential_tools(mcp, *, ctx)` — auto-discovered.
- **Gate:** all 7 tools `@require_allowlist()` (target-IP lock + audit). Secondary host `dc_ip` in `kerberoast` additionally `check_targets_allowlist` gated.
- **Vault:** `CredentialStore` (`tools/credential_store.py`) under `workspace/credentials/<target_ip>/credentials.jsonl`, Fernet-encrypted at rest (`CredentialStore.encryption_enabled` true when `cryptography` installed, else plaintext fallback).

## Tools Exported (7)

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `cred_store_add` | `target_ip`, `username`, `password=""`, `credential_type="password"` (`password|hash|token|key`), `source_host=""`, `target_host=""`, `notes=""` | `CRED_STORE_ADD: stored|duplicate (already present)\nTARGET: ...\nUSERNAME: ...\nTYPE: ...\nCONFIRMED: False (run cred_store_confirm after validated reuse)\nENCRYPTION_AT_REST: ENABLED|DISABLED ...\nSTORE: ...` | Validates IP/FQDN, requires `username` + non-empty `password/secret`; `credential_type` strict set. Builds `CredentialRecord(timestamp, source_host, target_host, username, password, credential_type, source_action="cred_store_add", confirmed=False, notes)`, `store.add(rec)` dedupes. `password`/`notes` redacted in audit (`_SECRET_ARG_NAMES` + `_WHOLESALE_REDACT_FIELDS`). |
| `cred_store_get` | `target_ip`, `username=""`, `target_host=""`, `include_secret=False` | `CRED_STORE_GET: N credential(s) for ip` + per-record `USERNAME/TYPE/TARGET_HOST/SOURCE_HOST/CONFIRMED/SOURCE_ACTION/SECRET: <masked or revealed>/NOTES` or `CRED_STORE_GET: no credentials stored` | Safe by default (`SECRET: <masked -- set include_secret=True with username to reveal>`). Only `include_secret=True` **with** a specific `username` reveals decrypted `r.password`; empty username lists masked only. Optional filtering by `target_host`/`username`. |
| `cred_store_list` | `target_ip` | `CRED_STORE_LIST: N credential(s) for ip` + `target: username/type confirmed=... (source: ...)` + `ENCRYPTION_AT_REST: ...` or `no credentials stored` | Safe summary, never cleartext. |
| `cred_store_confirm` | `target_ip`, `username`, `target_host=""`, `credential_type=""`, `validated=False` | `CRED_STORE_CONFIRM: confirmed=True for username=... target_host=...` or `no unconfirmed matching credential found` or `BLOCKED: validation required. Pass validated=True ...` | Requires `validated=True` explicit assertion that reuse succeeded (e.g. via `lateral_exec`/`dump_credentials`), otherwise returns `BLOCKED` and flips nothing — never promotes unvalidated harvest. Calls `store.confirm_credential(username, target_host, credential_type, validated=True)` with HMAC-signed `confirmed` flag. |
| `lateral_exec` | `target_ip`, `method="psexec"` (`wmiexec|smbexec|psexec|atexec`), `username=""`, `password=""`, `ntlm_hash=""`, `command=""` | `LATERAL_EXEC_RESULT: completed|failed|timed_out\nATTEMPT_ID: ...\nMETHOD: ...\nTARGET: ...\nUSER: ...\nCOMMAND: ...\nDURATION: ...\nOUTPUT:` | Requires `username` + either `password` or `ntlm_hash` (`32 hex` or `64 hex with colon` `^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?`). Builds argv `["impacket-{method}", "-hashes", ":NT" or "-password", "...", "user@ip", command?]` — no shell, password/hash literal. Runs via `_run_with_pgrp_timeout` (120s). |
| `dump_credentials` | `target_ip`, `method="sam"` (`secretsdump|sam_local|mimikatz|lsass|dcsync`), `username=""`, `password=""`, `ntlm_hash=""`, `domain=""`, `output_file=""`, `target_user=""` | `CRED_DUMP_RESULT: completed|... METHOD: ... TARGET: ...` | `secretsdump`: requires user + secret, builds `impacket-secretsdump domain/user:pass@ip [-hashes :NT]` via argv 300s. `dcsync`: same but `-just-dc [-just-dc-user <user>] -outputfile <attempt_dir>/ntds_hashes`; target must be DC already allowlist-gated. `sam_local`: `reg save HKLM\SAM + SYSTEM + impacket-secretsdump -sam ...` via `bash -c` + `_run_with_pgrp_timeout`. `mimikatz`/`lsass`: `mimikatz.exe` / `procdump` argv 120s. |
| `kerberoast` | `target_ip`, `domain=""`, `username=""`, `password=""`, `ntlm_hash=""`, `dc_ip=""` | `KERBEROAST_RESULT: completed ... DOMAIN: ... DC_IP: ... TARGET: ... TICKETS_FILE: <attempt_dir>/kerberoast_tickets.txt TICKETS_SIZE: N bytes CRACK_COMMAND: hashcat -m 13100 -a 0 file rockyou.txt` | Requires `domain` + either password or hash (`DC_IP` != `target_ip` → `check_targets_allowlist([dc])` pivot lock); `dc` defaults to `target_ip` and validated as IP/FQDN. Builds `["impacket-GetUserSPNs.py", "-dc-ip", dc, "-request", domain/user:pass@ip, "-hashes :NT"?, "-outputfile", tickets_file]` via argv (no shell), 300s. |

## Credential Vault Notes

- **Per-target, not per-attempt** — stable dir `credentials/<ip>/` so creds persist across engagement; `target_ip` validated to prevent path traversal.
- **Encryption:** `CredentialStore` Fernet-encrypts `password` field at rest; `enc` flag surfaced in results.
- **Redaction:** `password` in `_SECRET_ARG_NAMES`, `notes` in `_WHOLESALE_REDACT_FIELDS` — audit log never has cleartext secrets.
- **Confirmed flag:** only set via `cred_store_confirm(validated=True)` after validated reuse; harvested creds never auto-confirmed; `Confirmed` is HMAC-signed.

## Dependencies

- `tools/credential_store.CredentialStore`, `CredentialRecord`
- `tools/kernel/allowlist._allowed_target_list`, `check_targets_allowlist`
- `tools/validation_utils.validate_target_or_ip`, `is_target_in_allowlist`
- `tools/mcp_shared._run_with_pgrp_timeout`, `_attempt_dir`, `shutil.which`

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets`
- `cryptography` package optional for at-rest encryption

## Auditing

All via `@require_allowlist()` + `_redact_args` (password masked, `notes` wholesale). `kerberoast` secondary `dc_ip` gated inside body and also recorded. `BLOCKED` results flip to `approved=False`.

## Tests

- `tests/test_credential_store.py` — vault encryption / dedupe / confirm HMAC
- `tests/test_mcp_injection_hardening.py:208,239,256,413` — `lateral_exec`/`secretsdump`/`kerberoast` argv list literal, `kerberoast` blocks non-target `dc_ip`
- `tests/test_mcp_tool_scope.py` — allowlist scope checks (shared with metasploit)

## Related Docs

- `docs/mcp/tool-families/cracking.md` — offline cracking of `dump_credentials`/`kerberoast` output
- `docs/mcp/tool-families/ad.md` — AD/Kerberos lasso after credential capture
