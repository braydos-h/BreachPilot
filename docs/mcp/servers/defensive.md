---
title: Defensive MCP Server (mcp_server.py)
sources:
  - mcp_server.py
  - tools/mcp_shared.py
  - tools/validation_utils.py
  - tools/nmap_priv.py
tests:
  - tests/test_linux_support.py
  - tests/test_scope_gate.py
subsystem: mcp
---

# Defensive MCP Server

Legacy scope-enforced scanner at `mcp_server.py:1-374`. Mirrors `mcp_exploit_server.py` structure but exposes only the defensive surface. All tools require the caller to supply an asset approved in mission scope; out-of-scope requests return `{ok: False, error: ...}`.

## Server Identity

- FastMCP name: `ai-nmap-defensive` (`mcp_server.py:228`)
- Transports: `stdio` (default) or `http` (`mcp_server.py:345-349`, `mcp_server.py:362-369`)
- Default HTTP port: `8000` (`mcp_server.py:348`)
- CLI: `python mcp_server.py --transport stdio|http --config config.yaml --host 127.0.0.1 --port 8000 [--allow-public-bind]`
- HTTP serving delegates to `tools.mcp_shared.run_mcp_http_server` (`mcp_server.py:369`) — loopback gate + optional `MCP_HTTP_TOKEN` bearer auth

## Factory

`create_mcp_server(*, nvd, researcher, config, allow)` (`mcp_server.py:195-335`):

- Normalizes allowlist via `_normalize_allowlist` (`mcp_server.py:60-75`): strips blanks/comments, dedupes
- Reads `config["research"]["allowed_assets"]` when `allow` not supplied (`mcp_server.py:213-214`)
- Reads `config["nmap"]` → module globals `_NMAP_BINARY`, `_NMAP_USE_SUDO`, `_NMAP_PRIV_FALLBACK` (`mcp_server.py:222-226`)
- Builds `FastMCP("ai-nmap-defensive")` and registers 8 tools as closures capturing `allowlist`, `default_timeout`, `nvd`, `researcher`

## Scope Gate

`_is_in_allowlist(asset, allow)` (`mcp_server.py:78-108`):

1. Delegates IP / wildcard / IP-in-CIDR to `tools.validation_utils.is_target_in_allowlist` (`tools/validation_utils.py:380-420`)
2. Handles CIDR-subset-of-CIDR: `10.0.0.0/24` is accepted when allow contains `10.0.0.0/16` via `ip_network.subnet_of` (`mcp_server.py:96-107`)

Every tool checks this gate before running Nmap or accepting a command token.

## Nmap Runner

`_run_nmap(args, timeout)` (`mcp_server.py:133-189`):

- Applies privilege helpers `apply_nmap_privilege([_NMAP_BINARY, *args], sudo, priv_fallback)` (`tools/nmap_priv.py` via `mcp_server.py:124-130`)
- `priv_fallback=True` downgrades `-O`/`-sS` etc. when unprivileged and `nmap.sudo` is off; `sudo=True` runs via `sudo -n` (non-interactive)
- Offloads `subprocess.run` to `asyncio.to_thread` so event loop is not blocked under HTTP
- Returns `{ok, stdout, stderr, exit_code, duration_s}`; appends `downgrade_note` to `stderr` when flags were downgraded; handles `FileNotFoundError` and `TimeoutExpired`

## Tools (8)

| Tool | Signature | Gate | What it runs |
|------|-----------|------|--------------|
| `run_nmap_ping_sweep` | `(subnet: str) -> dict` | `_is_in_allowlist(subnet)` | `nmap -sn -T4 <subnet>` (`mcp_server.py:231-240`) |
| `run_nmap_triage_scan` | `(subnet: str, top_ports: int=100) -> dict` | `_is_in_allowlist(subnet)` | `nmap -sS --top-ports N -T4 <subnet>` (`mcp_server.py:243-251`) |
| `run_nmap_basic_scan` | `(ip: str) -> dict` | `validate_ipv4(ip)` + allowlist | `nmap -sV -T4 <ip>` (`mcp_server.py:254-259`) |
| `run_nmap_service_scan` | `(ip: str) -> dict` | `validate_ipv4(ip)` + allowlist | `nmap -sV -sC -O -T4 <ip>` (`mcp_server.py:262-270`) |
| `run_nmap_vuln_scan` | `(ip: str) -> dict` | `validate_ipv4(ip)` + allowlist | `nmap -sV --script vuln -T4 <ip>` (`mcp_server.py:273-278`) |
| `run_limited_terminal` | `(command: str) -> dict` | `preflight_command_check` + allowlist pattern + per-IP allowlist | Allowlisted Nmap shapes only (`mcp_server.py:281-311`) |
| `search_vulnerability_intel` | `(query: str) -> str` | API-key gate | `researcher.search(query)` sanitized (`mcp_server.py:314-322`) |
| `search_cve_intel` | `(query: str) -> str` | — | `nvd.search_sync(query) -> format_cve_results` (`mcp_server.py:325-333`) |

### `run_limited_terminal` allowlist

`preflight_command_check` must pass (`mcp_server.py:291-292`), then command must match one of (`mcp_server.py:294-303`):

- `^nmap\s+-sn\b`, `-sV`, `-sC`, `-O`, `-sS`, `-sT`, `-A`, `--script`

Then every IPv4/CIDR token extracted via `re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")` must be in allowlist (`mcp_server.py:308-310`); sanitized command is split and passed to `_run_nmap` (`mcp_server.py:311`).

## Config Keys

- `research.allowed_assets: list[str]` — scope allowlist
- `research.nmap_timeout_seconds: int` — default 300 (`mcp_server.py:217`)
- `nmap.path: str` — binary path, default `nmap`
- `nmap.sudo: bool` — run via `sudo -n`
- `nmap.priv_fallback: bool` — auto-downgrade privileged flags when unprivileged (default true)
- `research.serpapi` / `cve_lookup` blocks for researcher/NVD wiring via `tools/mcp_shared.build_*`

## Dependencies

- `tools/mcp_shared.build_cve_search` / `build_researcher` / `load_config` / `run_mcp_http_server`
- `tools/validation_utils` — `is_target_in_allowlist`, `preflight_command_check`, `sanitize_target_in_command`, `validate_ipv4`
- `tools/nmap_priv` — `_NMAP_ROOT_FLAGS`, `_downgrade_unprivileged_args`, `apply_nmap_privilege`, `is_privilege_error`

## Related Docs

- `docs/mcp/overview.md`
- `docs/mcp/security.md` — allowlist and validation detail
- `docs/mcp/lifecycle.md` — HTTP hardening shared with this server
