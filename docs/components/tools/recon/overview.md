---
title: Recon — Overview
packages: [tools/recon, tools/recon_pipeline.py, tools/recon_enrichers.py, tools/recon_osint.py, tools/recon_diff.py, tools/fast_recon.py, tools/socket_scan.py, tools/nmap_priv.py]
symbols: [ReconPipeline, PrimaryReconScanner, SecondaryEnumerator, ReconConfig, HostReconResult, ServiceInfo, ToolAvailability, parse_tls_info, parse_udp_nmap_output, http_spider, run_osint, diff_recon, FastReconCoordinator, socket_scan, apply_nmap_privilege]
---

# Recon — Overview

Adaptive, fallback-enabled scanning. Canonical pipeline: `tools/recon_pipeline.py` (2385 LOC god file, now shimmed by `tools/recon/*`).

## Package map

| File | Export | Line | Role |
|---|---|---|---|
| `tools/recon/pipeline.py` | `ReconPipeline` | 22 | Orchestrator: `recon_host` → primary+secondary |
| `tools/recon_pipeline.py` | `ReconConfig, HostReconResult, ServiceInfo, ToolAvailability, PrimaryReconScanner, SecondaryEnumerator` | 50+ | Data + primary/secondary impl |
| `tools/recon/config.py` | re-export shim | 3 | `from tools.recon_pipeline import ReconConfig` |
| `tools/recon/scanner.py` | re-export shim | 3 | `PrimaryReconScanner` |
| `tools/recon_enrichers.py` | `parse_tls_info, parse_smtp_banner, parse_db_banner, parse_udp_nmap_output, http_spider` | — | Pure parsing + bounded spider |
| `tools/recon_osint.py` | `run_osint, passive_ipv6_lookup, reverse_dns, crtsh_cert_transparency, shodan_lookup` | — | Passive public-source OSINT |
| `tools/recon_diff.py` | `diff_recon, diff_recon_files` | 94,202 | Pure diff of two `HostReconResult.to_dict()` |
| `tools/fast_recon.py` | `FastReconCoordinator, FastReconConfig, FastReconResult` | 337,58 | Dependency-aware parallel preset |
| `tools/socket_scan.py` | `socket_scan, probe_reachable, COMMON_PORTS` | 200,163 | No-privilege TCP fallback |
| `tools/nmap_priv.py` | `apply_nmap_privilege, _downgrade_unprivileged_args, is_privilege_error` | 70,39,105 | Root handling |

## Data structures (`recon_pipeline.py:50-214`)

| Type | Fields | Notes |
|---|---|---|
| `ServiceInfo` | `port, protocol, service, version, banner, cpe[], scripts{}, ssl_info, smtp_info, db_info, os_guess, confidence, technologies[]` | `to_dict`/`from_dict` round-trip |
| `HostReconResult` | `target_ip, hostname, os_name/family/accuracy, ttl, mac/vendor, services[], open/ filtered/ udp_ports[], scan_duration/tool/raw_output, evidence_refs, errors/warnings, spider_results[], osint{}, ipv6_addresses[], extended{}` | `get_services_by_name/port`, `has_service/port`, `from_dict` for resume |
| `ReconConfig` | `nmap/rustscan/masscan/nikto/feroxbuster/… paths, timeout_seconds(300), max_retries(2), aggression_level, stealth_options, wordlist_path, fallback_enabled, parallel_secondary, sudo/priv_fallback, udp_top_ports(100), extended_enumerators, shodan_api_key, subdomain_enum/vhost/waf/asn/cloud/snmp/dns_zone flags, preflight_probe/ports/timeout` | `from_config(config, **overrides)` reads `nmap.*` + `recon.*` |
| `ToolAvailability` | `check(tool_name)`, `reset()` | `shutil.which` cache |

## `ReconPipeline` (`tools/recon/pipeline.py:22`)

| Method | Line | Description |
|---|---|---|
| `recon_host(target)` | 38 | Preflight probe (opt-in) → `PrimaryReconScanner.scan_host` → `SecondaryEnumerator.enumerate_host` if `open_ports` |
| `recon_hosts(targets)` | 92 | `asyncio.gather` |
| `recon_udp(target, top_ports)` | 98 | Delegates to `PrimaryReconScanner.recon_udp` |
| `get_attack_surface_summary(result)` | 110 | `{services_by_name, high_value_targets, credential_targets, web_targets, lateral_movement_targets, privilege_hints, recommended_attack_modules via find_modules}` |

`ReconConfig.from_config` defaults: `extended_enumerators=True` in production (dataclass default `False` preserves test behavior), `shodan_api_key` from `recon.shodan_api_key` or `SHODAN_API_KEY` env, each depth flag opt-in.

## `PrimaryReconScanner` (`recon_pipeline.py:488-1082`)

- `scan_host(target)` – Nmap comprehensive (`-sS -sV -O -Pn -T4 --script=vuln,default -p- -oX -`) → RustScan → Masscan → `socket_scan(COMMON_PORTS)` pyramid; `_run_nmap` applies `apply_nmap_privilege`, downgrades once on `is_privilege_error` when `priv_fallback` off, parses XML then grepable fallback, TTL→`os_family`.
- `_run_nmap_udp` / `recon_udp` (`:671-787`) – `-sU --top-ports N -sV --script=default,vuln`, parses via `recon_enrichers.parse_udp_nmap_output`.
- `_run_rustscan` / `_run_masscan` – port discovery + Nmap service follow-up; `run_command` wrapper (`:405`) handles retries with `is_privilege_error` / `_NON_RETRYABLE_EXIT_CODES` short-circuit (3221225477 etc. on Windows).
- Preflight probe (`pipeline.py:52`) – `socket_scan.probe_reachable(ports)`: `False`→skip full scan, `None`→ambiguous proceed.

## `SecondaryEnumerator` (`recon_pipeline.py:1090+`)

`enumerate_host(result)` fans out coroutines per detected service family, gated by `ToolAvailability`, bounded by semaphore (fix for Task-precreation). Coroutines mutate shared `result` in place. Families: http (Nikto/Feroxbuster/Nuclei/SQLMap), ssh, smb, ldap, ftp, redis, elasticsearch, docker/k8s, rdp, plus Phase 3 additive `extended_enumerators` block: TLS, SMTP, DB, web spider, OSINT (`run_osint`), plus depth flags: `subdomain_enum`, `vhost_discovery`, `waf_fingerprint`, `asn_whois`, `cloud_metadata_probe`, `snmp_enum`, `dns_zone_transfer` (each opt-in).

## `recon_enrichers.py` (693 LOC, pure helpers)

| Function | Input | Output | Notes |
|---|---|---|---|
| `parse_tls_info(raw:str\|dict)` | nmap ssl-cert text or JSON | `{issuer,subject,san[],valid_from/to,protocol,cipher}` | Never raises; deduped SAN |
| `parse_smtp_banner(banner)` | EHLO/220 text | `{server_software, supports_starttls, auth_methods[], banner}` | |
| `parse_db_banner(banner, service)` | DB handshake | `{db_type, version, auth_required, banner}` | redis/mongo/mssql/postgres/mysql |
| `parse_udp_nmap_output(raw)` | nmap -oG or -oX UDP output | `[{port,protocol:"udp",service,state,banner}]` | Skips closed/filtered |
| `http_spider(target_ip,port,scheme,max_pages,fetch_fn)` | target only | `{urls_visited,links,forms,status_codes,technologies}` | Bounded BFS 20, injectable fetch, never raises |

## `recon_osint.py` (222 LOC, passive only)

| Function | Description |
|---|---|
| `passive_ipv6_lookup(host, resolver_fn)` | `getaddrinfo(AF_INET6)` → `[]` on error |
| `reverse_dns(ip, resolver_fn)` | `gethostbyaddr` |
| `crtsh_cert_transparency(domain, fetch_fn)` | `https://crt.sh/?q=%25<domain>&output=json` |
| `shodan_lookup(ip, api_key, fetch_fn)` | `https://api.shodan.io/shodan/host/{ip}?key=`; disabled when no key |
| `run_osint(target_ip, hostname, shodan_api_key, resolver_fn, fetch_fn)` | Aggregates reverse→hostname→AAAA+CT+Shodan; never raises |

## `recon_diff.py` (214 LOC, pure)

`diff_recon(old:dict, new:dict) → {target_ip, added/removed_ports, changed_services[{port,service,field,old,new}], new/lost_cves[], os_changed, old/new_os, summary}` (`:94`). `diff_recon_files(old_path,new_path)` (`:202`) → `{"error":…}` on IO/JSON fail. CVE regex `CVE-\d{4}-\d{4,}` mirrors `mcp_tools/attack_modules.py:1187`.

## `fast_recon.py` (812 LOC) — parallel preset

`FastReconConfig.from_config` (`:58`): `enabled, max_concurrency(8), service_concurrency(6), cve_concurrency(8), per_task_timeout(60), overall_timeout(180), tcp_discovery, udp_top_ports(50), passive_osint, service_enumeration, cve_lookup, cache_ttl(300)`.

Stage A parallel: `check_os | quick_scan | run_osint_recon | run_udp_recon` → parse `open_ports/services/os`; short-circuit on empty. Stage B: bounded `get_service_fingerprint` per port + deduped `search_cve_intel` per `product version` (cache per-run). Writes `fast_recon.json` + `recon_assessment.json` (`build_assessment_from_mcp_results`) + `.fast_recon_cache/{sha16}.json`. `FastReconCoordinator.run` handles per-task `asyncio.wait_for`, `_EXC_GROUP_CATCH`, `return_exceptions=True`, global `asyncio.wait_for(overall_timeout)` partial on timeout.

`FastReconResult` carries `open/udp_ports, services, os, cves, web, osint, warnings/errors, coverage, task_timings, cache_hit, assessment, summary_text` (`:99`).

## `socket_scan.py` (224 LOC)

`COMMON_PORTS` 27 ports (`:19`), `_SERVICE_GUESS` map, `_probe_port` (double-connect + banner recv), `socket_scan_sync` (sync multi), `_connect_status → open/refused/unknown` via `_REFUSED_ERRNOS` (ECONNREFUSED/EHOSTUNREACH/ENETUNREACH/EADDRNOTAVAIL), `probe_reachable(ports, timeout=1)→ True|False|None` (False only when all `refused`), async `socket_scan` via `run_in_executor`, `format_socket_scan_results` (`QUICK_SCAN_RESULTS` text).

## `nmap_priv.py` (112 LOC)

`_NMAP_ROOT_FLAGS = {-O,-sS,-sX,-sN,-sF,-sA,-sM}`; `_is_privileged()` (euid==0 or Windows); `_downgrade_unprivileged_args(args)` replaces `-sS→-sT`; `apply_nmap_privilege(argv, sudo, priv_fallback)` – privileged→unchanged, `sudo→sudo -n` prefix, `priv_fallback→downgrade`, else unchanged; `is_privilege_error(stderr)` via `_PRIV_ERROR_RE` (requires root/raw socket/permission denied).

## Config keys

| Key | Module |
|---|---|
| `nmap.path` / `sudo` / `priv_fallback` | `nmap_priv.py` + `_run_nmap` |
| `recon.enabled` / `extended_enumerators` / `shodan_api_key` | `ReconConfig.from_config` |
| `recon.subdomain_enum` / `vhost_discovery` / `waf_fingerprint` / `asn_whois` / `cloud_metadata_probe` / `snmp_enum` / `dns_zone_transfer` | Depth flags |
| `recon.udp_top_ports` / `preflight_probe` / `preflight_ports/ timeout` / `max_retries/retry_delay/timeout_seconds` | Pipeline |
| `recon.fast.*` (`max_concurrency` etc., `enabled`, `cache_ttl_seconds`) | `FastReconCoordinator` |
| `cve_lookup.*` (separate NVD client, not recon) | `tools/cve_lookup.py` |

## Tests

| File | Verified | Covers |
|---|---|---|
| `tests/test_recon_pipeline.py` | yes | `PrimaryReconScanner`, fallback chain, XML parse |
| `tests/test_recon_enrichers.py` | yes | `parse_tls/smtp/db/udp`, `http_spider` |
| `tests/test_recon_osint.py` | yes | `run_osint`, passive helpers, mock inject |
| `tests/test_recon_diff.py` | yes | `diff_recon` ports/CVEs/ports/services |
| `tests/test_fast_mode.py` / `tests/test_recon_spider_osint.py` | yes | `FastReconCoordinator` stages + cache + timeout |
| `tests/test_socket_scan.py` | yes | `probe_reachable`, `socket_scan`, format |
| `tests/test_nmap_priv.py` | yes | `apply_nmap_privilege`, `is_privilege_error`, downgrade |
| `tests/test_recon_udp_tls_smtp_db.py` | yes | UDP+TLS+SMTP+DB enrichers |
| `tests/test_recon_extended_enumerators.py` | yes | Depth enumerators |
| `tests/test_recon_mcp_new_tools.py` | yes | MCP `run_*_recon` wiring |
| `tests/test_recon_event_and_allowlist.py` | yes | Events + allowlist gating |
