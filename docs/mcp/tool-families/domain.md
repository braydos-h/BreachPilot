---
title: "Tool Family: domain"
sources:
  - tools/mcp_tools/domain.py
  - tools/validation_utils.py
  - tools/kernel/allowlist.py
  - tools/mcp_shared.py
tests:
  - tests/test_domain_mcp_tools.py
  - tests/test_domain_allowlist.py
  - tests/test_mcp_tool_registration.py
subsystem: mcp
---

# Tool Family: domain

- **Registration source:** `tools/mcp_tools/domain.py:282 register_domain_tools(mcp, *, ctx)` — auto-discovered. Domain-specific attack surface alongside IP tools; all domain-param tools use `@require_allowlist("domain")` (wildcard-aware).
- **Takeover & enumeration:** `enumerate_subdomains` adds discoveries to `EXPLOIT_DISCOVERED_TARGETS` via `add_discovered_target` so agent can attack without per-host config edits; lock preserved.

## Tools Exported (5)

| Tool | Gate | Params | Result Shape | Notes |
|------|------|--------|--------------|-------|
| `resolve_domain` | `@require_allowlist("domain")` | `domain: str`, `record_types: str="A,AAAA,MX,NS,TXT,CNAME,SOA,CAA"` (comma CSV) | `DNS_RESULT: completed\nDOMAIN: ...\nNOTE?: ...\n  A: ...\n  MX: ...` | Bridge primitive. `is_fqdn(domain)` validated; `record_types` split + uppercased defaulting to all 8. Uses `dnspython` when present (`dns.resolver.resolve` per type) else `socket.getaddrinfo` for A/AAAA only + note. Helper `_dns_resolve_all` (`domain.py:237`) + `_stdlib_fetch` (`domain.py:204`) for HTTP. |
| `enumerate_subdomains` | `@require_allowlist("domain")` | `domain`, `sources: str="crt_sh,dns_bruteforce"` (`crt_sh|dns_bruteforce|subfinder|amass` CSV), `max_results: int=500` | `SUBDOMAIN_RESULT: completed\nDOMAIN: ...\nSOURCES: ...\nDISCOVERED: N resolvable\nTAKEOVER_CANDIDATES: M\nSUBDOMAINS:\n  sub -> ip\nTAKEOVER_CANDIDATES:\n  sub (CNAME -> ...): ...\nAUTO_AUTHORIZED: ...` | ~200-word builtin wordlist `_SUBDOMAIN_WORDLIST` (`domain.py:37-89`); `crt_sh` via `crt.sh/?q=%25.domain` (5MB fetch cap to avoid JSON truncation), DNS bruteforce 32-thread `ThreadPoolExecutor` via `resolve_target_to_ip`, `subfinder`/`amass` via `_run_with_pgrp_timeout` when `shutil.which` found. Resolves passively found subs without IP, `add_discovered_target(sub, ip?)` each; unresolvable + CNAME → takeover check against `_TAKEOVER_FINGERPRINTS` (19 services: GitHub Pages, Heroku, S3, Azure, etc. with `suffix` + `body_markers`), HTTP `https` then `http` probe for confirmation → `CONFIRMED takeover -- body matches`. `is_subdomain_of` boundary-aware to avoid `badexample.com` false-positive. |
| `dns_recon` | `@require_allowlist("domain")` | `domain`, `zone_transfer: bool=False` | `DNS_RECON_RESULT: completed\nDOMAIN: ...\nA/AAAA/MX/NS/TXT/SPF/DMARC/SOA/CAA per-type\nDNSSEC: signed|unsigned|unknown\nNS_VERSION: ...\nAXFR: AXFR_SUCCESS|REFUSED|FAILED|SKIPPED|NOT_REQUESTED` + persists `dns_recon.json` | `dnspython` full recon: resolver for `A/AAAA/MX/NS/TXT/SOA/CAA` + SPF (TXT with spf) + DMARC (`_dmarc.domain` TXT) + DS for DNSSEC (presence = signed) + `version.bind` CH/TXT for NS fingerprinting (fixes prior `version.bind.{ns}` bug). AXFR opt-in double-gated: `zone_transfer=True` **and** `recon.dns_zone_transfer: true`; uses `dns.xfr.xfr` or `dns.query.xfr` fallback. Falls back to socket A/AAAA when no dnspython. |
| `vhost_enum` | `@require_allowlist()` (target_ip param) | `target_ip`, `port: int=80`, `domain: str` (required), `wordlist: str=""` (CSV extra prefixes), `timeout: int=300` | `VHOST_RESULT: completed\nTARGET: ip:port\nDOMAIN: ...\nBASELINE_LENGTH/HASH ...\nVHOSTS_FOUND: N\nVHOSTS:\n  vhost (status=..., len vs baseline, hash vs ...)` + `NOTE: HTTPS vhost uses Host header only; SNI not rotated` when https | 28-word builtin + extra prefixes; capped `max_probes = max(1, timeout//10)` probes (10s each). Baseline `Host: target_ip` via `_stdlib_fetch(base_url)`, SHA256 baseline; each `w.domain` probed with `Host: w.domain`; flagged when status or length or content hash differs. `is_fqdn(domain)` validated; `scheme https` for 443/8443. |
| `domain_whois` | `@require_allowlist("domain")` | `domain` | `WHOIS_RESULT: completed\nDOMAIN: ...\nREGISTRAR: ...\nCREATION_DATE: ...\nEXPIRY_DATE: ...\nREGISTRANT_ORG: ...\nDNS_PROVIDER: Cloudflare|AWS Route53|Google|Azure|... (unknown (NS: ...))\nNAMESERVERS:` or `WHOIS_RESULT: unavailable\nInstall python-whois...` | PASSIVE: prefers `python-whois` (`whois.whois`) structured fields (handles `creation_date` list), else `whois` binary via `_run_with_pgrp_timeout`; heuristics parse `Registrar:`, `Creation Date`, `Registry Expiry`, `Registrant Org`, all `Name Server:` lines (collects all, not first). DNS provider derived from NS names. |

## Validation

- Domain tools validate `is_fqdn(dom)` (wildcard `*.` allowed at input); `vhost_enum` validates ip via `validate_target_or_ip`.
- Subdomain boundary via `is_subdomain_of(candidate, parent)` (`tools/validation_utils.py:430`) — suffix `.` + parent, prevents `badexample.com` collision.
- Enumerated hosts auto-authorized via `add_discovered_target`; still gated by `is_target_in_allowlist` on next use.

## Dependencies

- `tools/validation_utils.is_fqdn`, `resolve_target_to_ip`, `is_subdomain_of`, `validate_target_or_ip`, `is_target_in_allowlist`
- `tools/kernel/allowlist._allowed_target_list`, `add_discovered_target`, `check_targets_allowlist`
- `tools/mcp_shared._run_with_pgrp_timeout`, `_attempt_dir`
- Optional: `dnspython`, `python-whois`, `subfinder`, `amass`, `whois` binary

## Config

- `exploit.require_explicit_allowlist`, `exploit.allowed_targets`
- `recon.dns_zone_transfer: bool` — gates `dns_recon` AXFR (default false)
- No per-tool wordlist config; builtin wordlist used.

## Auditing

- Domain tools `@require_allowlist("domain")` with `target_param="domain"` binding → audit records keyed by `domain` string.
- `vhost_enum` allowlist-gated on `target_ip`; writes `started`/`completed|blocked`.

## Tests

- `tests/test_domain_mcp_tools.py` — `resolve_domain`, `enumerate_subdomains` (crt.sh mock, bruteforce, takeover), `dns_recon` branches, `vhost_enum` baseline/hash diff, `domain_whois` parse
- `tests/test_domain_allowlist.py` — wildcard + subdomain boundary
- `tests/test_mcp_tool_registration.py` — at least domain tools implicitly via total

## Related Docs

- `docs/mcp/security.md` — auto-authorization via `EXPLOIT_DISCOVERED_TARGETS`
- `docs/mcp/tool-families/recon.md` — IP recon counterpart
