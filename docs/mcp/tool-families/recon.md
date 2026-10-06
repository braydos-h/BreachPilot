---
title: "Tool Family: recon"
sources:
  - tools/mcp_tools/recon.py
  - tools/recon_pipeline.py
  - tools/recon_osint.py
  - tools/recon_diff.py
tests:
  - tests/test_recon_dns_pinning.py
  - tests/test_recon_mcp_new_tools.py
subsystem: mcp
---

# Tool Family: recon

- **Registration source:** `tools/mcp_tools/recon.py:register_recon_tools` — auto-discovered; no edit to `mcp_exploit_server.py`.
- **Gate:** all 7 tools use `@require_allowlist()` (target-IP lock + audit trail).

## Tools Exported (7)

| Tool | Params | Target access and result |
|------|--------|--------------------------|
| `check_os` | `target_ip: str` | Runs a bounded Nmap TCP connect/light-version scan of the common ports in the sandbox worker. Returns a cautious OS hint from service metadata; TTL and privileged OS probes are not collected. |
| `quick_scan` | `target_ip: str`, `ports: str` | Runs a bounded Nmap TCP connect/light-version scan in the worker and reports ports Nmap marks open. Accepts up to 1000 distinct ports. |
| `run_full_recon` | `target_ip: str`, `aggression: str="normal"` | Runs a worker Nmap TCP scan and saves the parsed result. Stealth scans the top 1000 ports; normal/aggressive scan all TCP ports, with the aggressive profile enabling the `default,vuln` NSE categories. It does not run the legacy secondary enumerators or claim raw-socket OS detection. |
| `get_service_fingerprint` | `target_ip: str`, `port: int` | Runs a worker Nmap TCP service/version probe for one port. TLS ports also use Nmap's `ssl-cert` script; the operator process does not open sockets or perform a TLS handshake. |
| `run_udp_recon` | `target_ip: str`, `top_ports: int=100` | Returns `SANDBOX_UNSUPPORTED`. The hardened worker drops `NET_RAW`, required for reliable Nmap UDP semantics. No scan or host fallback is attempted. |
| `run_osint_recon` | `target_ip: str` | Bounded passive lookups against fixed public providers: reverse DNS, AAAA DNS, certificate transparency, and optional Shodan. It does not actively connect to or scan the target. |
| `diff_recon_runs` | `old_path: str`, `new_path: str` | Compares saved recon snapshots without touching a target. The allowlist decorator is retained for consistent auditing. |

## Target validation and pinning

Every tool is gated by the existing MCP target allowlist lock. Active TCP tools then:

1. Validate an IPv4, IPv6, or FQDN target and resolve it once with the bounded resolver.
2. Reject metadata and link-local destinations. A hostname resolving to a non-public address also requires that concrete IP or containing CIDR to be separately allowlisted.
3. Pass the original authorized target to the sandbox scope gate and place only the resolved IP literal in the fixed Nmap argv, preventing Nmap from performing a second DNS lookup.
4. Return a structured error on worker failure, timeout, unsuccessful Nmap exit, or missing XML. They never retry on operator-host sockets or subprocesses.

## Result details

- Nmap XML is parsed into the recon result model. A missing service record means “not reported open”; it is not presented as proof that a port is closed.
- `check_os` reports `TTL: N/A`; its service-metadata scores are hints, not an OS fingerprint.
- `run_full_recon` records the worker-only scan result and a warning that service-specific secondary enumeration was not run.
- The configured `recon.timeout_seconds` is bounded to 5–1800 seconds for full scans. Short scans have fixed timeouts.
- MCP scans invoke the worker image's `nmap` binary. Host-side `nmap.path`,
  `nmap.sudo`, and `nmap.priv_fallback` settings apply to direct
  `ReconPipeline` callers and do not change these fixed worker argv.
- Passive OSINT has a 45-second total limit, at most four concurrent resolver workers, 15-second provider request timeouts, and a 2 MiB response cap.

## Separation from the in-process pipeline

The campaign start/step handlers and opt-in swarm ReconAgent use the same
`sandbox_recon_host` adapter as `run_full_recon`; they do not fall back to
`ReconPipeline` if the worker is unavailable. `ReconPipeline` remains a direct
Python/library API with its own scanner behavior, but the agent-facing MCP
entrypoints do not call it for target-active recon.

## Tests

- `tests/test_recon_dns_pinning.py` — DNS pinning, private/metadata rejection, worker routing, no-worker fail-closed behavior, and passive OSINT.
- `tests/test_recon_mcp_new_tools.py` — MCP result shapes and explicit UDP unsupported behavior.
- `tests/test_sandbox_family_audit.py` — recon is registered as a sandboxed worker-process family.
