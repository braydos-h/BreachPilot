---
name: attacking-domains-end-to-end
description: End-to-end domain attack methodology -- resolve, enumerate subdomains,
  run DNS recon, check for subdomain takeover, scan web apps, and exploit across the
  full domain attack surface. Orchestrates the domain-specific MCP tools.
domain: cybersecurity
subdomain: web-application-security
tags:
- domain-attack
- subdomain-enumeration
- dns-recon
- subdomain-takeover
- attack-surface
- web-application-security
- reconnaissance
- exploitation
version: '1.0'
nist_csf:
- ID.RA-01
- DE.CM-01
- PR.DS-10
mitre_attack:
- T1595
- T1592
- T1190
- T1059.007
- T1505.003
---

# Attacking Domains End-to-End

## When to Use
- When the operator targets a domain (e.g. `--target example.com`) instead of a bare IP
- When the assessment is an attack-surface engagement, not a single-host pentest
- When subdomain takeover is in scope (forgotten subdomains pointing at deprovisioned services)
- When DNS intelligence (zone transfers, DNSSEC, MX/NS/TXT/SPF/DMARC) would inform the attack path
- When virtual host enumeration on a web server could reveal additional applications

## Prerequisites
- The operator must own or be explicitly authorized to test the target domain and ALL its subdomains
- `config.yaml` `exploit.allowed_targets` accepts domains and `*.wildcard` entries (e.g. `*.example.com`)
- `dnspython` (optional, `pip install dnspython`) for full DNS recon / zone transfers / CNAME lookups
- `subfinder` / `amass` (optional) for richer subdomain enumeration
- `python-whois` or `whois` binary (optional) for WHOIS lookups

## Methodology

### Phase 1: Resolve the domain
Call `resolve_domain("example.com")` to get the A/AAAA records. This is the bridge
primitive -- every subsequent tool uses the resolved IP for IP-based tools and the
domain for web tools. If the domain resolves to a CDN/WAF (Cloudflare, AWS CloudFront),
note it: the IP is shared infrastructure, not the origin. Look for the origin IP via
DNS history, SPF records, and MX records.

### Phase 2: Enumerate subdomains
Call `enumerate_subdomains("example.com", sources="crt_sh,dns_bruteforce,subfinder,amass")`.
This discovers the full attack surface. Each discovered subdomain is auto-authorized
(added to the allowlist) so you can attack it without a per-host config edit. Pay
attention to:
- **Takeover candidates**: subdomains that don't resolve but have a CNAME pointing at a
  deprovisioned service (GitHub Pages, Heroku, S3, Azure, Shopify, etc.) -- these are
  subdomain-takeover vulnerabilities.
- **Non-standard ports**: subdomains running services on unexpected ports (8080, 8443,
  9090) are often less-hardened dev/staging environments.
- **Forgotten environments**: `dev.`, `staging.`, `test.`, `qa.` subdomains often have
  weaker authentication, debug endpoints, and default creds.

### Phase 3: DNS reconnaissance
Call `dns_recon("example.com", zone_transfer=True)` (requires `recon.dns_zone_transfer:
true` in config). Look for:
- **AXFR zone transfer**: if the nameserver allows it, you get the entire DNS zone --
  every internal hostname, every subdomain, every service record. This is a
  misconfiguration; report it.
- **DNSSEC status**: if disabled, the domain is vulnerable to DNS spoofing/cache poisoning.
- **SPF/DMARC**: a missing or misconfigured SPF/DMARC record means the domain is
  vulnerable to email spoofing (useful for social-engineering prerequisites).
- **MX records**: mail servers are high-value targets (Exchange, O365, Postfix) and
  often expose RCE or credential-spray surfaces.
- **NS version**: a nameserver running an old BIND/unbound version may have known CVEs.

### Phase 4: WHOIS intelligence
Call `domain_whois("example.com")` for registrar, creation/expiry dates, registrant
org, and DNS provider. Useful for:
- **Age**: a domain registered < 1 year ago is more likely a dev/test domain.
- **DNS provider**: Cloudflare-proxied domains hide the origin IP; you'll need DNS
  history (SecurityTrails, VirusTotal) to find the real backend.
- **Registrant org**: matches the target's real-world identity for reporting.

### Phase 5: Per-subdomain recon
For each discovered subdomain with a resolved IP, run `run_full_recon("<ip>")` to get
open ports and services. Prioritize:
- Web services (80/443/8080/8443) -- run `run_web_scan` next.
- SSH (22) -- check for weak creds / known CVEs.
- SMB (445) -- use `lateral_exec`, `dump_credentials`, or `kerberoast` if it's a DC.
- Databases (3306/5432/27017/6379) -- check for default creds / unauth access.

### Phase 6: Web scanning
For each web service, run `run_web_scan(scanner, target_ip, port)` with the **domain**
(not the IP) as the target where possible, so the scanner sends proper Host headers:
- `nikto` -- web server misconfigurations / outdated software
- `nuclei` -- template-based vulnerability scanning (CVEs, misconfig, exposures)
- `sqlmap` -- SQL injection (feed it a URL with a parameter)
- `gobuster` / `feroxbuster` -- directory/content discovery
- `whatweb` -- technology fingerprinting
- `wpscan` -- WordPress enumeration (if WordPress detected)

### Phase 7: Virtual host enumeration
On web servers that host multiple sites, call
`vhost_enum(target_ip, port, domain="example.com")`. This sends rotated `Host:` headers
and compares response bodies. A different response indicates another virtual host on the
same IP -- often an internal admin panel, a staging site, or a forgotten app.

### Phase 8: Subdomain takeover verification
For each takeover candidate from Phase 2 (unresolvable subdomain with a CNAME to a
deprovisioned service), verify by attempting to claim the resource:
- **GitHub Pages**: create a repo named `<subdomain>` and enable Pages -- if it serves
  your content, the takeover is confirmed.
- **Heroku**: create an app named `<subdomain>.herokuapp.com` -- if it routes to your
  app, confirmed.
- **AWS S3**: create a bucket named `<subdomain>` -- if it serves your content, confirmed.
- **Azure**: create a web app at `<subdomain>.azurewebsites.net` -- confirmed.
Report each confirmed takeover immediately -- these are often critical.

### Phase 9: Exploitation
Use the standard attack modules (`run_attack_module`, `craft_exploit`, `run_msf_module`)
against discovered services. Cross-reference findings across the domain family:
- **Shared credentials**: a cred found on `dev.example.com` often works on
  `www.example.com` and `api.example.com`.
- **Shared backend**: a SSRF on `app.example.com` can reach `internal.example.com`
  (which may not be publicly routable).
- **Shared sessions**: a JWT from `auth.example.com` may be accepted by
  `api.example.com` and `admin.example.com`.
- **API keys in frontend JS** on `www.example.com` may reference `api.example.com`
  endpoints with elevated privileges.

### Phase 10: Cross-reference and chain
- A forgotten subdomain with an old framework version (e.g. Spring Boot 1.x on
  `old.example.com`) may have RCE that gives you a foothold, then pivot to the main
  domain via shared credentials or network access.
- A subdomain takeover can serve malware/phishing to employees of the target org
  (the domain is trusted), or intercept password-reset emails if the subdomain is
  referenced in MX/SPF records.

## Tool Reference

| Tool | Purpose | Source |
|------|---------|--------|
| `resolve_domain` | Forward DNS (A/AAAA/MX/NS/TXT/CNAME/SOA/CAA) | This repo (new) |
| `enumerate_subdomains` | Subdomain discovery + takeover detection | This repo (new) |
| `dns_recon` | Full DNS intel (AXFR, DNSSEC, NS version, SPF/DMARC) | This repo (new) |
| `vhost_enum` | Virtual host enumeration via Host-header rotation | This repo (new) |
| `domain_whois` | WHOIS + DNS provider profiling | This repo (new) |
| `run_full_recon` | Per-host port/service scan | This repo (existing) |
| `run_web_scan` | Web scanner (nikto/nuclei/sqlmap/gobuster/...) | This repo (existing) |
| `run_attack_module` | Web-app probes (JWT/SSTI/GraphQL/SSRF/XXE/...) | This repo (existing) |
| `run_msf_module` | Metasploit exploit/auxiliary modules | This repo (existing) |

## Notes
- The target-IP lock now locks to a **set** (domain + resolved IP + discovered
  subdomains) instead of a single IP. Every member of the set is still
  operator-authorized; the lock model is preserved.
- Use the **domain** for HTTP Host headers / TLS SNI / curl --resolve so the target
  server serves the correct virtual host and the TLS certificate validates.
- Use the **IP** for nmap / metasploit RHOSTS / hydra / smbclient / impacket -- these
  tools work at the network layer and don't care about Host headers.
- Subdomain takeover is time-sensitive: once you confirm a takeover candidate, claim
  it quickly before the provider patches the dangling delegation or another researcher
  takes it.