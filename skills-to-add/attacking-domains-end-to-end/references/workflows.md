# Workflows — Attacking Domains End-to-End

## Workflow 1: Quick domain attack-surface assessment (15 min)

```
1. resolve_domain("target.com")
   → get primary IP

2. enumerate_subdomains("target.com", sources="crt_sh,dns_bruteforce")
   → discover subdomains + takeover candidates

3. dns_recon("target.com")
   → zone transfer attempt, DNSSEC, MX/NS/TXT

4. domain_whois("target.com")
   → registrar, dates, DNS provider

5. For each web subdomain:
   run_web_scan("nikto", subdomain, 80)
   run_web_scan("nuclei", subdomain, 443)

6. Report takeover candidates immediately
```

## Workflow 2: Full domain exploitation (1-4 hours)

```
1. Phases 1-4 from the SKILL.md methodology (resolve, enumerate, DNS, WHOIS)

2. For each discovered subdomain with a resolved IP:
   run_full_recon(ip)
   → open ports + services

3. For each web service:
   run_web_scan("nuclei", subdomain, port)
   run_web_scan("gobuster", subdomain, port)
   → vulnerabilities + hidden content

4. vhost_enum(ip, port, domain="target.com")
   → virtual hosts on the same IP

5. For each confirmed vuln:
   run_attack_module(module_name, target_ip=subdomain_ip, ...)
   → exploit

6. Cross-reference creds/sessions across the domain family
   → pivot from a forgotten subdomain to the main domain
```

## Workflow 3: Subdomain takeover audit (30 min)

```
1. enumerate_subdomains("target.com", sources="crt_sh")
   → focus on TAKEOVER_CANDIDATES in the output

2. For each candidate (unresolvable + CNAME to known service):
   - GitHub Pages: create repo named <subdomain>, enable Pages
   - Heroku: create app named <subdomain>.herokuapp.com
   - AWS S3: create bucket named <subdomain>
   - Azure: create web app at <subdomain>.azurewebsites.net

3. Verify the claim routes to your content → confirmed takeover

4. Report as critical (CVSS 9.8) -- the trusted domain serves attacker content
```