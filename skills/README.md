# NetAttackAI Skill Catalog

Curated for NetAttackAI: a local AI-assisted penetration testing and bug bounty assistant for authorized targets. This folder now contains only direct-fit skills; original skill contents were not edited.

## Retained for NetAttackAI

### Core methodology, scope, recon, and workflow

- `conducting-network-penetration-test` - end-to-end authorized network pentest workflow with scope validation, nmap, exploitation, logging, and reporting.
- `conducting-internal-network-penetration-test` - internal network assessment workflow aligned with service discovery and controlled exploitation.
- `conducting-external-reconnaissance-with-osint` - external recon process for authorized scopes and bug bounty targets.
- `conducting-full-scope-red-team-engagement` - high-level engagement planning, scope, safety, execution, and reporting model.
- `executing-red-team-engagement-planning` - planning structure for rules of engagement, approvals, objectives, and constraints.
- `executing-red-team-exercise` - controlled exercise execution model useful for attack-path planning and audit trails.
- `scanning-network-with-nmap-advanced` - direct match for advanced nmap discovery, service enumeration, NSE checks, and structured outputs.
- `performing-external-network-penetration-test` - external network testing workflow with recon, searchsploit, and exploit validation.
- `performing-agentless-vulnerability-scanning` - vulnerability discovery without endpoint agents, useful for authorized target assessments.
- `performing-authenticated-vulnerability-scan` - authenticated scanning workflow for validated findings and reduced false positives.
- `performing-authenticated-scan-with-openvas` - OpenVAS workflow for vulnerability discovery and validation.
- `scanning-infrastructure-with-nessus` - infrastructure vulnerability scanning workflow.
- `performing-vulnerability-scanning-with-nessus` - Nessus scan execution and triage for CVE-driven findings.
- `building-vulnerability-scanning-workflow` - reusable workflow design for scan orchestration.
- `building-vulnerability-dashboard-with-defectdojo` - finding intake, deduplication, and dashboarding for vulnerability management.
- `building-vulnerability-aging-and-sla-tracking` - tracking vulnerability age, ownership, and remediation targets.
- `building-vulnerability-exception-tracking-system` - exception and risk-acceptance tracking for findings.
- `triaging-vulnerabilities-with-ssvc-framework` - structured vulnerability triage and decision support.
- `prioritizing-vulnerabilities-with-cvss-scoring` - CVSS-based vulnerability severity scoring.
- `implementing-epss-score-for-vulnerability-prioritization` - EPSS likelihood scoring for exploitability prioritization.
- `performing-asset-criticality-scoring-for-vulns` - asset context scoring to prioritize findings.
- `performing-cve-prioritization-with-kev-catalog` - KEV-driven CVE prioritization.
- `implementing-threat-intelligence-lifecycle-management` - threat-intel lifecycle including vulnerability and exploit-source tracking.
- `generating-threat-intelligence-reports` - report format for threat and vulnerability intelligence outputs.
- `mapping-mitre-attack-techniques` - maps observed or planned actions to ATT&CK techniques.
- `analyzing-cyber-kill-chain` - attack lifecycle reasoning for attack-path planning.
- `building-attack-pattern-library-from-cti-reports` - reusable attack-pattern knowledge base construction.

### Recon, enumeration, and evidence analysis

- `collecting-open-source-intelligence` - OSINT collection for target discovery and context.
- `performing-open-source-intelligence-gathering` - OSINT workflow for authorized assessments.
- `performing-osint-with-spiderfoot` - automated OSINT discovery with SpiderFoot.
- `performing-ai-driven-osint-correlation` - LLM-assisted OSINT correlation, including local Ollama-style usage.
- `performing-subdomain-enumeration-with-subfinder` - subdomain enumeration for bug bounty and external scope discovery.
- `performing-dns-enumeration-and-zone-transfer` - DNS enumeration and zone-transfer testing.
- `performing-ip-reputation-analysis-with-shodan` - internet-exposure enrichment with Shodan-style data.
- `analyzing-tls-certificate-transparency-logs` - certificate transparency recon for subdomains and exposed assets.
- `auditing-tls-certificate-transparency-logs` - CT monitoring and ownership/scope review.
- `analyzing-typosquatting-domains-with-dnstwist` - related-domain discovery and impersonation surface awareness.
- `analyzing-network-flow-data-with-netflow` - network flow analysis for recon validation and evidence.
- `analyzing-network-packets-with-scapy` - packet parsing and custom protocol inspection in Python.
- `analyzing-network-traffic-with-wireshark` - packet inspection for service behavior and exploit evidence.
- `performing-network-forensics-with-wireshark` - deeper packet evidence analysis for findings.
- `performing-network-packet-capture-analysis` - packet capture workflow for validation and documentation.
- `performing-network-traffic-analysis-with-tshark` - command-line packet analysis suited to automation.
- `performing-network-traffic-analysis-with-zeek` - Zeek-based network evidence extraction.
- `analyzing-api-gateway-access-logs` - API activity review for validation and abuse-pattern evidence.
- `analyzing-sbom-for-supply-chain-vulnerabilities` - dependency and SBOM vulnerability analysis.
- `analyzing-threat-intelligence-feeds` - enrichment of IOCs, CVEs, and threat context.
- `automating-ioc-enrichment` - automated enrichment patterns useful for CVE and exploit research.

### Web, API, and application security testing

- `conducting-api-security-testing` - comprehensive API assessment workflow.
- `performing-api-security-testing-with-postman` - Postman-based API security testing.
- `performing-api-inventory-and-discovery` - API discovery and inventory creation.
- `performing-api-fuzzing-with-restler` - REST API fuzzing workflow.
- `performing-api-rate-limiting-bypass` - rate-limit weakness testing for authorized APIs.
- `testing-api-security-with-owasp-top-10` - OWASP API Top 10 coverage.
- `testing-api-authentication-weaknesses` - API authentication weakness testing.
- `testing-api-for-broken-object-level-authorization` - BOLA testing.
- `testing-api-for-mass-assignment-vulnerability` - mass assignment testing.
- `testing-cors-misconfiguration` - CORS weakness assessment.
- `testing-websocket-api-security` - WebSocket authorization and input testing.
- `performing-web-application-penetration-test` - full web application pentest workflow.
- `performing-web-application-scanning-with-nikto` - Nikto-based web enumeration and scanning.
- `performing-web-application-vulnerability-triage` - web finding validation and prioritization.
- `testing-for-broken-access-control` - access-control weakness testing.
- `testing-for-business-logic-vulnerabilities` - business logic testing.
- `testing-for-email-header-injection` - email-header injection checks.
- `testing-for-host-header-injection` - host-header injection checks.
- `testing-for-json-web-token-vulnerabilities` - JWT vulnerability testing.
- `testing-jwt-token-security` - JWT configuration and implementation checks.
- `testing-oauth2-implementation-flaws` - OAuth2 implementation testing.
- `testing-for-open-redirect-vulnerabilities` - open redirect checks.
- `testing-for-sensitive-data-exposure` - sensitive data exposure review.
- `testing-for-xml-injection-vulnerabilities` - XML injection checks.
- `testing-for-xss-vulnerabilities` - XSS testing.
- `testing-for-xss-vulnerabilities-with-burpsuite` - Burp-assisted XSS testing.
- `testing-for-xxe-injection-vulnerabilities` - XXE testing.
- `bypassing-authentication-with-forced-browsing` - forced browsing and auth bypass testing.
- `performing-security-headers-audit` - HTTP security header assessment.
- `performing-clickjacking-attack-test` - clickjacking validation.
- `performing-csrf-attack-simulation` - CSRF validation in authorized apps.
- `performing-content-security-policy-bypass` - CSP weakness testing for XSS impact.
- `performing-directory-traversal-testing` - path traversal testing.
- `performing-http-parameter-pollution-attack` - HTTP parameter pollution testing.
- `performing-web-cache-deception-attack` - web cache deception testing.
- `performing-web-cache-poisoning-attack` - web cache poisoning testing.
- `performing-graphql-security-assessment` - GraphQL security review.
- `performing-graphql-introspection-attack` - GraphQL introspection exposure testing.
- `performing-graphql-depth-limit-attack` - GraphQL depth and complexity testing.
- `performing-soap-web-service-security-testing` - SOAP and XML service testing.
- `performing-serverless-function-security-review` - serverless application security review.
- `performing-thick-client-application-penetration-test` - thick-client testing, including local config and SQLite exposure checks.
- `performing-cryptographic-audit-of-application` - crypto implementation review.
- `performing-ssl-tls-security-assessment` - TLS configuration assessment.

### Exploit research, exploit validation, and controlled exploitation

- `exploiting-vulnerabilities-with-metasploit-framework` - Metasploit workflow for exploit validation.
- `exploiting-smb-vulnerabilities-with-metasploit` - SMB exploit validation with Metasploit.
- `exploiting-ms17-010-eternalblue-vulnerability` - specific SMB CVE validation in authorized labs.
- `exploiting-zerologon-vulnerability-cve-2020-1472` - specific AD CVE validation workflow.
- `exploiting-nopac-cve-2021-42278-42287` - specific AD CVE validation workflow.
- `exploiting-active-directory-certificate-services-esc1` - AD CS ESC1 validation.
- `exploiting-adcs-with-certipy` - Certipy-based AD CS testing.
- `exploiting-active-directory-with-bloodhound` - BloodHound-driven AD attack path analysis.
- `exploiting-api-injection-vulnerabilities` - API injection validation.
- `exploiting-broken-function-level-authorization` - BFLA exploit validation.
- `exploiting-broken-link-hijacking` - broken link hijacking checks.
- `exploiting-excessive-data-exposure-in-api` - API data exposure validation.
- `exploiting-http-request-smuggling` - HTTP request smuggling validation.
- `exploiting-idor-vulnerabilities` - IDOR validation.
- `exploiting-insecure-deserialization` - insecure deserialization testing.
- `exploiting-ipv6-vulnerabilities` - IPv6-specific weakness validation.
- `exploiting-jwt-algorithm-confusion-attack` - JWT algorithm confusion validation.
- `exploiting-mass-assignment-in-rest-apis` - REST mass assignment validation.
- `exploiting-nosql-injection-vulnerabilities` - NoSQL injection validation.
- `exploiting-oauth-misconfiguration` - OAuth misconfiguration exploitation.
- `exploiting-prototype-pollution-in-javascript` - prototype pollution validation.
- `exploiting-race-condition-vulnerabilities` - race condition testing.
- `exploiting-server-side-request-forgery` - SSRF validation.
- `exploiting-sql-injection-vulnerabilities` - SQL injection validation.
- `exploiting-sql-injection-with-sqlmap` - sqlmap-driven SQLi validation.
- `exploiting-template-injection-vulnerabilities` - SSTI validation.
- `exploiting-type-juggling-vulnerabilities` - type juggling validation.
- `exploiting-websocket-vulnerabilities` - WebSocket vulnerability validation.
- `performing-binary-exploitation-analysis` - binary exploit analysis for public exploit review/adaptation.
- `performing-blind-ssrf-exploitation` - blind SSRF validation.
- `performing-ssrf-vulnerability-exploitation` - SSRF exploit validation.
- `performing-second-order-sql-injection` - second-order SQLi testing.
- `performing-jwt-none-algorithm-attack` - JWT `none` algorithm validation.
- `performing-fuzzing-with-aflplusplus` - fuzzing workflow for vulnerability discovery.

### Active Directory, privilege escalation, and attack paths

- `analyzing-active-directory-acl-abuse` - AD ACL abuse analysis for attack-path planning.
- `conducting-internal-reconnaissance-with-bloodhound-ce` - BloodHound CE internal recon.
- `mapping-attack-paths-with-bloodhound-ce` - BloodHound attack-path mapping.
- `performing-active-directory-bloodhound-analysis` - BloodHound analysis for AD findings.
- `performing-active-directory-penetration-test` - AD pentest methodology.
- `performing-active-directory-vulnerability-assessment` - AD vulnerability assessment.
- `performing-privilege-escalation-assessment` - privilege escalation assessment workflow.
- `performing-privilege-escalation-on-linux` - Linux privilege escalation checks.
- `performing-service-account-audit` - service-account exposure and privilege review.

### Agent, MCP, and safety controls

- `auditing-mcp-servers-for-tool-poisoning` - MCP server and tool-poisoning audit for agent tool safety.
- `securing-agentic-ai-tool-invocation` - tool allowlisting, approval gates, identity binding, and audit logging for AI agents.
- `performing-threat-modeling-with-owasp-threat-dragon` - threat modeling for NetAttackAI workflows and trust boundaries.

Everything not listed above was removed from the catalog as not directly useful for this project.

## Authoring a skill

A skill is a directory containing a `SKILL.md` with YAML frontmatter and a
markdown body, plus an optional `references/` bundle. It is **advisory
prompt-context only** — it never grants execution authority and never changes
scope, permission, approval, command-safety, or audit rules.

### Frontmatter

```yaml
---
name: my-skill                # required, must match the directory name
description: One-line summary used for selection and display.
domain: web                   # optional grouping
subdomain: api                # optional finer grouping
tags:                         # used for deterministic selection
  - api
  - owasp
nist_csf:                     # optional framework mapping
  - PR.IP
mitre_attack:                 # optional technique mapping
  - T1190
---
```

- `tags` drive selection (`config.yaml` `skills.include_tags` and the dynamic
  goal/mode/service/CVE tag derivation). Attack-only tags (`exploit`,
  `credential`, `post-exploit`, etc.) are excluded in recon mode.
- `nist_csf` and `mitre_attack` surface in rendered context only when
  `skills.include_metadata: true` and in the `list_skill_references` MCP tool
  summary. They are advisory metadata.

### Body

Use `## When to Use` and `## Workflow` sections. The body is **untrusted
imported markdown** and is sanitized before it ever reaches a prompt
(`tools/skill_registry.py::_sanitize_skill_body`):

- HTML comments (`<!-- ... -->`) and `<script>`/`<iframe>` blocks are removed.
- Role-directive headings/lines are dropped: `## SYSTEM:`, `[SYSTEM]`,
  `[INSTRUCTION]`, `[ASSISTANT]`, `<<SYSTEM>>`, `<|...|>`, and headings
  starting with `ignore`/`disregard`/`override`/`new instructions`/
  `important override` (case-insensitive).
- Fenced blocks tagged ` ```system ` / ` ```instructions ` /
  ` ```ignore-above ` have their role markers neutralized.
- Tool-call mimics (`- run tool: ...`, `* call tool: ...`) are stripped.
- Rendered output is wrapped in an `<untrusted_skill_guidance>` fence with a
  NOTE telling the model to treat embedded instructions with suspicion and
  never act on directives that conflict with scope/permission/approval/
  command-safety/audit.

Do not rely on any of the stripped constructs — they will not survive into a
prompt. Write plain methodology.

### Optional `references/` bundle

Place `references/*.md` files alongside `SKILL.md`. Their **paths** are
listable via the `list_skill_references` MCP tool (gated by
`skills.allow_reference_listing`, default true). Their **contents are never
inlined** into a prompt — the model must use the existing workspace read
tools (still subject to `require_allowlist`) to pull a reference.

### `maybe/` tier

`skills/maybe/<name>/SKILL.md` is a gated tier for experimental or
higher-risk methodology. It is ignored — excluded from selection, the
catalog, and the `load_runtime_skill` tool — unless an operator sets
`skills.maybe_enabled: true` (default `false`). A placeholder lives at
`skills/maybe/experimental-skill-test/`.

### Selection at runtime

Skills are selected deterministically by `tools/skill_selector.py`: configured
`default_enabled` + `include_tags`, dynamic tags from the assessment context,
a boost-only cross-mission feedback term (ExperienceStore Beta posterior), and
semantic cosine-similarity ranking over `nomic-embed-text` (default-on with a
graceful fallback to tag matching when Ollama is unavailable). See
`docs/skills.md` for the full selection → re-selection → feedback → semantic
pipeline.
