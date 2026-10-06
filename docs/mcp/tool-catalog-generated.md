---
title: MCP Tool Catalog (Generated)
description: Machine-readable table for every MCP tool — gates, purpose, source location. Verified against tools/mcp_tools/ + mcp_server.py + mcp_engine_server.py.
source: [tools/mcp_tools/ad.py, tools/mcp_tools/assessment_state.py, tools/mcp_tools/attack_modules.py, tools/mcp_tools/browser.py, tools/mcp_tools/cracking.py, tools/mcp_tools/credentials.py, tools/mcp_tools/domain.py, tools/mcp_tools/egress_guard.py, tools/mcp_tools/hitl.py, tools/mcp_tools/killchain.py, tools/mcp_tools/manifest.py, tools/mcp_tools/metasploit.py, tools/mcp_tools/mitre.py, tools/mcp_tools/operator_connection.py, tools/mcp_tools/parallel_agents.py, tools/mcp_tools/payloads.py, tools/mcp_tools/peer_models.py, tools/mcp_tools/poc_verifier.py, tools/mcp_tools/recon.py, tools/mcp_tools/registry.py, tools/mcp_tools/replay_simulator.py, tools/mcp_tools/research.py, tools/mcp_tools/retest.py, tools/mcp_tools/runtime_skills.py, tools/mcp_tools/sandbox_exec.py, tools/mcp_tools/sessions.py, tools/mcp_tools/snapshots.py, tools/mcp_tools/verify.py, tools/mcp_tools/web_scan.py, tools/mcp_tools/workspace.py, tools/mcp_tools/terminal/allowlist.py, tools/mcp_tools/terminal/execute.py, tools/mcp_tools/terminal/package.py, tools/mcp_tools/terminal/privilege.py, tools/mcp_tools/modules/adaptive.py, tools/mcp_tools/modules/campaign.py, tools/mcp_tools/modules/hash.py, tools/mcp_tools/modules/planning.py, tools/mcp_tools/modules/synthesis.py, tools/mcp_tools/modules/web.py, mcp_server.py, mcp_engine_server.py]
generated_from: [tools/mcp_tools/ad.py, tools/mcp_tools/assessment_state.py, tools/mcp_tools/attack_modules.py, tools/mcp_tools/browser.py, tools/mcp_tools/cracking.py, tools/mcp_tools/credentials.py, tools/mcp_tools/domain.py, tools/mcp_tools/egress_guard.py, tools/mcp_tools/hitl.py, tools/mcp_tools/killchain.py, tools/mcp_tools/manifest.py, tools/mcp_tools/metasploit.py, tools/mcp_tools/mitre.py, tools/mcp_tools/operator_connection.py, tools/mcp_tools/parallel_agents.py, tools/mcp_tools/payloads.py, tools/mcp_tools/peer_models.py, tools/mcp_tools/poc_verifier.py, tools/mcp_tools/recon.py, tools/mcp_tools/registry.py, tools/mcp_tools/replay_simulator.py, tools/mcp_tools/research.py, tools/mcp_tools/retest.py, tools/mcp_tools/runtime_skills.py, tools/mcp_tools/sandbox_exec.py, tools/mcp_tools/sessions.py, tools/mcp_tools/snapshots.py, tools/mcp_tools/verify.py, tools/mcp_tools/web_scan.py, tools/mcp_tools/workspace.py, tools/mcp_tools/terminal/allowlist.py, tools/mcp_tools/terminal/execute.py, tools/mcp_tools/terminal/package.py, tools/mcp_tools/terminal/privilege.py, tools/mcp_tools/modules/adaptive.py, tools/mcp_tools/modules/campaign.py, tools/mcp_tools/modules/hash.py, tools/mcp_tools/modules/planning.py, tools/mcp_tools/modules/synthesis.py, tools/mcp_tools/modules/web.py, mcp_server.py, mcp_engine_server.py]
verify: every tool listed exists as an @mcp.tool def at time of generation (2026-10-05).
---

# MCP Tool Catalog (Generated)

> Machine-readable companion to `docs/mcp/tool-families/` and `docs/mcp/servers/`. Every tool below was verified to exist as an `@mcp.tool` def at generation time — no invented tools. Gates are the literal `@audit_tool` / `@require_allowlist(...)` decorators on each def; purpose is the docstring first line. Defensive-server tools enforce scope via an inline allowlist check instead of decorators; engine-server tools are read-only advisory with no gates.

Source locations use `<file>:<line>` relative to the repo root. Registration functions (`register_*_tools`) are auto-discovered via `tools/mcp_tools/registry.py:collect_tools()`; no manual list edit is needed.


_Generated 2026-10-05 from `42 source files` (167 tools across 37 families)._

## engine (`mcp_engine_server.py`) (5)

- **Registration:** inline `@mcp.tool` defs in `create_mcp_server()` — no `register_*` wrapper.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `search_skills` | — | Lexical + field-weighted search over the runtime skill catalog | `mcp_engine_server.py:96` |
| `get_skill` | — | Return one skill's full body + metadata by name. | `mcp_engine_server.py:122` |
| `cve_lookup` | — | NVD CVE lookup for a known product/version string (e.g. | `mcp_engine_server.py:147` |
| `list_runs` | — | List recent assessment runs (read-only history). Newest first. | `mcp_engine_server.py:157` |
| `get_run` | — | Return one run's details: state, request, preview, result, error. | `mcp_engine_server.py:185` |

## defensive (`mcp_server.py`) (8)

- **Registration:** inline `@mcp.tool` defs in `create_mcp_server()` — no `register_*` wrapper.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `run_nmap_ping_sweep` | — | Run `nmap -sn` against an approved subnet. Returns live hosts. | `mcp_server.py:232` |
| `run_nmap_triage_scan` | — | Top-port triage scan against an approved subnet. | `mcp_server.py:244` |
| `run_nmap_basic_scan` | — | Service/version detection on a single approved host. | `mcp_server.py:255` |
| `run_nmap_service_scan` | — | Service + scripts + OS detection on a single approved host. | `mcp_server.py:263` |
| `run_nmap_vuln_scan` | — | Run the Nmap NSE `vuln` category on a single approved host. | `mcp_server.py:274` |
| `run_limited_terminal` | — | Run a command if it is an allowlisted Nmap command and the | `mcp_server.py:282` |
| `search_vulnerability_intel` | — | Defensive public vulnerability/advisory search. The query is | `mcp_server.py:331` |
| `search_cve_intel` | — | NVD CVE lookup for a known product/version string. | `mcp_server.py:342` |

## `tools/mcp_tools/ad.py` (7)

- **Registration:** `register_ad_tools()` (`tools/mcp_tools/ad.py:364`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `asrep_roast` | `@require_allowlist()` | AS-REP Roast accounts with preauth disabled (impacket-GetNPUsers) for offline cracking. | `tools/mcp_tools/ad.py:381` |
| `pass_the_hash` | `@require_allowlist()` | Execute a command on a Windows target via NTLM hash (no plaintext). | `tools/mcp_tools/ad.py:458` |
| `adcs_enum` | `@require_allowlist()` | Enumerate AD Certificate Services templates via certipy (ESC1-8). | `tools/mcp_tools/ad.py:509` |
| `bloodhound_collect` | `@require_allowlist()` | Collect BloodHound data (users/groups/sessions/acls) for graph attack-path analysis. | `tools/mcp_tools/ad.py:563` |
| `responder_relay` | `@require_allowlist()` | Relay coerced NTLM auth via impacket ntlmrelayx. | `tools/mcp_tools/ad.py:616` |
| `smb_signing_check` | `@require_allowlist()` | Check whether the target requires SMB signing (relay feasibility). | `tools/mcp_tools/ad.py:684` |
| `golden_ticket` | `@require_allowlist()` | Mint a Kerberos golden ticket (TGT) from a stolen krbtgt NTLM hash. | `tools/mcp_tools/ad.py:716` |

## `tools/mcp_tools/assessment_state.py` (6)

- **Registration:** `register_assessment_state_tools()` (`tools/mcp_tools/assessment_state.py:108`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `get_assessment_state` | `@require_allowlist()` | Return a compact snapshot of assessment state for one target: goal, phase, hypotheses, attack-plan DAG summary, newest recon result (services/CVEs), credential count, and an audit-trail rollup. Read-only; target must be in the allowlist. Ra… | `tools/mcp_tools/assessment_state.py:127` |
| `query_capabilities` | `@audit_tool` | Discover available capabilities without touching the target. scope=modules lists all registered attack modules via capability_record() (filter by service substring against module.target_services when service is set). scope=tools lists regis… | `tools/mcp_tools/assessment_state.py:142` |
| `get_capability_details` | `@audit_tool` | Get the full capability record for one named module, tool, or skill, plus (for modules) an applicability explanation against a minimal empty-services context so the model can see why it would/wouldn't rank. Advisory only. Returns a CAPABILI… | `tools/mcp_tools/assessment_state.py:201` |
| `get_evidence` | `@require_allowlist()` | Read recent exploit_audit.jsonl entries for one target and return compact evidence refs (exploit_audit:<target>:<attempt_id> with tool/status/duration only -- raw command/args are never emitted, they may contain secrets). target must be in … | `tools/mcp_tools/assessment_state.py:272` |
| `record_hypothesis` | `@require_allowlist()` | Record one tracked hypothesis about the target into the assessment state store (<workspace>/plans/<target>_assessment.json). target must be in the allowlist (re-validated before writing -- the path is LLM-influenced). Returns a HYPOTHESIS_R… | `tools/mcp_tools/assessment_state.py:318` |
| `update_task` | `@require_allowlist()` | Mutate one step of the attack plan for one target: complete/fail/cancel/reset. Loads <workspace>/plans/<ip>_plan.json via AttackPlanner, dispatches to mark_step_done/fail_step/cancel_step/reset_step, and saves. target must be in the allowli… | `tools/mcp_tools/assessment_state.py:356` |

## `tools/mcp_tools/attack_modules.py` (2)

- **Registration:** `register_attack_module_tools()` (`tools/mcp_tools/attack_modules.py:22`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `list_attack_modules` | `@audit_tool` | List all registered pre-packaged attack modules. | `tools/mcp_tools/attack_modules.py:33` |
| `run_attack_module` | `@require_allowlist()` | Execute a pre-packaged attack module against a target IP. | `tools/mcp_tools/attack_modules.py:66` |

## `tools/mcp_tools/browser.py` (13)

- **Registration:** `register_browser_tools()` (`tools/mcp_tools/browser.py:183`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `browser_start` | `@require_allowlist("target")` | Start a sandboxed Chromium session locked to the target. Returns SESSION_STARTED with the session id for browser_navigate/browser_observe/... | `tools/mcp_tools/browser.py:203` |
| `browser_navigate` | `@require_allowlist("target")` | Navigate a browser session to a URL (redirect/SPA aware). The URL host must be allowlisted. Returns the final URL + status. | `tools/mcp_tools/browser.py:226` |
| `browser_observe` | `@require_allowlist("target")` | Harvest a compact page snapshot: title/URL/DOM summary/forms/endpoints/scripts/framework indicators. Bounded; never raw HTML. | `tools/mcp_tools/browser.py:270` |
| `browser_page_state` | `@require_allowlist("target")` | Lightweight page-state snapshot (URL/title/forms/endpoints) without a full observation drain. | `tools/mcp_tools/browser.py:325` |
| `browser_network_events` | `@require_allowlist("target")` | Captured request/response records (headers/body samples redacted). Paginate with limit/after_id. | `tools/mcp_tools/browser.py:351` |
| `browser_storage` | `@require_allowlist("target")` | Cookies + localStorage/sessionStorage for the origin. Values are redacted; persist useful ones via cred_store_add explicitly. | `tools/mcp_tools/browser.py:389` |
| `browser_screenshot` | `@require_allowlist("target")` | Capture a viewport screenshot as a hashed artifact under the workspace. | `tools/mcp_tools/browser.py:415` |
| `browser_execute_js` | `@require_allowlist("target")` | Execute JavaScript in the page and capture a bounded, redacted preview. Requires browser.allow_mutating_actions (lab opt-in). | `tools/mcp_tools/browser.py:446` |
| `browser_discover_forms` | `@require_allowlist("target")` | Discover forms + fields on the live page (metadata fingerprints, no submission). | `tools/mcp_tools/browser.py:490` |
| `browser_discover_endpoints` | `@require_allowlist("target")` | Discover REST/GraphQL endpoints from captured traffic + script refs. | `tools/mcp_tools/browser.py:522` |
| `browser_close` | `@require_allowlist("target")` | Hard-close a browser session (idempotent; releases worker resources). | `tools/mcp_tools/browser.py:559` |
| `browser_submit` | `@require_allowlist("target")` | Fill one live-page form by field name and submit it. The form's action host must be allowlisted. Requires browser.allow_mutating_actions. | `tools/mcp_tools/browser.py:582` |
| `browser_replay` | `@require_allowlist("target")` | Replay one HTTP request through the session (captured event_id as base, explicit url/method/headers/body override). The final URL host must be allowlisted. Requires browser.allow_mutating_actions. | `tools/mcp_tools/browser.py:662` |

## `tools/mcp_tools/cracking.py` (1)

- **Registration:** `register_cracking_tools()` (`tools/mcp_tools/cracking.py:22`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `run_hash_crack` | `@audit_tool` | Crack a hash inside the disposable worker with hashcat or john. | `tools/mcp_tools/cracking.py:89` |

## `tools/mcp_tools/credentials.py` (7)

- **Registration:** `register_credential_tools()` (`tools/mcp_tools/credentials.py:16`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `cred_store_add` | `@require_allowlist()` | Store a harvested or known credential for a target in the encrypted credential vault. Secrets and free-text notes are Fernet-encrypted at rest under exploit_workspace/credentials/<target_ip>/credentials.jsonl and are never written to the au… | `tools/mcp_tools/credentials.py:37` |
| `cred_store_get` | `@require_allowlist()` | Retrieve stored credentials for a target from the encrypted vault. By default returns a SAFE summary (secrets masked). Set include_secret=True WITH a specific username to reveal the decrypted secret for reuse in lateral_exec/dump_credential… | `tools/mcp_tools/credentials.py:92` |
| `cred_store_list` | `@require_allowlist()` | List all stored credentials for a target as a safe summary (no cleartext secrets). Shows username, type, target/source host, and confirmed status for each record in the encrypted vault, plus whether at-rest encryption is active. | `tools/mcp_tools/credentials.py:131` |
| `cred_store_confirm` | `@audit_tool` | Compatibility shim: agent calls cannot certify successful authentication. | `tools/mcp_tools/credentials.py:157` |
| `lateral_exec` | `@require_allowlist()` | Execute a command on a remote Windows host via impacket lateral-movement tools. Methods: wmiexec, smbexec, psexec, atexec. Provide either a plaintext password or an NTLM hash (format LM:NT or just NT). Use after obtaining credentials to mov… | `tools/mcp_tools/credentials.py:171` |
| `dump_credentials` | `@require_allowlist()` | Dump credentials from a target using secretsdump, mimikatz, or local SAM/LSASS extraction. Methods: secretsdump (remote via impacket), sam_local (local registry hives), mimikatz (if binary available), lsass (procdump + mimikatz), dcsync (im… | `tools/mcp_tools/credentials.py:230` |
| `kerberoast` | `@require_allowlist()` | Perform Kerberoasting against a Windows domain to extract TGS service tickets for offline hash cracking. Uses impacket GetUserSPNs.py. Provide domain, credentials (password or NTLM hash), and optionally the DC IP. Returns the path to the ca… | `tools/mcp_tools/credentials.py:335` |

## `tools/mcp_tools/domain.py` (5)

- **Registration:** `register_domain_tools()` (`tools/mcp_tools/domain.py:600`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `resolve_domain` | `@require_allowlist("domain")` | Resolve DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA). | `tools/mcp_tools/domain.py:610` |
| `enumerate_subdomains` | `@require_allowlist("domain")` | Enumerate subdomains of a domain via passive + active sources. | `tools/mcp_tools/domain.py:676` |
| `dns_recon` | `@require_allowlist("domain")` | Full DNS reconnaissance against a domain. | `tools/mcp_tools/domain.py:919` |
| `vhost_enum` | `@require_allowlist(host_param="domain")` | Enumerate virtual hosts on a web server via Host-header rotation. | `tools/mcp_tools/domain.py:1118` |
| `domain_whois` | `@require_allowlist("domain")` | WHOIS lookup + DNS-provider profiling for a domain. | `tools/mcp_tools/domain.py:1301` |

## `tools/mcp_tools/hitl.py` (3)

- **Registration:** `register_hitl_tools()` (`tools/mcp_tools/hitl.py:310`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `propose_finding` | `@audit_tool` | Propose a candidate finding for human review (agents propose, human decides). Appends a PROPOSED finding to reports/<run_id>/enhanced/enhanced_report.json — never APPROVED. A human promotes it via hitl_decide (operator path) or the WebUI Ev… | `tools/mcp_tools/hitl.py:318` |
| `hitl_decide` | `@audit_tool` | Record a human Approve/Reject decision on a proposed finding (operator-only human path — no target touch). Persists APPROVED/REJECTED + hitl_history[] (with actor) into the run artifact JSON. Only actor='human' is accepted — any other actor… | `tools/mcp_tools/hitl.py:379` |
| `list_proposed` | `@audit_tool` | List findings awaiting human review (hitl_status=PROPOSED). Empty run_id scans all runs (newest first). Zero target touch — reads the run artifact JSON only. Approved/rejected findings are hidden here; the final report surfaces APPROVED fin… | `tools/mcp_tools/hitl.py:412` |

## `tools/mcp_tools/killchain.py` (3)

- **Registration:** `register_killchain_tools()` (`tools/mcp_tools/killchain.py:65`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `killchain_status` | `@audit_tool` | Read-only kill-chain snapshot for a target: current state, applicable edges, and the shortest verified-edge path to the configured goal state. No target touch -- reads the kill-chain graph only. | `tools/mcp_tools/killchain.py:99` |
| `killchain_attempt` | `@require_allowlist("target")` | Attempt a verified kill-chain transition (e.g. creds_in_hand -> shell_as_user). The machine runs the edge's playbook through the normal MCP tool layer (allowlist + audit apply) and then independently verifies success via check probes; the s… | `tools/mcp_tools/killchain.py:122` |
| `killchain_plan` | `@audit_tool` | Compute the shortest kill-chain path (BFS over verified edges) from the target's current state to a goal state. Read-only planning -- executes nothing. ``goal_state`` defaults to the configured ``killchain.goal_state`` (fallback ``shell_as_… | `tools/mcp_tools/killchain.py:207` |

## `tools/mcp_tools/metasploit.py` (19)

- **Registration:** `register_metasploit_tools()` (`tools/mcp_tools/metasploit.py:258`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `run_msf_module` | `@require_allowlist()` | Run a Metasploit module against the target. Pass the module path (e.g. 'exploit/multi/http/log4shell_header_injection') and key=value options separated by spaces. The module runs in a visible terminal. | `tools/mcp_tools/metasploit.py:280` |
| `msfconsole_start` | `@audit_tool` | Legacy host-side console entry point. It is disabled; use the sandbox-contained run_msf_module tool. | `tools/mcp_tools/metasploit.py:403` |
| `msfconsole_stop` | `@audit_tool` | Legacy host-side console entry point. It is disabled; use sandbox-contained Metasploit execution. | `tools/mcp_tools/metasploit.py:428` |
| `msfconsole_command` | `@audit_tool` | Execute a command in the interactive msfconsole session. Use for: loading modules, setting options, running exploits, checking sessions, etc. The command is sent to the persistent msfconsole and output is captured. | `tools/mcp_tools/metasploit.py:446` |
| `msf_run_exploit` | `@require_allowlist()` | Run a Metasploit exploit module against a target using the persistent msfconsole. Provide module path (e.g., 'exploit/multi/http/log4shell_header_injection'), target IP, and optional key=value options separated by spaces. Returns the full e… | `tools/mcp_tools/metasploit.py:486` |
| `msf_run_auxiliary` | `@require_allowlist()` | Run a Metasploit auxiliary module (scanner, fuzzer, dos, etc.) against a target. Use for: port scanning, service enumeration, vulnerability checking. | `tools/mcp_tools/metasploit.py:550` |
| `msf_list_sessions` | `@audit_tool` | List all active Metasploit sessions (meterpreter, shell, cmd). Returns session IDs, types, target IPs, and platforms. | `tools/mcp_tools/metasploit.py:591` |
| `msf_interact_session` | `@audit_tool` | Send a command to a specific Metasploit session (meterpreter or shell). Use for: running post-exploitation commands, gathering system info, pivoting, etc. The session is backgrounded after the command completes. | `tools/mcp_tools/metasploit.py:623` |
| `msf_run_post_module` | `@audit_tool` | Run a post-exploitation module against a specific Metasploit session. Use for: privilege escalation, credential harvesting, persistence, keylogging, screenshot, etc. | `tools/mcp_tools/metasploit.py:667` |
| `msf_kill_session` | `@audit_tool` | Kill a specific Metasploit session. | `tools/mcp_tools/metasploit.py:703` |
| `msf_generate_payload` | `@audit_tool` | Generate a payload using msfvenom through the Metasploit bridge. Supports encoders and bad character avoidance. Returns the path to the generated payload file. | `tools/mcp_tools/metasploit.py:730` |
| `msf_run_resource_script` | `@audit_tool` | Create and run a Metasploit resource script in the persistent msfconsole. Resource scripts automate sequences of msfconsole commands. Use for: automated exploitation chains, mass scanning, post-exploitation workflows. | `tools/mcp_tools/metasploit.py:820` |
| `msf_run_recipe` | `@audit_tool` | Run a named Metasploit recipe (curated module+option preset). Recipes: smb_version, bluekeep, psexec, cred_gather_win, local_exploit_suggester, hashdump, getsystem, handler. Pass target_ip for exploit/auxiliary kinds, session_id for post ki… | `tools/mcp_tools/metasploit.py:861` |
| `msf_start_handler` | `@audit_tool` | Start exploit/multi/handler as a backgrounded job to catch a generated payload. lhost is the operator callback host (must be in allowed_targets). Pairs with msf_generate_payload: generate a reverse payload, then start a handler on the same … | `tools/mcp_tools/metasploit.py:920` |
| `msf_stop_handler` | `@audit_tool` | Stop all backgrounded handler jobs in the persistent msfconsole (jobs -K). | `tools/mcp_tools/metasploit.py:974` |
| `msf_post_hashdump` | `@audit_tool` | Dump SAM hashes from a Windows meterpreter session (post/windows/gather/hashdump). | `tools/mcp_tools/metasploit.py:1023` |
| `msf_post_getsystem` | `@audit_tool` | Attempt SYSTEM elevation on a Windows meterpreter session (post/windows/escalate/getsystem). | `tools/mcp_tools/metasploit.py:1036` |
| `msf_post_portfwd` | `@audit_tool` | Forward a local port through a meterpreter session to a remote host (portfwd). remote_host must be in allowed_targets (the allowlist is the pivot lock). | `tools/mcp_tools/metasploit.py:1049` |
| `msf_post_route` | `@audit_tool` | Add a route through a meterpreter session to a target subnet (post/multi/manage/autoroute). The subnet's network address must be in allowed_targets (pivot lock). | `tools/mcp_tools/metasploit.py:1086` |

## `tools/mcp_tools/mitre.py` (1)

- **Registration:** `register_mitre_tools()` (`tools/mcp_tools/mitre.py:17`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `export_attack_navigator` | `@audit_tool` | Map this run's audit trail to MITRE ATT&CK techniques and write a | `tools/mcp_tools/mitre.py:23` |

## `tools/mcp_tools/modules/adaptive.py` (2)

- **Registration:** `register_adaptive_tools()` (`tools/mcp_tools/modules/adaptive.py:17`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `craft_exploit` | `@require_allowlist()` | Generate a custom exploit script tailored to a specific target service. | `tools/mcp_tools/modules/adaptive.py:28` |
| `mutate_exploit` | `@audit_tool` | Mutate a previously generated exploit script based on failure feedback. | `tools/mcp_tools/modules/adaptive.py:130` |

## `tools/mcp_tools/modules/campaign.py` (4)

- **Registration:** `register_campaign_tools()` (`tools/mcp_tools/modules/campaign.py:188`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `start_autonomous_campaign` | `@require_allowlist()` | Start a fully autonomous attack campaign against a target IP. | `tools/mcp_tools/modules/campaign.py:199` |
| `get_campaign_status` | `@audit_tool` | Get the current status of a running or completed autonomous campaign. | `tools/mcp_tools/modules/campaign.py:403` |
| `run_campaign_step` | `@audit_tool` | Execute a single pending task from an autonomous campaign synchronously. | `tools/mcp_tools/modules/campaign.py:463` |
| `stop_campaign` | `@audit_tool` | Gracefully stop a running autonomous campaign. | `tools/mcp_tools/modules/campaign.py:633` |

## `tools/mcp_tools/modules/hash.py` (1)

- **Registration:** `register_hash_tools()` (`tools/mcp_tools/modules/hash.py:128`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `hash_crack_identify` | `@audit_tool` | Identify hash type and suggest cracking commands. Provide an NTLM, NetNTLMv2, Kerberos TGS, MD5, SHA, or bcrypt hash. Returns hashcat mode and cracking command. | `tools/mcp_tools/modules/hash.py:139` |

## `tools/mcp_tools/modules/planning.py` (3)

- **Registration:** `register_planning_tools()` (`tools/mcp_tools/modules/planning.py:18`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `create_attack_plan` | `@require_allowlist()` | Create a structured attack plan for a target IP. | `tools/mcp_tools/modules/planning.py:29` |
| `get_current_plan` | `@require_allowlist()` | Retrieve the current attack plan for a target IP. | `tools/mcp_tools/modules/planning.py:107` |
| `replan` | `@require_allowlist()` | Adapt the current attack plan based on a failure or new information. | `tools/mcp_tools/modules/planning.py:149` |

## `tools/mcp_tools/modules/synthesis.py` (1)

- **Registration:** `register_synthesis_tools()` (`tools/mcp_tools/modules/synthesis.py:16`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `cve_to_exploit_synth` | `@require_allowlist()` | Generate a Python exploit script for a specific CVE against the target. Provide the CVE ID (e.g., CVE-2021-44228), service name, and version. The tool fetches CVE details and returns a ready-to-use exploit script. Use write_python_file to s… | `tools/mcp_tools/modules/synthesis.py:720` |

## `tools/mcp_tools/modules/web.py` (7)

- **Registration:** `register_web_tools()` (`tools/mcp_tools/modules/web.py:311`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `jwt_tamper` | `@require_allowlist()` | Test JWT tokens for algorithm confusion (alg:none), HMAC key confusion, and weak secret brute-force. | `tools/mcp_tools/modules/web.py:323` |
| `ssti_probe` | `@require_allowlist()` | Probe for Server-Side Template Injection (SSTI) across Jinja2, Twig, Freemarker, Velocity, Smarty, and Mako engines. | `tools/mcp_tools/modules/web.py:510` |
| `graphql_introspect` | `@require_allowlist()` | Extract GraphQL schema via introspection query. | `tools/mcp_tools/modules/web.py:646` |
| `race_request` | `@require_allowlist()` | Send N concurrent HTTP requests to exploit TOCTOU race conditions. | `tools/mcp_tools/modules/web.py:792` |
| `timing_oracle` | `@require_allowlist()` | Detect timing side-channels in login, password reset, and token validation endpoints. | `tools/mcp_tools/modules/web.py:913` |
| `request_smuggling_probe` | `@require_allowlist()` | Test for HTTP request smuggling (CL.TE, TE.CL, TE.TE). | `tools/mcp_tools/modules/web.py:1017` |
| `password_spray` | `@require_allowlist()` | Spray one password across many common usernames. | `tools/mcp_tools/modules/web.py:1148` |

## `tools/mcp_tools/operator_connection.py` (7)

- **Registration:** `register_operator_connection_tools()` (`tools/mcp_tools/operator_connection.py:84`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `rce_exec` | `@require_allowlist()` | Execute a one-shot RCE command against an authorized victim host and return output. | `tools/mcp_tools/operator_connection.py:93` |
| `establish_persistence` | `@require_allowlist()` | Deploy a persistence implant on an authorized victim that beacons back to the operator box. | `tools/mcp_tools/operator_connection.py:139` |
| `list_connections` | `@audit_tool` | List operator-box -> victim persistence connections. | `tools/mcp_tools/operator_connection.py:281` |
| `check_connection` | `@require_allowlist()` | Health-check a persistence channel: verify implant still present on victim and listener running. | `tools/mcp_tools/operator_connection.py:321` |
| `remove_persistence` | `@require_allowlist()` | Remove a persistence implant from a victim and optionally stop its operator listener. | `tools/mcp_tools/operator_connection.py:396` |
| `rce_listener_start` | `@audit_tool` | Start an operator-side listener for persistence beacons (reverse shells). | `tools/mcp_tools/operator_connection.py:491` |
| `persistence_catalog` | `@audit_tool` | List available persistence implant methods (operator catalog). | `tools/mcp_tools/operator_connection.py:548` |

## `tools/mcp_tools/parallel_agents.py` (3)

- **Registration:** `register_parallel_agent_tools()` (`tools/mcp_tools/parallel_agents.py:258`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `spawn_subagent` | `@audit_tool` | Spawn a specialist sub-agent to work in parallel while you continue | `tools/mcp_tools/parallel_agents.py:279` |
| `await_subagent` | `@audit_tool` | Block until a spawned sub-agent finishes and return its result. | `tools/mcp_tools/parallel_agents.py:342` |
| `list_subagents` | `@audit_tool` | List all spawned sub-agents and their current status. | `tools/mcp_tools/parallel_agents.py:368` |

## `tools/mcp_tools/payloads.py` (1)

- **Registration:** `register_payload_tools()` (`tools/mcp_tools/payloads.py:14`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `generate_payload` | `@audit_tool` | Generate a payload using msfvenom. Supports reverse_tcp, reverse_https, bind_tcp and many output formats (exe, elf, raw, python, csharp, dll, ps1). Returns the path to the generated payload file in the workspace and a preview of the command… | `tools/mcp_tools/payloads.py:25` |

## `tools/mcp_tools/peer_models.py` (2)

- **Registration:** `register_peer_model_tools()` (`tools/mcp_tools/peer_models.py:40`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `consult_peer_models` | `@audit_tool` | Ask configured peer AI models for advisory help. Use sparingly when crafting an exploit approach, reviewing generated exploit code, or recovering from repeated failures. Peers receive no tool schemas and cannot execute commands; they only r… | `tools/mcp_tools/peer_models.py:53` |
| `peer_review_outcome` | `@audit_tool` | Cross-model outcome judging (D3). Ask configured peer AI models to grade whether the evidence supports the given verdict (e.g. "compromised" / "refuted"). Advisory only -- the deterministic OutcomeJudge stays the authority. One alias plans,… | `tools/mcp_tools/peer_models.py:164` |

## `tools/mcp_tools/poc_verifier.py` (1)

- **Registration:** `register_poc_verifier_tools()` (`tools/mcp_tools/poc_verifier.py:26`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `verify_poc` | `@audit_tool` | Syntax-check (py_compile) and optionally Docker-compile-test a synthesized Python PoC. Returns {syntax_ok, docker_ok, stderr, code_sha256}. The PoC is NEVER executed -- this is a compile/import gate, not a sandbox guarantee. Docker containe… | `tools/mcp_tools/poc_verifier.py:36` |

## `tools/mcp_tools/recon.py` (7)

- **Registration:** `register_recon_tools()` (`tools/mcp_tools/recon.py:279`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `check_os` | `@require_allowlist()` | Return a cautious OS hint from Nmap service metadata in the sandbox. | `tools/mcp_tools/recon.py:286` |
| `quick_scan` | `@require_allowlist()` | Run a bounded Nmap TCP connect scan in the sandbox worker. | `tools/mcp_tools/recon.py:361` |
| `run_full_recon` | `@require_allowlist()` | Run a TCP Nmap scan inside the sandbox worker and save its results. | `tools/mcp_tools/recon.py:422` |
| `get_service_fingerprint` | `@require_allowlist()` | Fingerprint one TCP service using Nmap inside the sandbox worker. | `tools/mcp_tools/recon.py:509` |
| `run_udp_recon` | `@require_allowlist()` | Report that UDP scanning is unavailable under the worker policy. | `tools/mcp_tools/recon.py:581` |
| `run_osint_recon` | `@require_allowlist()` | Run bounded passive OSINT lookups about the authorized target. | `tools/mcp_tools/recon.py:610` |
| `diff_recon_runs` | `@require_allowlist()` | Compare two persisted recon_result.json snapshots. | `tools/mcp_tools/recon.py:667` |

## `tools/mcp_tools/replay_simulator.py` (1)

- **Registration:** `register_replay_simulator_tools()` (`tools/mcp_tools/replay_simulator.py:22`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `replay_simulate` | `@audit_tool` | Dry-run an attack plan against a saved ReconAssessment JSON for pre-commit critique. Both arguments are JSON strings. Returns confidence (0..1), critique text, and branch proposals. Zero target touch -- pure simulation. When the LLM is unav… | `tools/mcp_tools/replay_simulator.py:32` |

## `tools/mcp_tools/research.py` (7)

- **Registration:** `register_research_tools()` (`tools/mcp_tools/research.py:14`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `search_exploit_db` | `@audit_tool` | Search the local exploit-db database via searchsploit. Returns exploit IDs, titles, paths and any associated CVEs. Use this to find known exploits for discovered services and CVEs. | `tools/mcp_tools/research.py:25` |
| `search_web_exploit` | `@audit_tool` | Read-only public web search for candidate exploit, PoC, advisory, and vulnerability-research sources. Returns titles, URLs, snippets, source quality, provider metadata, and warnings; it does not fetch full pages or execute anything. | `tools/mcp_tools/research.py:31` |
| `fetch_webpage` | `@audit_tool` | Read-only fetch for one public source URL discovered during research. Returns title, source URL, readable content, links, provider metadata, and warnings. Private/internal/localhost URLs are blocked by default, and this tool does not execut… | `tools/mcp_tools/research.py:39` |
| `deep_research` | `@audit_tool` | Perform read-only multi-source research for an authorized vulnerability, CVE, product/version, or technique. Searches candidate sources, ranks/de-duplicates them, fetches selected public pages, and returns structured JSON with citations, ke… | `tools/mcp_tools/research.py:47` |
| `search_cve_intel` | `@audit_tool` | Look up CVEs in the NVD database for a known CVE ID or product/version string. Returns CVSS score, description, and reference links. | `tools/mcp_tools/research.py:55` |
| `cve_to_poc` | `@audit_tool` | Resolve a CVE ID to VERIFIED PoC URLs only (GitHub Search API + searchsploit --cve + NVD references, each HTTP-existence-checked). Returns CVE_TO_POC_RESULTS with verified URLs, or NO_VERIFIED_POC_FOUND if none verify. NEVER fabricate or gu… | `tools/mcp_tools/research.py:73` |
| `search_threat_intel` | `@audit_tool` | Search OSV.dev / GitHub Security Advisories / CISA KEV for a package name or CVE ID. Advisory only — never touches the target. Returns a JSON block with per-source vuln/advisory lists + KEV membership. Feed text is control-char-stripped and… | `tools/mcp_tools/research.py:90` |

## `tools/mcp_tools/retest.py` (1)

- **Registration:** `register_retest_tools()` (`tools/mcp_tools/retest.py:374`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `retest_finding` | `@require_allowlist()` | Repeat a stored finding probe and record an unverified diagnostic. | `tools/mcp_tools/retest.py:380` |

## `tools/mcp_tools/runtime_skills.py` (4)

- **Registration:** `register_runtime_skill_tools()` (`tools/mcp_tools/runtime_skills.py:12`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `list_runtime_skills` | `@audit_tool` | List read-only runtime skills available to guide the assessment. Skills are advisory prompt context only; they do not execute code or change permissions. | `tools/mcp_tools/runtime_skills.py:34` |
| `search_runtime_skills` | `@audit_tool` | Search read-only runtime skills by query text and optional comma-separated tags. Use before load_runtime_skill when the current attack path needs more specific methodology guidance. | `tools/mcp_tools/runtime_skills.py:56` |
| `load_runtime_skill` | `@audit_tool` | Load one read-only runtime skill by exact name. Returns compact markdown methodology guidance. This never executes scripts, enables tools, changes target scope, or changes permission mode. | `tools/mcp_tools/runtime_skills.py:77` |
| `list_skill_references` | `@audit_tool` | List the reference document paths bundled with a runtime skill (read-only). Returns paths only, never contents -- read a path via the workspace read tools if needed (still subject to approval/allowlist). | `tools/mcp_tools/runtime_skills.py:102` |

## `tools/mcp_tools/sessions.py` (13)

- **Registration:** `register_session_tools()` (`tools/mcp_tools/sessions.py:18`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `start_tmux_session` | `@ctx.audit_tool` | Unavailable: persistent sessions are not yet backed by the sandbox worker. | `tools/mcp_tools/sessions.py:31` |
| `send_to_session` | `@ctx.audit_tool` | Unavailable: host sessions cannot be controlled by agent-generated input. | `tools/mcp_tools/sessions.py:37` |
| `read_session_output` | `@ctx.audit_tool` | Unavailable: session output is not exposed from host processes. | `tools/mcp_tools/sessions.py:43` |
| `kill_session` | `@ctx.audit_tool` | Unavailable: session lifecycle operations are not host-backed. | `tools/mcp_tools/sessions.py:49` |
| `start_background_job` | `@ctx.audit_tool` | Unavailable: background jobs require a sandbox-backed implementation. | `tools/mcp_tools/sessions.py:55` |
| `read_job_output` | `@ctx.audit_tool` | Unavailable: job output is not read from host processes. | `tools/mcp_tools/sessions.py:61` |
| `stop_background_job` | `@ctx.audit_tool` | Unavailable: background jobs are not started on the host. | `tools/mcp_tools/sessions.py:67` |
| `start_listener` | `@ctx.audit_tool` | Unavailable: listeners and pivot processes require sandbox support. | `tools/mcp_tools/sessions.py:73` |
| `read_listener_output` | `@ctx.audit_tool` | Unavailable: listener output is not read from host processes. | `tools/mcp_tools/sessions.py:87` |
| `stop_listener` | `@ctx.audit_tool` | Unavailable: listeners are not started on the host. | `tools/mcp_tools/sessions.py:93` |
| `list_sessions` | `@ctx.audit_tool` | Unavailable: host process/session inventory is not exposed to agents. | `tools/mcp_tools/sessions.py:99` |
| `list_processes` | `@ctx.audit_tool` | Unavailable: host process inventory is not exposed to agents. | `tools/mcp_tools/sessions.py:105` |
| `kill_process` | `@ctx.audit_tool` | Unavailable: agent tools cannot signal host processes. | `tools/mcp_tools/sessions.py:111` |

## `tools/mcp_tools/snapshots.py` (3)

- **Registration:** `register_snapshot_tools()` (`tools/mcp_tools/snapshots.py:22`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `snapshot_create` | `@require_allowlist("vm_id")` | Take a snapshot of an allowlisted target's backing VM/container (docker commit for containers; hypervisor checkpoints for VMs). Infrastructure-touching: refused unless snapshots.enabled AND the target is allowlisted. Returns SNAPSHOT_CREATE… | `tools/mcp_tools/snapshots.py:40` |
| `snapshot_revert` | `@require_allowlist("vm_id")` | Roll an allowlisted target's backing VM/container back to a snapshot (empty ref = latest recorded). Infrastructure-touching: refused unless snapshots.enabled AND the target is allowlisted. Returns SNAPSHOT_REVERTED: on success, ERROR:/BLOCK… | `tools/mcp_tools/snapshots.py:65` |
| `snapshot_list` | `@audit_tool` + `@require_allowlist("vm_id")` | List recorded snapshots for an allowlisted target (read-only; no target touch). Returns a SNAPSHOT_LIST: block. | `tools/mcp_tools/snapshots.py:92` |

## `tools/mcp_tools/terminal/execute.py` (4)

- **Registration:** `_register_execute_tools()` (`tools/mcp_tools/terminal/execute.py:183`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `run_exploit_terminals` | `@audit_tool` | Run several short shell probes as ONE sandbox round-trip. | `tools/mcp_tools/terminal/execute.py:207` |
| `run_exploit_terminal` | `@audit_tool` | Run any shell command in a dedicated visible terminal window. The command executes synchronously; output is captured and RETURNED in the result under an OUTPUT: section. Use for running Kali tools, nmap, curl, netcat, searchsploit, etc. IMP… | `tools/mcp_tools/terminal/execute.py:338` |
| `run_as_root` | `@audit_tool` | Run a command as root inside the sandbox worker and capture its output. | `tools/mcp_tools/terminal/execute.py:478` |
| `git_clone` | `@audit_tool` | Clone a Git repository (GitHub exploit/PoC/tool) into the workspace. Provide the full repo URL (e.g., 'https://github.com/user/repo.git'). Optional target_dir for a custom folder name. | `tools/mcp_tools/terminal/execute.py:550` |

## `tools/mcp_tools/terminal/package.py` (5)

- **Registration:** `_register_package_tools()` (`tools/mcp_tools/terminal/package.py:22`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `apt_install` | `@audit_tool` | Legacy compatibility tool; host-side package installation is disabled. | `tools/mcp_tools/terminal/package.py:33` |
| `pip_install` | `@audit_tool` | Legacy compatibility tool; host-side package installation is disabled. | `tools/mcp_tools/terminal/package.py:39` |
| `install_package` | `@audit_tool` | Legacy compatibility tool; host-side package installation is disabled. | `tools/mcp_tools/terminal/package.py:45` |
| `download_and_install` | `@audit_tool` | Legacy compatibility tool; host-side downloads and installation are disabled. | `tools/mcp_tools/terminal/package.py:51` |
| `update_system` | `@audit_tool` | Legacy compatibility tool; host package updates are disabled. | `tools/mcp_tools/terminal/package.py:57` |

## `tools/mcp_tools/terminal/privilege.py` (2)

- **Registration:** `_register_privilege_tools()` (`tools/mcp_tools/terminal/privilege.py:130`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `check_environment` | `@audit_tool` | Check which security testing tools are installed and available on the system. | `tools/mcp_tools/terminal/privilege.py:137` |
| `preflight_env_check` | `@audit_tool` | Probe installed pentest tools, sudo/pip installability, and the | `tools/mcp_tools/terminal/privilege.py:195` |

## `tools/mcp_tools/verify.py` (1)

- **Registration:** `register_verify_tools()` (`tools/mcp_tools/verify.py:215`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `verify_finding` | `@require_allowlist()` | Repeat a candidate probe N times and persist its conservative result. | `tools/mcp_tools/verify.py:221` |

## `tools/mcp_tools/web_scan.py` (3)

- **Registration:** `register_web_scan_tools()` (`tools/mcp_tools/web_scan.py:266`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `run_web_scan` | `@require_allowlist()` | Run a web scanner (nikto/nuclei/sqlmap/gobuster/feroxbuster/whatweb/wpscan/dirb/dirbuster) against the target. Returns the scanner's parsed output. The target must be in the explicit allowlist. ``options`` are extra scanner flags (space-sep… | `tools/mcp_tools/web_scan.py:316` |
| `parse_nuclei_results` | `@audit_tool` | Parse a prior nuclei scan's JSONL events into confirmed-candidate TechnicalFindings (local only: no target arg, no network). Returns a NUCLEI_FINDINGS summary; full records are saved as nuclei-findings.json in the attempt dir. | `tools/mcp_tools/web_scan.py:431` |
| `generate_nuclei_template` | `@audit_tool` | Generate a reusable Nuclei template YAML from a confirmed finding (local only: no target arg, no network). Validates the generated YAML schema without launching a host scanner; reports VALID/INVALID. | `tools/mcp_tools/web_scan.py:505` |

## `tools/mcp_tools/workspace.py` (4)

- **Registration:** `register_workspace_tools()` (`tools/mcp_tools/workspace.py:115`) — auto-discovered; no edit to `mcp_exploit_server.py`.

| Tool | Gates | Purpose | Source |
|------|-------|---------|--------|
| `write_python_file` | `@audit_tool` | Write an AI-generated Python exploit script. | `tools/mcp_tools/workspace.py:125` |
| `run_python_file` | `@require_allowlist()` | Execute a previously written Python exploit script against the target IP. | `tools/mcp_tools/workspace.py:209` |
| `read_workspace_file` | `@audit_tool` | Read a file inside the run workspace by path. | `tools/mcp_tools/workspace.py:388` |
| `list_workspace` | `@audit_tool` | List all files in the exploit workspace directory. | `tools/mcp_tools/workspace.py:409` |

## Totals

- **Tools:** 167 across 37 families.

| Gates | Count |
|-------|-------|
| `@audit_tool` | 70 |
| `@require_allowlist()` | 49 |
| `@require_allowlist("target")` | 14 |
| `@ctx.audit_tool` | 13 |
| `—` | 13 |
| `@require_allowlist("domain")` | 4 |
| `@require_allowlist("vm_id")` | 2 |
| `@audit_tool + @require_allowlist("vm_id")` | 1 |
| `@require_allowlist(host_param="domain")` | 1 |
