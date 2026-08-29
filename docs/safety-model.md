# Safety Model

This project can run powerful security tooling. The codebase relies on layered controls, not a single switch.

## Layers

1. Mission authorization in `mission.py`
2. Scope enforcement in `scope_gate.py`
3. Risk and budget enforcement in `risk_controller.py`
4. Tool routing controls in `tool_router.py`
5. Exploit permission controls in `tools/exploit_agent/`
6. Runtime configuration in `config.yaml`
7. OPSEC advisory layer in `tools/opsec.py` (target-aware, advisory-only — never a gate)
8. Audit logs, evidence records, and workspace artifacts

## Mission Rules

`mission.yaml` defines:

- `allowed_assets`
- `disallowed_assets`
- `forbidden_actions`
- `rate_limits`
- `testing_modes`
- `risk_profile`
- optional accounts and notes

Risk profiles used in the sample mission:

- `low_noise_non_destructive`: recon and analysis only.
- `standard_authorized`: normal authorized bug bounty mode without exploit/pivot phases.
- `high_authorized_testing`: full testing, intended only for owned infrastructure or explicit authorization.

## Scope Gate

`scope_gate.py` answers whether an action can touch a target. It supports:

- exact domains
- wildcard domains
- IP addresses
- CIDR ranges
- explicit deny rules
- forbidden action types
- third-party asset detection
- per-target rate limiting
- risk level gating

Any new Flow B / recon execution path should call the scope gate before network
or system actions (the lab attack path is intentionally exempt — its one lock is
the MCP allowlist). If a change bypasses `ToolRouter`, it must add equivalent checks.

## Risk Controller

`risk_controller.py` answers how an allowed target can be touched. It handles:

- non-destructive defaults
- action risk classification
- per-session command budgets
- completed task budgets
- rate/budget checks
- human approval requirements for high-risk actions

Use `RiskController.assess_action` before adding new task or exploit execution behavior.

## Exploit Permission Modes

This is a **lab-only build**: run only against systems the operator owns or is
explicitly authorized to test, on a throwaway operator box. An explicit
`full_access` setting is **unrestricted but target-locked** in either run mode.

`tools/exploit_agent/policy.py` defines exploit permissions:

- `full_access` (config + schema default): the lab posture.
  `ExploitPolicy.approve_action` auto-approves after consulting the mission
  ScopeGate threaded onto the policy (`_enforce_mission_scope`): a tool mapped
  to a category in `exploit.forbidden_actions` (`_TOOL_ACTION_CATEGORY`), or an
  action naming an asset outside the gate's allow rules / inside
  `exploit.disallowed_assets`, is denied with a `SCOPE_DENIED` audit row. A
  gate verdict of `requires_human_approval` still auto-approves (full_access is
  the explicit lab grant — this check is not a blanket deny), and
  `scope_gate=None` (swarm without a mission gate) stays permissive. Command
  *content* is not inspected — destructive commands, egress, reverse shells,
  credential dumping, Metasploit, and Python write/run are all allowed against
  authorized targets. The former `_check_command_safety` / `_gate_pivot_and_count`
  gates remain removed (no code path calls them).
- `approve_only`: require operator approval for sensitive actions. Every
  non-approved exit (operator denial, aborted prompt, exhausted budget) is
  written to the tamper-evident audit chain as a `denied` row.
- `read_only`: gather information and avoid active exploitation. Set it for
  propose-only recon; `_resolve_exploit_permission` uses it as the missing-key
  fallback so a partial config never silently becomes live.

**The one full-access safety kept is the target-IP lock (no pivoting to other
hosts).** It is enforced at the MCP tool layer: `tools/mcp_shared._allowed_target_list`
(`tools/mcp_shared.py:494-534`) unions `os.environ["EXPLOIT_TARGET"]` (the runtime `--target`, set in
`tools/mcp_session.py:255`) with `exploit.allowed_targets` **plus** `EXPLOIT_TARGET_IP` (resolved IP for domain targets), `EXPLOIT_TARGET_DOMAIN` (domain string), and `EXPLOIT_DISCOVERED_TARGETS` (comma-separated subdomains/IPs auto-authorized mid-run via `tools/mcp_shared.add_discovered_target:537-555`); `is_target_in_allowlist` (`tools/validation_utils.py:380-420`) supports domains + `*.wildcard` + CIDR. `@require_allowlist` on
every target-touching tool plus `tools/mcp_tools/terminal._target_lock_block`
(defined in `tools/mcp_tools/terminal/allowlist.py`, re-exported from the
`terminal` package) refuse any destination that is not in the union. The lock is applied
wherever a non-target host can be named:

- `run_exploit_terminal` / `run_as_root`: `_target_lock_block` scans the shell
  command's destinations (URL authorities, `/dev/tcp` hosts, LHOST/RHOST,
  scanner-verb targets, bare IPs).
- `run_python_file`: the script body is scanned with the same
  `_target_lock_block` before execution, so a literal-IP pivot written into a
  Python script (reverse shell / `nc` to another host) is refused -- otherwise
  `run_python_file` would bypass the terminal lock. (Static body scan; a
  dynamically-constructed or DNS-resolved destination is not caught.)
- `kerberoast`: an explicit `dc_ip` (impacket `-dc-ip`) is allowlist-checked,
  not just the `target_ip` arg.
- Metasploit free-text commands (`msfconsole_command`,
  `msf_interact_session`, `msf_run_resource_script`): `_extract_msf_rhosts`
  extracts `RHOSTS`/`RHOST` **and** meterpreter pivot hosts (`portfwd -r`,
  `route add`, `autoroute`), so an existing-session pivot to another host is
  refused.

The autonomous orchestrator's no-MCP "Path B" is target-locked by its
`scope_gate.check_scope` (kept for that reason); its `max_pivot_depth` defaults
to 0.

**Operator-box filesystem is unrestricted** (the operator box is a throwaway lab
VM): `read_workspace_file` reads any path (including `/etc/hosts`, the vault
keyfile), `write_python_file` accepts arbitrary paths/sizes/code, and
`list_workspace` hides nothing. Recon / Flow B still enforce their own workspace
containment where relevant.

`config.yaml` defaults to the lab posture:

```yaml
exploit:
  permission: full_access            # lab build; missing-key fallback is read_only (tools/cli_exploit_settings.py:13-30)
  attack_mode: true
  require_explicit_allowlist: true   # the target-IP lock (tools/mcp_shared.py:494-534)
  allowed_targets: [127.0.0.1]        # lab checked-in default; schema default is [] (tools/config/schema.py:181)
  disallowed_assets: []               # enforced by the policy's full-access mission-scope check (SCOPE_DENIED) + Flow B
  forbidden_actions: []               # ditto (via _TOOL_ACTION_CATEGORY); also enforced by the swarm critic agent
multi_model:
  enabled: true                      # lab default true (schema False); advisory peer consultation
```

Recon safety is retained when `permission: read_only` is configured: the
post-session `SafetyReviewer`, the READ_ONLY propose-only path, the goal-menu
SAFE/GATED narrowing, and the defensive scope-gated `mcp_server.py` are unchanged.

## MCP Safety Boundary

`mcp_server.py` is a defensive, scope-aware MCP server.

`mcp_exploit_server.py` is not the main safety boundary. It exposes tools for shell execution, script writing/running, package installation, Metasploit, payloads, credential storage, recon, autonomous campaigns, sessions, listeners, and exploit modules. Its file-level docstring explicitly says policy gating is expected in `tools.exploit_agent`.

When `multi_model.enabled` is true, the exploit MCP server also exposes `consult_peer_models`. This is advisory only: peer models receive no MCP tool schemas, cannot execute commands, and their responses must still pass through the main agent and `ExploitPolicy` before any target-touching action occurs.

When `snapshots.enabled` is true, the exploit MCP server also exposes `snapshot_create` / `snapshot_revert` / `snapshot_list`. These are infrastructure-touching but not privilege-escalating: they snapshot/restore the operator's own backing VM or container for an allowlisted target, gated by `@require_allowlist("vm_id")` (the allowlist IS the lock) and `@audit_tool`. The automatic snapshot-before-destructive hooks in the exploit loop, swarm bridge, and campaign executor are fail-open by contract — a snapshot failure logs a warning and the action proceeds, so snapshot infrastructure can never become an attack-path gate. `replay_simulator.counterfactual` uses the same snapshots for revert-and-retry after a failed exploit action; it records both outcomes to the audit trail and never widens what the agent may execute. Provider credentials (`PROXMOX_API_TOKEN`) live in environment variables only — never in `config.yaml`, never logged.

When adding exploit MCP tools:

- Add policy checks in `ExploitPolicy`.
- Sanitize target arguments with `tools.validation_utils`.
- Write outputs into the workspace rather than arbitrary paths.
- Redact secrets in audit logs.
- Add focused tests.

## Evidence and Audit

Evidence and auditability are part of the safety model:

- `EvidenceStore` records raw output, metadata, hashes, task IDs, findings, and targets.
- `DatabaseManager.log_audit` records important state transitions and actions.
- `OutcomeJudge` records an operator-visible, evidence-linked assessment after
  observation. It can terminate or redirect an investigation path, but it
  cannot authorize a task, change scope, approve risk, unlock a target, or call
  a tool.
- `ActivityLogger` and enhanced reporting capture exploit-session timelines.
- Credential handling should go through `tools/credential_store.py` and avoid printing secrets by default.

## Development Rules

- This is a lab-only build: the attack path is unrestricted-but-target-locked; recon stays fully gated. Do not re-add attack-path content/scope gates without first ensuring the MCP-allowlist target-lock covers the path you de-restrict — the allowlist IS the lock.
- Recon / Flow B safety (`scope_gate.py`, `safety_reviewer.py`, `agent_loop.py`, `tool_router.py`, `risk_controller.py`, `mission.py`, `db.py`) must stay intact — do not edit those for the attack path.
- Require explicit allowlists for target-touching behavior (`require_explicit_allowlist: true` + the `EXPLOIT_TARGET` union is the target lock).
- Default new *recon* features to read-only behavior; new *attack* features inherit the unrestricted-but-locked posture.
- Do not add new network, shell, package install, or file-write paths without tests.
- Keep output sanitization and secret redaction near the boundary where output enters logs, model context, or reports.
- Keep evidential status separate from execution status. New outcome rules may
  reduce/reprioritize activity only; they must remain downstream of the
  existing scope, risk, approval, permission, target-lock, rate-limit, audit,
  and workspace controls.
- For tests, prefer localhost, mocks, and temporary workspaces.

## OPSEC (Advisory Layer)

`tools/opsec.py` provides `OpsecProfile` / `OpsecManager` with `resolve_for_target(ip)` that forces the profile OFF for private/local target IPs (RFC1918/loopback/link-local) and ON for public routable targets, matching the `opsec` config block in CLAUDE.md. It is advisory-only on the attack path: `is_quiet_blocked` / `noise_budget` stay **dormant** and must NOT become attack-path gates — the command always executes. The AI-facing surfaces (`build_opsec_briefing` in `tools/exploit_agent/prompt.py`, `_opsec_advisory_block` in `tools/mcp_tools/terminal/allowlist.py`) render advisory context (noise score, suggested quieter rewrite, pacing posture) only; they never gate execution.

## Plugin Safety

Plugins (`tools/plugins.py`) are trusted Python with full operator-box privileges, OFF by default, enabled via `config plugins.enabled`. Any MCP tool a plugin registers MUST wrap its handler with `ctx.require_allowlist()` (target-touching tools) or `ctx.audit_tool` (free-text command tools) so it inherits the same target-IP lock and audit trail as built-in tools. See `docs/plugin-development.md` section 9 for the full checklist.
