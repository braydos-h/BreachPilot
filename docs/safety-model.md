# Safety Model

This project can run powerful security tooling. The codebase relies on layered controls, not a single switch.

## Layers

1. Mission authorization in `mission.py`
2. Scope enforcement in `scope_gate.py`
3. Risk and budget enforcement in `risk_controller.py`
4. Tool routing controls in `tool_router.py`
5. Exploit permission controls in `tools/exploit_agent/`
6. Runtime configuration in `config.yaml`
7. Audit logs, evidence records, and workspace artifacts

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

Any new execution path should call the scope gate before network or system actions. If a change bypasses `ToolRouter`, it must add equivalent checks.

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
explicitly authorized to test, on a throwaway operator box. The attack path is
**unrestricted but target-locked**; recon keeps its full safety.

`tools/exploit_agent/policy.py` defines exploit permissions:

- `full_access` (config + schema default): the lab attack posture.
  `ExploitPolicy.approve_action` auto-approves every action with no command-content
  or scope inspection — destructive commands, egress, reverse shells, credential
  dumping, Metasploit, and Python write/run are all allowed. The `is_full_access`
  branch increments the per-session command budget and returns True. The
  `_check_command_safety` / `_check_scope_gate` / `_gate_pivot_and_count` gates
  were removed from this branch (they remain referenced by the `read_only` /
  `approve_only` recon paths' comments only).
- `approve_only`: require operator approval for sensitive actions (interactive /
  recon paths; unreachable from attack mode).
- `read_only`: gather information and avoid active exploitation. Recon uses this;
  `_resolve_exploit_permission` hard-codes `read_only` as the missing-key fallback
  so a partial config never silently becomes live.

**The one attack-mode safety kept is the target-IP lock (no pivoting to other
hosts).** It is enforced at the MCP tool layer: `tools/mcp_shared._allowed_target_list`
unions `os.environ["EXPLOIT_TARGET"]` (the runtime `--target`, set in
`tools/mcp_session.py`) with `exploit.allowed_targets`; `@require_allowlist` on
every target-touching tool plus `tools/mcp_tools/terminal._target_lock_block`
refuse any destination IP that is not the runtime target. The lock is applied
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
  permission: full_access
  attack_mode: true
  require_explicit_allowlist: true   # the target-IP lock
  allowed_targets: []               # the runtime --target is injected via EXPLOIT_TARGET
  disallowed_assets: []
  forbidden_actions: []
multi_model:
  enabled: false
```

Recon safety is retained: the post-session `SafetyReviewer`, the READ_ONLY
propose-only path, the goal-menu SAFE/GATED narrowing, and the defensive
scope-gated `mcp_server.py` are unchanged.

## MCP Safety Boundary

`mcp_server.py` is a defensive, scope-aware MCP server.

`mcp_exploit_server.py` is not the main safety boundary. It exposes tools for shell execution, script writing/running, package installation, Metasploit, payloads, credential storage, recon, autonomous campaigns, sessions, listeners, and exploit modules. Its file-level docstring explicitly says policy gating is expected in `tools.exploit_agent`.

When `multi_model.enabled` is true, the exploit MCP server also exposes `consult_peer_models`. This is advisory only: peer models receive no MCP tool schemas, cannot execute commands, and their responses must still pass through the main agent and `ExploitPolicy` before any target-touching action occurs.

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
- `ActivityLogger` and enhanced reporting capture exploit-session timelines.
- Credential handling should go through `tools/credential_store.py` and avoid printing secrets by default.

## Development Rules

- This is a lab-only build: the attack path is unrestricted-but-target-locked; recon stays fully gated. Do not re-add attack-path content/scope gates without first ensuring the MCP-allowlist target-lock covers the path you de-restrict — the allowlist IS the lock.
- Recon / Flow B safety (`scope_gate.py`, `safety_reviewer.py`, `agent_loop.py`, `tool_router.py`, `risk_controller.py`, `mission.py`, `db.py`) must stay intact — do not edit those for the attack path.
- Require explicit allowlists for target-touching behavior (`require_explicit_allowlist: true` + the `EXPLOIT_TARGET` union is the target lock).
- Default new *recon* features to read-only behavior; new *attack* features inherit the unrestricted-but-locked posture.
- Do not add new network, shell, package install, or file-write paths without tests.
- Keep output sanitization and secret redaction near the boundary where output enters logs, model context, or reports.
- For tests, prefer localhost, mocks, and temporary workspaces.
