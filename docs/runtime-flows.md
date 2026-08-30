# Runtime Flows

## Mission Creation Flow

```text
mission.yaml or CLI configuration
  -> mission.Mission.from_yaml_or_dict
  -> Mission.validate
  -> MissionController.create_from_config
  -> db.DatabaseManager.create_mission
  -> scope rules persisted
  -> workspace/evidence/report directories initialized
```

Use this flow when changing mission schema, risk profiles, scope behavior, or CLI mission creation.

## Database-Backed Research Loop

`agent_loop.py` is the clearest description of the original agent workflow:

```text
MissionController
  -> ScopeGate
  -> PlannerAgent
  -> TaskQueue
  -> ExecutorAgent
  -> ToolRouter
  -> ObserverAgent
  -> OutcomeJudge
  -> HypothesisRepository
  -> EvidenceStore
  -> MemoryManager
  -> TargetGraph
  -> FindingVerifier
  -> ReportGenerator
```

Key rules:

- Planner creates scoped, phase-based tasks.
- TaskQueue chooses pending work by priority.
- Executor only executes approved tasks and delegates scope enforcement to ToolRouter.
- Observer extracts facts and possible findings, but does not validate vulnerabilities.
- OutcomeJudge evaluates structured facts against task criteria after both
  successful and failed executions. Execution status remains on the task;
  hypothesis status is persisted separately.
- Confirmed, refuted, and exhausted hypotheses block pending/replanned checks.
  An inconclusive hypothesis can continue only with a materially different
  check fingerprint.
- The learning loop records positive experience for confirmed hypotheses and
  negative experience for refuted hypotheses only. Inconclusive/exhausted
  judgments do not reinforce tools or strategies, and learning metadata keeps
  the evidence references.
- FindingVerifier owns validation state.
- EvidenceStore keeps raw outputs linked to tasks/findings.

The judgment sequence is:

```text
ExecutionResult (succeeded / failed / blocked)
  + structured Observation
  + task success_criteria / stop_conditions
  + evidence references
  -> OutcomeAssessment
  -> hypothesis status (open / confirmed / refuted / inconclusive / exhausted)
  -> operator event + audit record
  -> optional evidence-supported experience
  -> next planning cycle
```

Blocked checks are normally handled before observation and do not consume a
hypothesis attempt. A failed command can still yield useful structured evidence,
but the error itself is never treated as a refutation.

## Recon-First Flow

`main.py --recon-first` or default recon-first behavior:

```text
target
  -> tools.recon_pipeline
  -> service/OS/port findings
  -> tools.goal_suggester
  -> operator chooses or confirms goal
  -> exploit/recon session continues with selected goal
```

Use this path when working on target fingerprinting, goal suggestions, or first-run operator experience.

## Exploit Session Flow

```text
main.py
  -> load config
  -> select model with tools.model_router (provider = models.provider: ollama|chatgpt)
  -> start/connect mcp_exploit_server.py
  -> build tool list (OpenAI-shaped; forwarded unchanged to either provider)
  -> tools.exploit_agent.run_exploit_agent
  -> optional consult_peer_models advisory calls when multi_model is enabled
  -> tools.model_router records metadata-only LLM usage telemetry (provider-attributed)
  -> ExploitPolicy evaluates requested tool calls
  -> MCP tool executes if permitted
  -> result is sanitized, summarized, audited, and returned to model
```

The model client is built by `tools/model_router.py::_build_model_client`, the
single provider seam: `provider: ollama` (default) constructs an
`ollama.Client`; `provider: chatgpt` injects a `ChatGptProxyClient`
(`tools/providers/chatgpt_provider.py`) that POSTs to the vendored
openai-oauth loopback proxy at `127.0.0.1:10531/v1`. Both wrap into the same
`ModelClient`/`ModelRouter` surface, so the rest of the flow is provider-agnostic.
Embeddings stay on Ollama under either provider. See
[docs/providers.md](providers.md).

The session boot is wrapped by `tools/mcp_session.py:open_exploit_mcp_session` (async context manager emitting `[BOOT]`/`[OK]` markers); single-target orchestration is `tools/exploit_session.py:run_exploit_session`; `tools/swarm_bridge.py:SwarmMcpBridge` bridges the sync swarm `tool_executor` onto the live MCP `ClientSession`.

Important controls:

- `config.yaml` controls `exploit.permission`, `attack_mode`, command limits, round limits, target allowlist, and workspace paths.
- `multi_model.enabled` or `--multi-model-consult` exposes an advisory peer-model tool; peer models receive no tool schemas and cannot execute commands.
- Model telemetry is written to `research_workspace/logs/llm_usage.jsonl`.
- `ExploitPermission` supports `read_only`, `approve_only`, and `full_access`.
- `ExploitPolicy` is the place to update approval rules for exploit tools.
- `mcp_exploit_server.py` exposes powerful primitives and should not be treated as a safety boundary by itself.

## Domain Targeting Flow

When the operator passes `--target example.com`, `main.py` resolves it via `tools/validation_utils.resolve_target_to_ip`, then threads `original_target` (the domain) and `resolved_ip` through `run_exploit_session` → `open_exploit_mcp_session`. The MCP server subprocess receives `EXPLOIT_TARGET`, `EXPLOIT_TARGET_IP`, and `EXPLOIT_TARGET_DOMAIN` env vars, so the allowlist locks to the resolved IP plus the domain. Subdomain expansion (mid-run) auto-authorizes each discovered `(subdomain, ip)` pair via `tools/mcp_shared.add_discovered_target`, which appends to `EXPLOIT_DISCOVERED_TARGETS`. Five domain MCP tools live in `tools/mcp_tools/domain.py`: `resolve_domain`, `enumerate_subdomains`, `dns_recon`, `vhost_enum`, `domain_whois`. A `DOMAIN TARGET BRIEFING` is injected into the agent system prompt telling it to use the domain for Host/SNI and the IP for nmap/metasploit.

## Defensive MCP Flow

```text
MCP client
  -> mcp_server.py
  -> allowlist normalization
  -> target validation
  -> nmap or limited terminal command
  -> structured result
```

Defensive tools include ping sweep, triage scan, basic scan, service scan, vuln scan, limited terminal, vulnerability intel, and CVE intel. This server is the safer integration surface for scan-only clients.

## Swarm Flow

```text
task/context
  -> tools.swarm.orchestrator.SwarmOrchestrator
  -> critic pre-check where enabled
  -> specialist agent selected by task type
  -> blackboard and battle log updated
  -> optional reflection pass
```

Use the swarm path for multi-agent strategy, parallel routing, blackboard state, and battle-log observability changes.

## Autonomous Orchestrator Flow

`tools/autonomous_orchestrator.py` drives persistent multi-phase campaigns (recon -> vuln -> exploit -> post-exploit) with adaptive aggression levels, auto-retry on failure with modified parameters, vulnerability chaining, and privilege-escalation tracking. It is a SEPARATE campaign engine from the swarm (which is parallel specialist decomposition) and can be used independently. It is target-locked by `scope_gate.check_scope(asset=task.target)`, and its `max_pivot_depth` defaults to 0 (no host-pivoting recursion).

## Report Flow

```text
validated finding
  -> FindingVerifier marks report_ready
  -> ReportGenerator.generate_report
  -> ReportGenerator.export_report
  -> reports/ markdown output
```

Report generation should stay evidence-linked, reproducible, and conservative in severity wording.

## Plugin Load Flow

`tools/plugins.load_plugins(config)` runs once during boot before the MCP exploit server is created. It discovers filesystem plugins under `plugins/` (configurable via `plugins.search_paths`) plus entry-point plugins in the `breachpilot.plugins` group. Only enabled plugins are registered; each `Plugin.register(registry)` contributes attack modules, MCP tool factories, skill dirs, and config sections to the shared `PLUGIN_REGISTRY`.
