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
  -> select model with tools.model_router
  -> start/connect mcp_exploit_server.py
  -> build tool list for Ollama
  -> tools.exploit_agent.run_exploit_agent
  -> optional consult_peer_models advisory calls when multi_model is enabled
  -> tools.model_router records metadata-only LLM usage telemetry
  -> ExploitPolicy evaluates requested tool calls
  -> MCP tool executes if permitted
  -> result is sanitized, summarized, audited, and returned to model
```

Important controls:

- `config.yaml` controls `exploit.permission`, `attack_mode`, command limits, round limits, target allowlist, and workspace paths.
- `multi_model.enabled` or `--multi-model-consult` exposes an advisory peer-model tool; peer models receive no tool schemas and cannot execute commands.
- Model telemetry is written to `research_workspace/logs/llm_usage.jsonl`.
- `ExploitPermission` supports `read_only`, `approve_only`, and `full_access`.
- `ExploitPolicy` is the place to update approval rules for exploit tools.
- `mcp_exploit_server.py` exposes powerful primitives and should not be treated as a safety boundary by itself.

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

## Report Flow

```text
validated finding
  -> FindingVerifier marks report_ready
  -> ReportGenerator.generate_report
  -> ReportGenerator.export_report
  -> reports/ markdown output
```

Report generation should stay evidence-linked, reproducible, and conservative in severity wording.
