# Swarm Subsystem

The swarm is the multi-agent execution engine of the offensive path: six
specialist agents cooperate through a shared, thread-safe blackboard, with a
critic gating every non-recon action and a reflection agent adapting strategy
between phases. It lives in `tools/swarm/` and is driven by
`SwarmOrchestrator`, which is itself driven by `AgentLoop`
(Flow B) or the autonomous campaign (Flow A), and can be delegated to from
the main exploit agent via the `spawn_subagent` MCP tools.

## File Map

| File | Responsibility |
|---|---|
| `tools/swarm/__init__.py` | Package exports: `Agent`, `AgentResult`, `AgentStatus`, `SwarmOrchestrator` (`__init__.py:5-13`) |
| `tools/swarm/base.py` | `AgentStatus` enum (`base.py:15-20`), `AgentResult` dataclass with findings/new-tasks/memory/graph/reflection fields (`base.py:23-38`), abstract `Agent` base (`base.py:41-71`) |
| `tools/swarm/blackboard.py` | Thread-safe shared state: `dict` subclass with atomic writes + per-target namespacing (`blackboard.py:48-287`) |
| `tools/swarm/negotiation.py` | Bounded critic↔exploit negotiation (`_negotiate`, `_NEGOTIABLE_KEYS`) + lazy `models.roles` critic-client resolution; bound onto `SwarmOrchestrator` |
| `tools/swarm/milestones.py` | Per-(target, phase) completion events (`_mark_milestone`, `_await_milestone`); bound onto `SwarmOrchestrator` |
| `tools/swarm/state_store.py` | History bounding + `swarm_state.json` persist/load via `tools/kernel/orchestration.py`; bound onto `SwarmOrchestrator` |
| `tools/swarm/reflection_run.py` | `reflect()` dispatch over the battle log; bound onto `SwarmOrchestrator` |
| `tools/swarm/bb_compat.py` | `bb_set`/`bb_append`/`bb_extend`/`bb_remove` bridging the atomic Blackboard API to plain-dict callers (`bb_compat.py:29-89`) |
| `tools/swarm/orchestrator.py` | `SwarmOrchestrator`: task routing, parallel dispatch with milestone gating, battle log, event emission (`orchestrator.py`). Critic negotiation, milestones, state persistence, and reflection dispatch live in submodules and are bound onto the class (same pattern as `tools/campaign/phases.py`) |
| `tools/swarm/skill_phase.py` | Phase → skill-tag mapping used by the advisory skill pipeline (`skill_phase.py:16-59`) |
| `tools/swarm/agents/__init__.py` | Exports the six agents (`agents/__init__.py:5-19`) |
| `tools/swarm/agents/recon_agent.py` | Scanning, tech fingerprinting, attack-surface scoring, downstream task generation |
| `tools/swarm/agents/vuln_agent.py` | NVD/Exploit-DB/web CVE correlation, CVSS scoring, attack-module matching, exploit-path recommendation |
| `tools/swarm/agents/exploit_agent.py` | Attack module auto-selection, PayloadCrafter, adaptive mutation, post-exploit handoff |
| `tools/swarm/agents/post_exploit_agent.py` | Privesc enumeration, credential/loot harvesting, pivot-target generation |
| `tools/swarm/agents/critic_agent.py` | Pre-execution safety review: scope → risk → policy → strategy → LLM |
| `tools/swarm/agents/reflection_agent.py` | Post-phase battle-log analysis, root-cause, strategy shifts, cross-mission lessons |

## Architecture

```
                      ┌─────────────────────────────────────────┐
                      │           AgentLoop / run_service       │
                      │   (task queue, mission, scope, risk)    │
                      └───────────────┬─────────────────────────┘
                                      │ route(task) / run_autonomous_campaign()
                                      ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                     SwarmOrchestrator                        │
   │  route() ── sequential;  route_parallel() ── concurrent      │
   │                                                              │
   │  task ──► [CriticAgent pre-check] ──► [phase agent] ──►      │
   │            approve/deny/modify         result                 │
   │  │                                    │                       │
   │  │  blackboard milestone events  ─────┘   battle_log  ◄──────┘
   │  ▼                                                        │
   │  reflect() ──► ReflectionAgent ──► strategy_shift,        │
   │                 failed/successful_modules                 │
   └───────────────┬───────────────────────────────┬────────────┘
                   │ shared Blackboard             │ events + swarm_state.json
                   ▼                               ▼
   ┌────────────────────────────┐   ┌─────────────────────────────┐
   │  Blackboard (dict subclass)│   │ event_callback → UI / JSONL │
   │  __global__ + per-target   │   │ _persist_state → state file │
   │  buckets, threading.Lock   │   └─────────────────────────────┘
   └────────────────────────────┘
```

The phase→agent mapping is `_DEFAULT_AGENT_MAP` (`orchestrator.py:28-36`):
`recon`→ReconAgent, `analysis`/`test`→VulnAgent, `validate`/`exploit`→
ExploitAgent, `post_exploit`→PostExploitAgent, `report`→ReflectionAgent.

## Agent Roles

All agents subclass `Agent` (`base.py:41`) and implement `run(task, context)`.
`agent_type` is the class name lowercased minus `Agent` (`base.py:51-54`);
`PostExploitAgent.agent_type` is `"postexploit"` (no underscore), which
`skill_phase.py:33-43` aliases back to the post-exploit tag set.

| Agent | Phase(s) | Skills / behaviors | Key refs |
|---|---|---|---|
| ReconAgent | `recon` | Runs the shared `ReconPipeline.recon_host` (`recon_agent.py:180-185`), enriches services with risk scores (`:211`) + banner tech fingerprinting (`:350-366`), assembles OS guess, computes attack-surface score, generates `analysis` tasks for high-risk/web services (`:247-272`), writes `recon_complete`/`discovered_services`/`target_os`/`attack_surface_score`/`technologies` to the blackboard (`:295-299`) | `recon_agent.py:146-346` |
| VulnAgent | `analysis`, `test` | Pulls services from the task or `discovered_services` (`vuln_agent.py:115-116`), NVD + Exploit-DB + web PoC lookup per service (`:175-218`), attack-module matching via `find_modules` with experience-blended ranking (`:220-222`, `:158-169`), confidence scoring (`:225-232`), generates `exploit` tasks at confidence ≥ 0.7 (`:247-260`), optional LLM exploit-path refinement (`:266-275`), writes `vuln_research_complete`/`vulnerability_hypotheses`/`recommended_exploit_path`/`matched_attack_modules` (`:283-289`) | `vuln_agent.py:103-319` |
| ExploitAgent | `exploit`, `validate` | Reads hypotheses/modules/services from the blackboard (`exploit_agent.py:128-131`). **Path A** (live MCP): runs `run_exploit_agent` with the shared session on the main loop (`:231-296`); success requires a *verified* compromise marker, not merely actions run (`:286-292`). **Path B** (no session): runs matched attack modules, falls back to PayloadCrafter (`:299-361`); generated scripts are NOT counted as access. On success writes `access_achieved`/`access_level`/`shell_type`, appends to `compromised_hosts` (`:373-376`), generates a `post_exploit` handoff task + finding (`:394-413`); on failure records `exploit_attempted`/`last_exploit_error` (`:415-416`). Scope gate threaded through `ExploitPolicy` (`:117-125`, `:246-250`) | `exploit_agent.py:102-440` |
| PostExploitAgent | `post_exploit` | Per-attempt loot dir (`post_exploit_agent.py:93-100`), `PostExploitRunner` + `CredentialStore`/`LootStore` persistence (`:98-100`), processes exploit raw output (`:103-122`), enumeration summary (`:125-140`), generates pivot `exploit` tasks for other compromised hosts (`:143-158`), extends `credentials_found`/`loot` on the blackboard (`:171-173`) | `post_exploit_agent.py:55-213` |
| CriticAgent | review (pre-check, not in map) | Runs before every non-`recon`/`report` task (`orchestrator.py:177`). Layers: scope gate (`critic_agent.py:108-119`), risk budget (`:122-127`), forbidden actions (`:130-136`), risk-profile downgrade (`:139-144`), repeat-failure detection on `failed_modules` (`:147-152`), LLM deep review when a model client exists (`:155-167`). Decisions: `approve`/`deny`/`modify`; `deny` blocks the agent (`orchestrator.py:198-226`), `modify` mutates the task (`:228-230`) | `critic_agent.py:91-179` |
| ReflectionAgent | `report`, auto after exploit phases | Heuristic battle-log analysis: what worked/failed (`reflection_agent.py:128-138`), pattern detection (`:143-171`), root-cause (`:174-181`), strategy-shift ladder (`:197-212`), LLM deep reflection (`:215-225`), merges `failed_modules`/`successful_modules` (`:235-251`), persists cross-mission lesson via `semantic_memory.store_lesson` (`:270-287`), records per-skill outcomes (`:297-313`). Auto-run by the orchestrator after `exploit`/`post_exploit` phases (`orchestrator.py:309-311`) and by `AgentLoop` every `reflection_every_n_actions` (`agent_loop.py:920-929`) | `reflection_agent.py:100-328` |

## Mission Lifecycle & Phase Flow

A mission is a `Mission` row (Flow B) or the `swarm_mission_config` dict built
by `run_service._setup_swarm` (`service.py:999-1015`). Tasks enter via
`AgentLoop`'s queue and are dispatched with `self._swarm.route(task)`
(`agent_loop.py:648-649`); swarm-emitted `new_tasks` are merged back into the
queue (`agent_loop.py:672-691`), along with memory and graph updates
(`:692-711`).

```
        ┌───────────────────────────────────────────────────────────────┐
        │                    Swarm phase sequence                        │
        └───────────────────────────────────────────────────────────────┘

  recon ──────────► analysis ──────────► exploit ──────────► post_exploit
  ReconAgent       VulnAgent            ExploitAgent        PostExploitAgent
  scan, fingerprint  CVE/module match   module/PayloadCrafter  privesc/loot
  writes:            writes:            writes:               writes:
   discovered_         vulnerability_     access_achieved,      credentials_found,
   services,           hypotheses,        compromised_hosts,    loot, pivot_targets,
   target_os,          recommended_       shell_type,           post_exploit_complete
   attack_surface_     exploit_path,      exploit_attempted
   score               matched_modules
        │                  │                  │                    │
        │                  ▼                  ▼                    ▼
        │            [CriticAgent pre-check runs BEFORE exploit
        │             and post_exploit; denied ⇒ BLOCKED,         └──► (pivot tasks
        │             modified ⇒ task mutated]                          spawn new
        │                                                               exploit phase)
        └──────────────────────────► reflection ────────────────────────┘
                                    ReflectionAgent (auto after exploit/
                                    post_exploit; also every N actions):
                                    strategy_shift, failed_modules,
                                    successful_modules, semantic lesson
```

Milestone keys on the blackboard seed the run (`orchestrator.py:107-120`):
`recon_complete`, `vuln_research_complete`, `access_achieved`,
`discovered_services`, `vulnerability_hypotheses`, `compromised_hosts`,
`credentials_found`, `pivot_targets`, `loot`, `failed_modules`,
`attack_surface_score`, `strategy_shift`.

## Parallel Phase-3 Execution

`route_parallel` (`orchestrator.py:314-418`) dispatches a task batch with a
semaphore and milestone gating:

- **Recon-first policy** — by default only `recon` + `analysis` parallelize;
  `exploit`/`post_exploit` run sequentially afterwards unless
  `exploit_parallel` (config) or per-task `force_parallel` flips it
  (`orchestrator.py:347-364`).
- **Semaphore** — `asyncio.Semaphore(self._max_parallel)` (`:366`), agents run
  via `run_in_executor` worker threads (`:381-383`).
- **Precondition gating** — a task with `depends_on: [target, phase]` blocks in
  its worker thread on the `threading.Event` milestone (`:374-380`,
  `_await_milestone` at `:519-530`); milestones are marked even on agent
  failure so a failed recon can't wedge dependents (`_mark_milestone`
  `:492-507`). Same-phase different-target tasks don't wait (parallel recon).
- **Order preservation** — results are re-ordered to input order by task_id
  (`:396-418`).

The five concurrency hazards this design fixes are documented at
`orchestrator.py:317-346`: (1) RLock no longer serializes `agent.run`; (2)
thread-safe namespaced Blackboard; (3) atomic list merges; (4) milestone
precondition gating; (5) per-attempt UUID workspaces.

## MCP Bridge into the Swarm

`tools/swarm_bridge.py` `SwarmMcpBridge` connects the sync swarm to the live
MCP `ClientSession` opened by `run_exploit_session`:

- `dispatch(name, args)` (`swarm_bridge.py:103-133`) is the `tool_executor`
  shape: gates through `ExploitPolicy.approve_action`, then hops to the main
  loop (`asyncio.run_coroutine_threadsafe`) and calls `session.call_tool`.
  Returns `BLOCKED: ...` / `TOOL_EXECUTION_ERROR: ...` on gate/exec failure
  (conventions `agent_loop.py` and the tool router already understand).
- `attach(session, schemas, policy, loop)` (`:46-56`) stashes the live session
  so the attack-mode ExploitAgent reads `context["mcp_session"]`,
  `["exploit_tools_schemas"]`, `["main_loop"]` and runs its
  `run_exploit_agent` coroutine on the main loop instead of a fresh one
  (`exploit_agent.py:231-276`).
- Single-session invariant preserved: the swarm shares the ONE session; it
  opens no second one (`swarm_bridge.py:33-36`). The `_EXC_GROUP_CATCH` /
  `_is_exception_group` helpers from `tools/exceptions.py` wrap every
  session-bound call (`swarm_bridge.py:120-131`).

A second delegation surface: `tools/mcp_tools/parallel_agents.py` exposes
`spawn_subagent` / `await_subagent` / `list_subagents` MCP tools that run
swarm agents in-process (Path B, no live session) behind the target-IP
allowlist (`parallel_agents.py:102-130`, allowlist note `:28-34`).

## Blackboard Data Flow

`Blackboard` (`blackboard.py:48`) subclasses `dict` so all legacy
`bb["k"]` / `bb.get("k")` read sites work unchanged — they read the
`__global__` bucket (the old flat-dict view). Write sites must use the atomic
API:

| Write | Semantics |
|---|---|
| `set_scalar(key, value, target=...)` (`blackboard.py:107-114`) | atomic overwrite, auto-creates target bucket |
| `append_to(key, item, target=...)` (`:116-132`) | atomic append, no dedupe |
| `extend_list(key, items, target=..., dedupe=True)` (`:134-163`) | atomic merge, order-preserving dedupe |
| `remove_from_list(key, item, target=...)` (`:165-179`) | atomic filter (reflection's "clear succeeded modules") |

Per-target namespacing: a parallel recon agent on host X writes
`bb_set(bb, "discovered_services", [...], target="10.0.0.5")` into
`targets["10.0.0.5"]`; reads without a target hit `__global__`. This is what
kills the cross-target "last writer wins" race (`blackboard.py:14-28`,
verified by `test_parallel_recon_keeps_all_targets_findings`). Milestone keys
stay global.

`bb_compat` (`bb_compat.py`) bridges the two: if the blackboard has the atomic
method it uses it, otherwise it falls back to plain-dict operations. The
fallback is only reachable from single-threaded test/legacy callers such as
`context = {"blackboard": {}}` (`test_swarm_recon_fix.py:45`); production
through the orchestrator always passes a `Blackboard`
(`orchestrator.py:107-125`).

The orchestrator's own milestone merge (`orchestrator.py:273-296`) extends
list outputs into the blackboard (Bug #18: first-write-wins was a no-op for
lists once the key existed; now merged with dedupe) and forces
`access_achieved` True on any truthy first write. The autonomous path shares
the SAME live blackboard via `share_blackboard()` (`orchestrator.py:469-483`,
wired at `agent_loop.py:1132`) so `AttackModuleExecutor` failures feed the
swarm critic's repeat-failure check (`autonomous_orchestrator.py:896-943`).

## bb_compat — What It Bridges

`tools/swarm/bb_compat.py` bridges the migrated atomic Blackboard write API to
the legacy plain-dict contract (docstring `bb_compat.py:1-22`):

- Production (`SwarmOrchestrator`) passes a real `Blackboard` → atomic path.
- Direct callers and tests passing `{}` (no `set_scalar`/`append_to`...) →
  legacy get-then-set fallback, which is not atomic but runs only where there
  is no concurrency, so the race the atomic API fixes cannot happen there.

The four helpers: `bb_set` (`:29-34`), `bb_append` (`:37-51`),
`bb_extend` (`:54-79`, order-preserving dedupe to match the Blackboard
default), `bb_remove` (`:82-89`).

## skill_phase

`tools/swarm/skill_phase.py` maps each swarm phase to a set of advisory skill
tags (`skill_phase.py:16-44`): recon → `reconnaissance/nmap/network-security/
osint`; vuln → `vulnerability-scanning/cve/vulnerability-triage/cvss`; exploit
→ `exploit-research/exploit/web/api/database/sql-injection`; post_exploit →
`post-exploit/credential/active-directory/privilege-escalation/lateral`
(plus the `postexploit` alias). `critic` and `reflection` return `None`
(`:47`, `:50-59`) meaning "review the full active skill set". The pipeline
helpers (`tools.skill_pipeline.phase_skill_hints` /
`phase_skill_payloads`) use this to give each agent only advisory hints —
never full skill bodies for non-exploit agents (single-MCP-session invariant,
`skill_phase.py:8-12`; verified by `test_vuln_agent_llm_prompt_carries_vuln_hints_only`
and `test_critic_agent_llm_prompt_carries_full_set`).

## Observability

**Events** — emitted through `_emit` (`orchestrator.py:532-539`) to the
`event_callback`, then rendered on console and appended to
`swarm_events.jsonl` by `AgentLoop._persist_event` (`agent_loop.py:446-453`):

| Event | Emitted at |
|---|---|
| `agent_started` | `orchestrator.py:666-673` |
| `agent_complete` / `agent_failed` / `agent_blocked` | `orchestrator.py:244-256` |
| `critic_decision` | `orchestrator.py:188-196` |
| `agent_blocked` (critic deny) | `orchestrator.py:216-224` |
| `blackboard_updated` | `orchestrator.py:293-296` |
| `reflection_output` | `orchestrator.py:446-453` |

**Artifacts** —

- `swarm_state.json` — persisted on every event via `_persist_state`
  (`orchestrator.py:557-596`): agent statuses, the FULL namespaced blackboard
  snapshot (`blackboard_schema: "namespaced"`), `battle_log_tail` (last 20),
  `results_count`, `last_reflection`, `strategy_shift`. Written atomically via
  tmp file + `os.replace` (Windows-safe, `:586-594`).
- `swarm_events.jsonl` — append-only event trail (`agent_loop.py:264, 446`).
- `load_state` (`orchestrator.py:598-656`) restores the blackboard on resume —
  both the namespaced shape (via `merge_snapshot`) and the legacy flat shape.
  `AgentLoop` calls it on resumed missions (`agent_loop.py:286-296`).
- One-line live progress from `swarm_state.json`: `_read_swarm_snapshot`
  (`main.py:247-260`, `tools/run_service/service.py:218-221`).

**History bounding** — `_results` and `_battle_log` are capped at 500 each
(`orchestrator.py:96-97`); `_trim_history` (`:541-555`) drops the head while
persisting every outcome. Consumers only read length + a recent tail
(`battle_log[-20:]` for persist, `[-reflection_interval:]` for reflection), so
no consumed data is lost. `AgentLoop._battle_log` is bounded the same way:
`max(200, reflection_interval * 4)` (`agent_loop.py:311`, trim at `:916-918`).

## Workspace Layout

```
reports/<run_id>/                    # per-run artifacts
├── swarm_workspace/                 # AgentLoop workspace (service.py:1016)
│   ├── swarm_state.json             # orchestrator snapshot (agent_loop.py:263)
│   ├── swarm_events.jsonl           # event trail (agent_loop.py:264)
│   ├── autonomous/                  # AutonomousOrchestrator workspace
│   │   └── attack_states.json       # per-target AttackState resume file
│   │                                #   (agent_loop.py:1126; api reads it at
│   │                                #   runs.py:419-420)
│   └── subagents/<subagent_id>.json # spawn_subagent results
│                                    #   (parallel_agents.py:113)
└── exploit_workspace/<ip>/<attempt_uuid>/   # per-attempt exploit artifacts
                                             #   (exploit_agent.py:163-166)
    └── loot/                        # post-exploit credential/loot JSONL
                                     #   (post_exploit_agent.py:93-100)
```

Tests use throwaway `test_workspace_swarm*` dirs (`test_swarm.py:167, 196,
224, 247`); `exploit_workspace/` and `swarm_workspace/` are gitignored runtime
state (AGENTS.md).

## Launch Paths

**CLI (Flow A)** — `main.py` flags `--swarm`, `--parallel-swarm` (flips
`swarm.parallel_enabled`), `--critic`, `--reflection` (`main.py:363-372`).
`run_service` builds `swarm_mission_config` from the goal/mode
(`service.py:999-1015`), creates the `AgentLoop` with
`tool_executor=swarm_bridge.dispatch` and `state_dir=swarm_workspace`
(`:1016-1023`), attaches the live session via `swarm_bridge.attach(...)`
(`:703`), then in attack mode runs
`swarm_loop.run_autonomous_campaign([target_ip])`, else
`swarm_loop.run(max_cycles)` in a thread (`:1029-1034`). `_wait_swarm`
(`:1096-1140`) polls the swarm task against the swarm timeout
(`long_session.swarm_session_timeout_minutes` override, `config.yaml:322`)
and prints live snapshot progress.

**AgentLoop** — builds the `SwarmOrchestrator` with `max_parallel`,
`critic_enabled`, `reflection_enabled`, the event callback, and the state path
(`agent_loop.py:265-278`); `set_model_client` injects the LLM client into the
swarm context (`:354-364`). Every queued task goes through
`self._swarm.route(task)` (`:648-649`); reflection runs every
`reflection_every_n_actions` (default 10, `:920-929`).

**Autonomous campaign** — `AgentLoop.run_autonomous_campaign`
(`agent_loop.py:1087-1154`) builds an `AutonomousOrchestrator` and wires the
swarm's LIVE blackboard, `model_client`, and fresh `CriticAgent`/
`ReflectionAgent` into `AttackModuleExecutor` (`:1113-1136`) so the
most-aggressive path gets the same multi-layer reasoning
(`autonomous_orchestrator.py:449-459`, `_run_critic` `:830-871`,
`_record_failure_on_blackboard` `:896-919`, `_run_reflection` `:945-985`).
Resume threads `resume=self._resumed` + domain-targeting context (`:1143-1150`).

## Config Keys (`config.yaml`)

```yaml
swarm:
  enabled: true                    # config.yaml:215
  agents: [recon, vuln, exploit, post_exploit, critic, reflection]  # :216-222
  max_parallel_agents: 3           # :223 (read at agent_loop.py:271-273)
  parallel_enabled: false          # :230 gates route_parallel + spawn_subagent
  per_phase_concurrency: 3         # :231
  exploit_parallel: false          # :232 recon-first; true = exploits parallelize
  subagent_timeout_seconds: 600    # :233
autonomous:
  persistence_phase: false         # :240
  checkpoint_every: 0              # :241
  adaptive_replan: false           # :242
  max_cycles: 100                  # :243
  max_pivot_depth: 0               # :244 (single-IP lock default)
long_session:
  swarm_session_timeout_minutes: 30  # :322 overrides the 300s swarm cap
skills:
  swarm_inject: true               # :411
  swarm_phase_hints_only: true     # :412
```

Mission-level keys (`use_swarm`, `critic_enabled`, `reflection_enabled`,
`reflection_every_n_actions`, `adaptive_exploits_enabled`) flow in via the
mission config (`agent_loop.py:241, 274-275, 304, 319-324`).

## Test-Verified Invariants

From `tests/test_swarm*.py` (all mock subprocess/network; no live tools):

- **Routing & lifecycle** (`test_swarm.py`): `agent_type` inferred from class
  name (`:59`); status lifecycle `IDLE→RUNNING→COMPLETE/FAILED/BLOCKED`
  (`:68`); correct agent per phase (`:79`); unknown phase → FAILED (`:88`);
  critic denies high-risk (`:95`) and modifies tasks (`:106`); parallel
  routing returns results (`:115`); reflection on/off (`:128, :139`);
  `swarm.max_parallel_agents` nested key honored, precedence over legacy
  top-level, default 3 (`:173-247`); LLM prompts carry phase-only skill hints
  for vuln and the full set for critic/reflection (`:284-324`).
- **Parallel phase 3** (`test_swarm_parallel_phase3.py`): milestone set after
  `route` and scoped per target (`:77`); `depends_on` waits for the milestone
  (`:93`); 3×0.5s recon finishes < 1.2s = real concurrency (`:152`); all 3
  targets' findings survive (per-target buckets) (`:182`); exploit tasks run
  sequentially by default (`:213`); `force_parallel` overrides (`:252`);
  results preserve input order (`:288`).
- **MCP bridge** (`test_swarm_mcp_bridge.py`): dispatch before attach →
  `BLOCKED` (`:29`); approve → tool called (`:39`); deny → tool NOT called
  (`:58`); call/approve errors → `TOOL_EXECUTION_ERROR` (`:75, :93`);
  `ready()` requires session+policy+loop (`:110`).
- **Observability** (`test_swarm_observability.py`): `agent_started` +
  `agent_complete` emitted (`:10`); critic deny emits `critic_decision` +
  `agent_blocked` and returns BLOCKED (`:43`); `swarm_state.json` written with
  `blackboard_schema: "namespaced"` and `access_achieved` under
  `__global__` (`:82`); `swarm_events.jsonl` appended by AgentLoop (`:118`).
- **History bound** (`test_swarm_history_bound.py`): `_results`/`_battle_log`
  capped at their maxes with newest retained (`:29`); `_trim_history` no-op
  under cap (`:44`).
- **Recon fix** (`test_swarm_recon_fix.py`): ReconAgent calls
  `ReconPipeline.recon_host` exactly once with the target, no
  TypeError/AttributeError (`:41`); `stealth=True` maps to
  `aggression_level="stealth"` (`:81`); output enrichment (risk scores, tech
  fingerprinting, OS guess) and blackboard updates work through a plain dict
  via bb_compat (`:58-77`).

## Interaction with the Autonomous Orchestrator

`AutonomousOrchestrator` (`tools/autonomous_orchestrator.py`) is the
single-target attack engine (recon → exploit → privesc → lateral →
persistence → validation, `:1230-1298`) with its own retry engine
(`RetryEngine` `:336-403`) and state resume (`save_state`/`load_state`
`:2084-2158`). It shares the swarm's blackboard, critic, and reflection
(above), so module outcomes recorded by `AttackModuleExecutor` are visible to
the swarm critic's repeat-failure detection and vice versa — the two paths
are alternative execution paths within a run, never concurrent
(`agent_loop.py:1113-1120`). `run_autonomous_campaign(resume=True)` reuses
prior per-target recon and doesn't re-fire succeeded/failed modules
(`:1156-1162`).

## Swarm vs Campaign: When to Use Which

`--swarm` and the autonomous campaign are alternative execution paths within
a run (never concurrent). One decision rule:

| Situation | Use |
|---|---|
| Single target, want specialist decomposition (parallel recon + vuln research, critic pre-check, reflection strategy shifts) | `--swarm` (add `--critic` / `--reflection`; `--parallel-swarm` for concurrent dispatch) |
| One or many targets, want a persistent multi-phase attack queue (recon → exploit → privesc → lateral → validation) with adaptive aggression, resume, and checkpoints | Autonomous campaign — no `--swarm` (`start_autonomous_campaign` MCP tool or `AgentLoop.run_autonomous_campaign`) |
| Single high-value target, want both breadth and persistence | Combined: a `--swarm` attack run whose `AgentLoop.run_autonomous_campaign` shares the swarm's live blackboard/critic/reflection into `AttackModuleExecutor` |

Both are target-locked by the same MCP-layer allowlist; neither changes the
permission model. Campaign-only knobs (`autonomous.*`, `max_pivot_depth`,
`checkpoint_every`, `adaptive_replan`) have no effect on pure-swarm runs,
and vice versa (`swarm.exploit_parallel`, `negotiation_rounds`).

## Overlap Map: Swarm vs Campaign

| Concern | Swarm (`tools/swarm/`) | Campaign (`tools/campaign/`) | Shared vocabulary |
|---|---|---|---|
| Work item | Task `dict` (`phase`/`target`/`tool`) — lightweight routing envelope | `AttackTask` dataclass (`state.py`) — durable queue item with status/retry/chain links + `to_dict` resume | Intentionally separate: dicts route, dataclasses persist |
| Execution units | 6 agents (recon/vuln/exploit/post_exploit/critic/reflection) | Phases (`phases.py`: recon/exploit/privesc/lateral/validation/…) driving `attack_modules/*` | Attack modules are the shared payload: the swarm ExploitAgent and `AttackModuleExecutor` both dispatch them |
| State | `Blackboard` — volatile cross-agent intel (global + per-target buckets, atomic writes) | `AttackState` per target — durable campaign state (phase/aggression/access/creds/timeline/recon) | Field names align (`access_achieved`, `credentials_found`, `pivot_targets`, `loot`, `failed_modules`); the campaign shares the LIVE blackboard via `share_blackboard()` |
| Retry | Critic `deny`/`modify` + `negotiation_rounds`; reflection pivots after `MAX_MODULE_FAILURES` repeated patterns | `RetryEngine.should_retry` + per-task `max_retries` + campaign `_max_module_failures` cap | `tools/kernel/orchestration.py`: `MAX_MODULE_FAILURES` (3); failure taxonomy (`tools/failure_taxonomy.py`) |
| Progress | `event_callback(event_type, data)` → `swarm_events.jsonl` | `_report_autonomous_progress` ContextVar hook | `tools/kernel/orchestration.py`: `safe_emit` (never-raises contract) |
| Persistence | `swarm_state.json` (`state_path`; throttled, atomic) | `attack_states.json` (opt-in checkpoints + resume) | `tools/kernel/orchestration.py`: `atomic_write_json` |
| Pre-execution gate | `CriticAgent` (scope → risk → policy → repeat-failure → LLM) | `AttackModuleExecutor` scope_gate + critic consult + aggression ceiling | Same critic agent class; the combined run reuses the swarm's live instances |
| Destructive snapshot | `SwarmMcpBridge._snapshot_before_destructive` | `AttackModuleExecutor._snapshot_before_destructive` | `tools/snapshots.py`: `should_snapshot` + fail-open `SnapshotManager` |
