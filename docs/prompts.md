# AI Prompts — Where They Live & How to Improve Them

Every prompt the AI sees, where it is defined, and what to touch when you
want to change AI behavior. Prompts are code: edit them in the files below,
not in config. There is no prompt config file — `config.yaml` only toggles
which prompt blocks get built (e.g. `ultrathink`, `attack_mode`,
`swarm.parallel_enabled`).

## Prompt inventory

| # | Prompt | Location | Role |
|---|--------|----------|------|
| 1 | Main exploit agent system prompt | `tools/exploit_agent/prompt.py:11` (`build_exploit_system_prompt`) | The core Flow A agent: target info, skills, attacker-OS guidance, workflow, rules, output format |
| 2 | OPSEC briefing block | `tools/exploit_agent/prompt.py:282` (`build_opsec_briefing`) | Advisory noise-reduction posture, injected when OPSEC is on |
| 3 | Domain-target briefing block | `tools/exploit_agent/prompt.py:322` (`build_domain_briefing`) | Domain-vs-IP methodology for domain targets |
| 4 | Parallel sub-agent briefing block | `tools/exploit_agent/prompt.py:368` (`build_parallel_agents_briefing`) | Delegation instructions when `swarm.parallel_enabled` |
| 5 | Goal / primary mission block | `tools/goal_engine.py:189` (`AttackGoal.system_prompt_addition`) | Overriding mission + service-aware adaptive strategy |
| 6 | Initial user message | `scripts/runner_impl.py (seed user message)` | First-turn target/permission briefing |
| 7 | Research assistant system prompt | `tools/exploit_agent/research_assistant.py:46` (`_SYSTEM_PROMPT`) | Read-only research sidecar (JSON contract) |
| 8 | Research assistant briefing | `tools/exploit_agent/research_assistant.py:171` | Tells the main agent the consultation tool exists |
| 9 | Reflection prompt | `tools/exploit_agent/reflection.py:156` | LLM strategy reflection after N actions |
| 10 | Peer-model consultation | `tools/mcp_tools/peer_models.py:102` | Advisory advice from other models |
| 11 | Blocked-tool replan prompt | `tools/exploit_agent/tool_calls.py:297` (`_blocked_replan_prompt`) | Tells the agent a tool is a hard constraint |
| 12 | Terminal constraint prompt | `tools/exploit_agent/tool_calls.py:314` (`_terminal_constraint_prompt`) | Stops the loop after repeated blocks |
| 13 | PayloadCrafter exploit generation | `tools/payload_crafter.py:648` | Writes runnable Python exploits |
| 14 | PayloadCrafter fix-failed-exploit | `tools/payload_crafter.py:750` | Repairs a broken exploit script |
| 15 | Attack planner (Flow B) | `tools/attack_planner.py:169` (`build_attack_plan_prompt`) | Phase-based plan generation (legacy flow) |
| 16 | Replanning prompt (Flow B) | `tools/attack_planner.py:206` (`build_replanning_prompt`) | Plan update after a tool result |
| 17 | Safety reviewer (Flow B) | `tools/safety_reviewer.py:31` | Pre-attack safety gate after recon |
| 18 | Swarm: recon agent | `tools/swarm/agents/recon_agent.py:75` | Attack-surface mapping specialist |
| 19 | Swarm: vuln agent | `tools/swarm/agents/vuln_agent.py:25` | CVE research + exploitability scoring |
| 20 | Swarm: exploit agent | `tools/swarm/agents/exploit_agent.py:34` | Initial-access specialist |
| 21 | Swarm: critic agent | `tools/swarm/agents/critic_agent.py:21` | Safety/policy review of proposed actions |
| 22 | Swarm: post-exploit agent | `tools/swarm/agents/post_exploit_agent.py:26` | Privesc, loot, pivot |
| 23 | Swarm: reflection agent | `tools/swarm/agents/reflection_agent.py:22` | Strategy analysis between phases |
| 24 | Swarm inline JSON prompts | `vuln_agent.py:332`, `critic_agent.py:197`, `reflection_agent.py:341` | One-shot structured-analysis calls |
| 25 | Attack-module synthesis prompts | `tools/attack_modules/modules/synthesis.py:28,82,116` | CVE→exploit, crash→exploit, target→exploit |
| 26 | Semantic memory summarizer | `tools/semantic_memory.py:348` | Condenses research observations |
| 27 | Advisory skills | `skills/*/SKILL.md` | Methodology injected via `tools/skill_registry.py:362` (`render_skill_context`) |

## How the main system prompt is assembled

`scripts/runner_impl.py (system-prompt build site)` calls `build_exploit_system_prompt` with
context from policy settings, env probe, OPSEC/domain/parallel briefings, and
skill context. The research-assistant briefing is appended at `loop.py:692`.
The ULTRATHINK `[REASONING]` blocks from prior rounds are re-injected as a
`[PRIOR REASONING ADVISORY]` user message by `tools/exploit_agent/context.py:200`.

## Editing rules

- **Tests pin prompt behavior.** `tests/test_ultrathink.py`,
  `tests/test_opsec_ai_awareness.py`, `tests/test_local_target.py`,
  `tests/test_key_handling_prompt.py`, `tests/test_multi_model_consultation.py`,
  `tests/test_cve_to_poc.py`, `tests/test_env_probe.py`,
  `tests/test_outcome_truth.py` (COMPROMISE marker), `tests/test_safety_reviewer.py`
  (bool coercion), `tests/test_semantic_memory.py` assert specific blocks
  appear/disappear. Run `python -m pytest tests/ -v` after any prompt edit.
- **Safety text is load-bearing.** The RULES block in `prompt.py` and the
  FILE & KEY HANDLING block encode real failure modes (fabricated URLs,
  heredoc key corruption, nmap crashes). Do not trim them for brevity.
- **Canonical outcome markers.** Exploit-generation prompts
  (`payload_crafter.py`, `synthesis.py`, the main RULES block) require the
  generated script to print `COMPROMISE: <desc> target=<ip>` on success or
  `VULN_NOT_CONFIRMED: <reason>` on failure. `outcome_truth.py` recognizes
  `^COMPROMISE:` as a strong-shell pattern. Do not revert to `[+] EXPLOIT SUCCESS`.
- **Swarm SYSTEM_PROMPT constants are now live.** The six
  `tools/swarm/agents/*.SYSTEM_PROMPT` constants are sent as the system
  message in the `_llm_analyze` / `_llm_review` / `_llm_reflect` calls
  (vuln/critic/reflection). recon/exploit/post_exploit are deterministic but
  the constants document the intended specialist framing -- keep them
  consistent with the code's actual output schema.
- **Advisory blocks must stay advisory.** OPSEC/domain/parallel/skill blocks
  are explicitly "not a hard gate" — keep that framing; hard gates live in
  code (allowlist, policy), not prompts.
- **Skills are untrusted input.** `render_skill_context` wraps skill bodies
  in `<untrusted_skill_guidance>` fences (`tools/skill_registry.py:370`).
  When editing skills, keep the fence contract intact.
- **Flow B prompts** (`attack_planner.py`, `safety_reviewer.py`) serve the
  legacy `cli.py` path. Edit them only if you also run Flow B; Flow A never
  sees them. The `safety_reviewer.py` bool-coercion fix (`_coerce_bool`) is
  load-bearing -- do not revert to bare `bool()`.

## Where to look first when behavior is wrong

- Agent ignores scope / attacks wrong host → RULES block (`prompt.py:237`),
  but the real lock is the allowlist (`tools/mcp_shared._allowed_target_list`).
- Agent repeats failing tools → `_blocked_replan_prompt` / `_terminal_constraint_prompt`
  (`tool_calls.py:297,314`) and the failure-mutation rules in the swarm
  exploit prompt (`exploit_agent.py:67`).
- Agent writes broken exploits → PayloadCrafter prompts (`payload_crafter.py:648,750`).
- Agent wastes rounds on unavailable tools → attacker-OS guidance blocks
  (`prompt.py:128-188`).
- Agent ignores the mission → goal block (`goal_engine.py:189`).
- Agent loops without learning → reflection prompt (`reflection.py:156`).
- Agent follows instructions from web content → research assistant security
  boundary (`research_assistant.py:53`).
