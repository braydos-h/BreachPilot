# Testing Guide

## Run Tests

Run the full suite:

```bash
python -m pytest
```

Run a focused file:

```bash
python -m pytest tests/test_scope_gate.py
```

Run a specific test:

```bash
python -m pytest tests/test_attack_modules.py::TestModuleRegistry::test_list_modules_returns_all
```

Run smoke checks:

```bash
python main.py --doctor
python main.py --self-test
python tests/test_new_modules.py
```

## What To Test By Change Type

The suite has ~100 files; this table covers the most common change types. When in doubt, grep `tests/` for the module name.

| Change | Tests to consider |
| --- | --- |
| Mission schema/risk profile | `tests/test_mission.py`, `tests/test_config_manager.py` |
| Scope matching/rate limits | `tests/test_scope_gate.py` |
| Risk budgets/approval | `tests/test_risk_controller.py` |
| Task lifecycle/planning | `tests/test_task_queue.py`, `tests/test_agent_loop.py` |
| Hypothesis/outcome judgment | `tests/test_outcome_judge.py`, `tests/test_cross_mission_wiring.py` |
| Evidence/finding/reporting | `tests/test_evidence.py`, `tests/test_finding_verifier.py`, `tests/test_report_generator.py` |
| Recon pipeline | `tests/test_recon_pipeline.py`, `tests/test_recon_first_session.py` |
| MCP workspace/tool behavior | `tests/test_mcp_workspace.py`, relevant safety tests |
| Exploit modules | `tests/test_attack_modules.py`, `tests/test_lateral_tools.py` |
| Exploit agent retry/context | `tests/test_retry_logic.py`, `tests/test_ultrathink.py` |
| Swarm behavior | `tests/test_swarm.py`, `tests/test_swarm_integration.py`, `tests/test_swarm_observability.py` |
| Interactive menu | `tests/test_interactive_menu.py` |
| Config/doctor/self-test | `tests/test_config_manager.py`, `tests/test_doctor.py`, `tests/test_self_test.py` |
| OPSEC / detection coverage | `tests/test_opsec_manager.py`, `tests/test_opsec_target_aware.py`, `tests/test_opsec_orchestrator_wiring.py`, `tests/test_opsec_ai_awareness.py`, `tests/test_detection_coverage.py`, `tests/test_detection_modules.py` |
| Plugins | `tests/test_plugins.py`, `tests/test_plugin_wiring.py` |
| Domain targeting | `tests/test_domain_allowlist.py`, `tests/test_domain_mcp_tools.py`, `tests/test_config_cli_domain.py` |
| Active Directory | `tests/test_ad_mcp_tools.py`, `tests/test_ad_kerberos_modules.py` |
| Supply chain / persistence | `tests/test_supply_chain_modules.py`, `tests/test_persistence_modules.py` |
| Autonomous orchestrator | `tests/test_autonomous_phase_machine.py`, `tests/test_autonomous_persistence_checkpoint_replan.py`, `tests/test_autonomous_local_target.py`, `tests/test_autonomous_config.py`, `tests/test_orchestrator_phase_modules.py` |
| Recon enrichers / OSINT / diff | `tests/test_recon_enrichers.py`, `tests/test_recon_osint.py`, `tests/test_recon_spider_osint.py`, `tests/test_recon_diff.py`, `tests/test_recon_udp_tls_smtp_db.py`, `tests/test_recon_extended_enumerators.py`, `tests/test_recon_assessment_cve_queries.py`, `tests/test_recon_mcp_new_tools.py` |
| Resume flow | `tests/test_resume_flow_a.py`, `tests/test_resume_mission.py` |
| Skill registry / embeddings / feedback / pipeline / CLI | `tests/test_skill_registry.py`, `tests/test_skill_registry_cache.py`, `tests/test_skill_embeddings.py`, `tests/test_skill_feedback.py`, `tests/test_skill_pipeline.py`, `tests/test_skill_reselection.py`, `tests/test_skills_cli.py` |
| Model routing / telemetry / ultrathink | `tests/test_model_router.py`, `tests/test_model_telemetry.py`, `tests/test_ultrathink.py` |
| Peer consultation | `tests/test_multi_model_consultation.py`, `tests/test_peer_consult_on_failure.py` |
| Reasoning loop | `tests/test_reasoning_loop.py`, `tests/test_reflection_evidential_bridge.py` |
| Tool calls / parsing / outcome tracking | `tests/test_tool_call_parse_split.py`, `tests/test_tool_outcome_tracker.py`, `tests/test_tool_router_approval.py`, `tests/test_outcome_classify.py`, `tests/test_outcome_judge_flow_a.py` |
| Validation / target / sudo pivot | `tests/test_validate_target.py`, `tests/test_sudo_pivot.py`, `tests/test_workspace_binary_write.py` |
| CLI config | `tests/test_config_cli.py`, `tests/test_cli_mission_id.py`, `tests/test_startup_noise.py` |
| CVE / exploit synthesis | `tests/test_cve_to_poc.py`, `tests/test_cve_lookup_concurrency.py`, `tests/test_msf_recipes.py`, `tests/test_version_aware_ranking.py`, `tests/test_weaponized_cloud_k8s_modules.py`, `tests/test_ssrf_xxe_lfi_modules.py`, `tests/test_tier4_correctness.py` |
| Cross-mission / research subsystem | `tests/test_cross_mission_wiring.py`, `tests/test_research_subsystem.py`, `tests/test_research_assistant.py` |
| Context compaction / attack memory | `tests/test_context_compaction.py`, `tests/test_attack_memory.py` |
| Rate limiting / reliability | `tests/test_rate_limiter.py`, `tests/test_reliability_bugs.py`, `tests/test_retry_logic.py` |
| Spinner / environment | `tests/test_spinner_release.py` |
| Phase4 bugfixes / swarm recon fix / swarm MCP bridge | `tests/test_phase4_bugfixes.py`, `tests/test_swarm_recon_fix.py`, `tests/test_swarm_mcp_bridge.py` |
| Credential store / audit redaction | `tests/test_credential_store.py`, `tests/test_audit_redaction.py`, `tests/test_audit_chain.py` |
| POE verifier | `tests/test_poe_verifier.py` |

## Test Workspace Pattern

Many tests use temporary or dedicated workspaces. Keep this pattern:

- Use temporary directories for generated files.
- Avoid writing into real `reports/` or `exploit_workspace/` unless a test is explicitly checking that behavior.
- Use localhost or mocked command execution for network/security tests.
- Keep regression fixtures small and readable.

## External Dependencies

Some runtime features require tools that may not be present on every developer machine:

- `nmap`
- Ollama and configured models
- Metasploit
- `searchsploit`
- system package managers
- Unix session tooling

Unit tests should mock these where possible. `--doctor` and `--self-test` are the right place to validate local machine readiness.

## Outcome-Judgment Regressions

`tests/test_outcome_judge.py` is deterministic and requires no network tools or
model. It covers execution/evidence separation, matching and contradictory
structured evidence, single versus repeated inconclusive attempts, duplicate
check rejection, terminal-state planning guards, restart persistence, and
version-3 database migration. Existing scope, approval, target-lock, and risk
tests remain the safety regression suite; outcome judgment does not replace
those gates.

## Before Handoff

For small changes, run the focused tests that match the touched module.

For cross-cutting changes, run:

```bash
python -m pytest
python main.py --doctor
python main.py --self-test
```

If a command cannot run because a local external tool is missing, note that in the handoff and include the focused tests that did run.
