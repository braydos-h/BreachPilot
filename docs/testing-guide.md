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

The suite has **248** files (all mock subprocess/network — no live Nmap); this table covers the most common change types grouped by feature. When in doubt, grep `tests/` for the module name. Run `python -m pytest tests/ -v` for the full list; focused: `python -m pytest tests/test_scope_gate.py -v`.

| Change | Tests to consider |
| --- | --- |
| Mission schema/risk profile | `tests/test_mission.py`, `tests/test_config_manager.py` |
| Scope matching/rate limits | `tests/test_scope_gate.py` |
| Risk budgets/approval | `tests/test_risk_controller.py` |
| Task lifecycle/planning | `tests/test_task_queue.py`, `tests/test_agent_loop.py` |
| Hypothesis/outcome judgment | `tests/test_outcome_judge.py`, `tests/test_cross_mission_wiring.py` |
| Evidence/finding/reporting | `tests/test_evidence.py`, `tests/test_finding_verifier.py`, `tests/test_report_generator.py` |
| Recon pipeline | `tests/test_recon_pipeline.py`, `tests/test_recon_first_session.py` |
| MCP workspace/tool behavior | `tests/test_mcp_workspace.py`, `tests/test_mcp_tool_registration.py`, `tests/test_mcp_tool_scope.py`, `tests/test_mcp_web_scan.py`, `tests/test_mcp_cracking.py`, `tests/test_mcp_runtime_skills.py`, `tests/test_mcp_injection_hardening.py`, relevant safety tests |
| MCP transport / sessions | `tests/test_mcp_http_lifecycle.py`, `tests/test_mcp_http_hardening.py`, `tests/test_mcp_shared_helpers.py`, `tests/test_mcp_tool_registration.py` |
| Exploit modules | `tests/test_attack_modules.py`, `tests/test_attack_modules_api.py`, `tests/test_lateral_tools.py`, `tests/test_exploit_mutator.py`, `tests/test_exploit_permission.py`, `tests/test_exploit_scope_gate.py` |
| Exploit agent retry/context | `tests/test_retry_logic.py`, `tests/test_ultrathink.py`, `tests/test_honest_retries.py`, `tests/test_context_compaction.py` |
| Swarm behavior | `tests/test_swarm.py`, `tests/test_swarm_integration.py`, `tests/test_swarm_observability.py`, `tests/test_swarm_parallel_phase3.py`, `tests/test_swarm_dynamic_composition.py`, `tests/test_swarm_history_bound.py`, `tests/test_swarm_negotiation.py`, `tests/test_blackboard_concurrency.py`, `tests/test_spawn_subagent.py` |
| Swarm bridge / parallel agents | `tests/test_swarm_mcp_bridge.py`, `tests/test_swarm_recon_fix.py`, `tests/test_phase4_bugfixes.py` |
| Interactive menu / attack UI | `tests/test_interactive_menu.py`, `tests/test_cli_mission_id.py`, `tests/test_startup_noise.py` |
| Config/doctor/self-test/validation | `tests/test_config_manager.py`, `tests/test_config_cli.py`, `tests/test_config_cli_domain.py`, `tests/test_doctor.py`, `tests/test_self_test.py`, `tests/test_validate_target.py`, `tests/test_sudo_pivot.py`, `tests/test_workspace_binary_write.py`, `tests/test_env_probe.py` |
| OPSEC / detection coverage | `tests/test_opsec_manager.py`, `tests/test_opsec_target_aware.py`, `tests/test_opsec_orchestrator_wiring.py`, `tests/test_opsec_ai_awareness.py`, `tests/test_detection_coverage.py`, `tests/test_detection_modules.py` |
| Plugins / Shodan / GitHub dorks / extensions | `tests/test_plugins.py`, `tests/test_plugin_wiring.py`, `tests/test_plugins_shodan_github_dorks.py`, `tests/test_example_plugin.py`, `tests/test_bloodhound_ce.py`, `tests/test_sliver_plugin.py`, `tests/test_spiderfoot_plugin.py`, `tests/test_zap_scan.py`, `tests/test_browser_attack.py`, `tests/test_mobile_attack.py`, `tests/test_wireless_plugin.py`, `tests/test_snmp_plugin.py`, `tests/test_caldera_plugin.py`, `tests/test_firmware_plugin.py`, `tests/test_atomic_tests.py` |
| Domain targeting / subdomain | `tests/test_domain_allowlist.py`, `tests/test_domain_mcp_tools.py`, `tests/test_config_cli_domain.py`, `tests/test_subdomain_boundary.py`, `tests/test_vhost_discovery.py` (via recon), `tests/test_recon_mcp_new_tools.py` |
| Active Directory / Kerberos | `tests/test_ad_mcp_tools.py`, `tests/test_ad_kerberos_modules.py` |
| Supply chain / persistence / orchestrator phases | `tests/test_supply_chain_modules.py`, `tests/test_persistence_modules.py`, `tests/test_orchestrator_phase_modules.py`, `tests/test_orchestrator_semantic_memory.py`, `tests/test_orchestrator_failure_taxonomy.py` |
| Autonomous orchestrator / campaign | `tests/test_autonomous_phase_machine.py`, `tests/test_autonomous_persistence_checkpoint_replan.py`, `tests/test_autonomous_local_target.py`, `tests/test_autonomous_config.py`, `tests/test_autonomous_evidence_ranking.py`, `tests/test_campaign_checkpoint.py`, `tests/test_api_campaign_checkpoint.py` |
| Recon enrichers / OSINT / diff / extended | `tests/test_recon_enrichers.py`, `tests/test_recon_osint.py`, `tests/test_recon_spider_osint.py`, `tests/test_recon_diff.py`, `tests/test_recon_udp_tls_smtp_db.py`, `tests/test_recon_extended_enumerators.py`, `tests/test_recon_assessment_cve_queries.py`, `tests/test_recon_mcp_new_tools.py`, `tests/test_recon_pipeline.py`, `tests/test_recon_first_session.py`, `tests/test_recon_event_and_allowlist.py`, `tests/test_recon_spider_osint.py`, `tests/test_target_preflight.py`, `tests/test_socket_scan.py`, `tests/test_service_banner_parsing.py`, `tests/test_service_extraction.py`, `tests/test_nmap_priv.py` |
| Resume flow / learning loop | `tests/test_resume_flow_a.py`, `tests/test_resume_mission.py`, `tests/test_learning_loop.py`, `tests/test_cross_mission_wiring.py` |
| Skill registry / embeddings / feedback / pipeline / CLI / selector | `tests/test_skill_registry.py`, `tests/test_skill_registry_cache.py`, `tests/test_skill_embeddings.py`, `tests/test_skill_feedback.py`, `tests/test_skill_pipeline.py`, `tests/test_skill_reselection.py`, `tests/test_skills_cli.py`, `tests/test_skill_selector.py`, `tests/test_skill_selector_domain.py`, `tests/test_skill_author.py`, `tests/test_skills_api.py` |
| Model routing / telemetry / ultrathink / chatgpt | `tests/test_model_router.py`, `tests/test_model_router_alias_and_spam.py`, `tests/test_model_telemetry.py`, `tests/test_ultrathink.py`, `tests/test_chatgpt_provider.py` |
| Peer consultation / multi-model | `tests/test_multi_model_consultation.py`, `tests/test_peer_consult_on_failure.py`, `tests/test_peer_outcome_judge.py` |
| Reasoning loop / reflection | `tests/test_reasoning_loop.py`, `tests/test_reflection_evidential_bridge.py`, `tests/test_capability_guidance_prompt.py`, `tests/test_key_handling_prompt.py` |
| Tool calls / parsing / outcome tracking / registry | `tests/test_tool_call_parse_split.py`, `tests/test_tool_outcome_tracker.py`, `tests/test_tool_router_approval.py`, `tests/test_outcome_classify.py`, `tests/test_outcome_judge_flow_a.py`, `tests/test_tool_catalog.py`, `tests/test_registry_complete.py` |
| Validation / target / sudo pivot / workspace | `tests/test_validate_target.py`, `tests/test_sudo_pivot.py`, `tests/test_workspace_binary_write.py`, `tests/test_scanner_target_extraction.py` |
| CLI config / Wiring | `tests/test_config_cli.py`, `tests/test_cli_mission_id.py`, `tests/test_startup_noise.py`, `tests/test_api_cli_args.py`, `tests/test_github_token_bootstrap.py`, `tests/test_git_clone_preflight.py` |
| CVE / exploit synthesis / SSRF / cloud | `tests/test_cve_to_poc.py`, `tests/test_cve_lookup_concurrency.py`, `tests/test_cve_templates_phase4.py`, `tests/test_cve_lookup.py`, `tests/test_epss_kev.py`, `tests/test_msf_recipes.py`, `tests/test_version_aware_ranking.py`, `tests/test_weaponized_cloud_k8s_modules.py`, `tests/test_ssrf_xxe_lfi_modules.py`, `tests/test_tier4_correctness.py`, `tests/test_cloud_exploit.py` |
| Cross-mission / research subsystem | `tests/test_cross_mission_wiring.py`, `tests/test_research_subsystem.py`, `tests/test_research_assistant.py`, `tests/test_intelligence_adapter*.py`, `tests/test_intelligence_*.py` |
| Context compaction / attack memory / brute-force | `tests/test_context_compaction.py`, `tests/test_attack_memory.py`, `tests/test_intelligence_fingerprint.py`, `tests/test_intelligence_memory.py` |
| Rate limiting / reliability / recovery | `tests/test_rate_limiter.py`, `tests/test_reliability_bugs.py`, `tests/test_retry_logic.py`, `tests/test_campaign_checkpoint.py` |
| API / WebUI / runs / events | `tests/test_api_auth.py`, `tests/test_api_runs.py`, `tests/test_api_events.py`, `tests/test_api_persistence.py`, `tests/test_api_memory.py`, `tests/test_api_webui.py`, `tests/test_api_frontend.py`, `tests/test_run_manager.py`, `tests/test_run_log.py`, `tests/test_api_models.py`, `tests/test_graph_explorer_api.py`, `tests/test_graph_route.py`, `tests/test_api_reset.py`, `tests/test_api_cli_args.py` |
| Assessment state / capability / decision log | `tests/test_assessment_state_mcp_tools.py`, `tests/test_module_capability_metadata_a.py`, `tests/test_module_capability_metadata_b.py`, `tests/test_capability_guidance_prompt.py`, `tests/test_decision_log_hook.py`, `tests/test_task_graph_simulations.py` |
| Evidence / audit / credential | `tests/test_evidence.py`, `tests/test_evidence_bridge.py`, `tests/test_enhanced_reporting_evidence.py`, `tests/test_flow_a_enhanced_report.py`, `tests/test_credential_store.py`, `tests/test_audit_redaction.py`, `tests/test_audit_chain.py`, `tests/test_audit_memory_bound.py`, `tests/test_activity_log.py`, `tests/test_run_log.py` |
| ICS / IoT / MITRE / webhook / ticketing | `tests/test_ics_exploit.py`, `tests/test_ics_iot_modules.py`, `tests/test_mitre_export.py`, `tests/test_webhook_notify.py`, `tests/test_ticketing.py`, `tests/test_threat_intel.py` |
| Spinner / environment / logging | `tests/test_spinner_release.py`, `tests/test_env_probe.py`, `tests/test_logging_setup.py` |
| Capability upgrade / wiring | `tests/test_witness_agent.py`, `tests/test_attack_modules_api.py`, `tests/test_bel_adversarial.py`, `tests/test_ctf_mode.py`, `tests/test_local_target.py` |
| Credential store / audit redaction / PoC verifier | `tests/test_credential_store.py`, `tests/test_audit_redaction.py`, `tests/test_audit_chain.py`, `tests/test_poc_verifier.py`, `tests/test_poe_verifier.py`, `tests/test_replay_simulator.py`, `tests/test_session_titler.py` |

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
