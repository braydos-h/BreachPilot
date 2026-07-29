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
