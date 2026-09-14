# 11. Type debt matters more here than in most Python projects

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — ratchet held, 276 vs 359) |
| Suggested priority | P1 |
| Suggested horizon | 30-day |
| Theme | Architecture and agent security |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [ ] frozen dataclasses;
- [ ] enums;
- [ ] `TypedDict` only at serialization boundaries;
- [ ] Pydantic request/response models;
- [ ] protocols for providers;
- [ ] explicit result types.

## Audit recommendation

The project has reduced tracked mypy debt, but still records around **276 suppressed/known errors** and broad disabled categories in `pyproject.toml`.

This isn't cosmetic for BreachPilot.

Your system moves security-sensitive structured values:

```text
target
scope
authorization verdict
tool
arguments
credential
agent state
evidence
finding state
sandbox policy
```

A wrong `Optional`, malformed dictionary or ambiguous return type could translate into behavioural differences.

## Focus typing here first

Not alphabetically.

Prioritize:

```text
ScopePolicy
ToolInvocation
ToolResult
AgentState
AssessmentRun
Finding
Evidence
AuthorizationDecision
SandboxPolicy
Target
CredentialRef
```

Use:

* frozen dataclasses;
* enums;
* `TypedDict` only at serialization boundaries;
* Pydantic request/response models;
* protocols for providers;
* explicit result types.

Then gradually remove the huge `disable_error_code` list.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: slice done (no new debt; new modules clean); full elimination is long-tail
- Design/issue: Wave 2 — typed security boundaries over zero-error-everywhere
- Commits/PRs: this session added ~2,000 lines across 10 new modules, all mypy-clean
  standalone (observation, budgets, manifest, checkpoint, damage, provider_compare,
  release_gate); whole-tree debt unchanged at 276 (was 359 at audit)
- Tests/evaluations: mypy standalone clean on all new modules; strict zero-disable
  tiers (validation_utils, exceptions, mcp_shared, kernel.*, sandbox.*) intact;
  scripts/mypy_debt.py gate prevents growth in CI
- Documentation: n/a (no contract change)
- Follow-ups: pay down run_manager (35) / _impl (31) / attack_ui (24) file by file.

