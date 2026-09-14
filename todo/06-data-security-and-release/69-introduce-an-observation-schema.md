# 69. Introduce an observation schema

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | 30-day |
| Theme | Data, security, and release |
| Dependencies | [#11](../02-architecture-and-agent-security/11-type-debt-matters-more-here-than-in-most-python-projects.md), [#12](../02-architecture-and-agent-security/12-turn-tools-into-declarative-capabilities.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [ ] deduplication;
- [ ] graph construction;
- [ ] planner reasoning;
- [ ] replay;
- [ ] provider-independent prompts;
- [ ] analytics.

## Audit recommendation

Something like:

```python
Observation(
    kind=ObservationKind.SERVICE,
    subject=AssetRef(...),
    confidence=0.98,
    source=ToolInvocationRef(...),
    facts={...},
    evidence=[...],
)
```

This enables:

* deduplication;
* graph construction;
* planner reasoning;
* replay;
* provider-independent prompts;
* analytics.

Raw tool output remains evidence.

Structured observations become intelligence.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 2 — one typed record for saw/did X
- Commits/PRs: working-tree: tools/kernel/observation.py (new: Observation +
  ToolInvocation + make_observation + observation_from_trial_dict bridge),
  tests/test_kernel_contracts.py (3 observation tests)
- Tests/evaluations: tests/test_kernel_contracts.py 7 passed (incl. manifests + budgets)
- Documentation: module docstring defines the schema contract
- Follow-ups: migrate planner/agent-loop/memory call sites to emit Observations;
  add trust labels under #15.

