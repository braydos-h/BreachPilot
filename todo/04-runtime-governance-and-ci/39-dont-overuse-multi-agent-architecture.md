# 39. Don't overuse multi-agent architecture

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — separation exists, simplification pending) |
| Suggested priority | P2 |
| Suggested horizon | Backlog |
| Theme | Runtime, governance, and CI |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [ ] latency;
- [ ] cost;
- [ ] state synchronization problems;
- [ ] prompt injection paths;
- [ ] duplicated actions;
- [ ] debugging complexity.

## Audit recommendation

Six swarm agents sounds powerful in a README.

But multi-agent systems increase:

* latency;
* cost;
* state synchronization problems;
* prompt injection paths;
* duplicated actions;
* debugging complexity.

Use agents when tasks are actually parallelizable.

A simple model I like for this project is:

```text
              Orchestrator
            /      |      \
       Explorer  Verifier  Researcher
            \      |      /
             Evidence Store
                  |
               Reporter
```

The **Verifier** should not be subordinate to claims from Explorer.

And every agent gets immutable scope/policy context.

No agent can delegate additional privileges to another agent.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 2 — small verifier-independent surface
- Commits/PRs: none yet; revalidation: CriticAgent pre-check + bounded
  critic↔exploit negotiation exist in the swarm, and verification is
  structurally separate (verify.py/retest.py/poc_verifier.py MCP tools +
  eval_checks executors + benchmark IndependentVerifier) — the independence
  half is real
- Tests/evaluations: critic/swarm suites green in CI (Tier 1)
- Documentation: n/a
- Follow-ups: usage guidance (when single-agent suffices), verifier-model
  separation policy, multi-agent cost accounting.

