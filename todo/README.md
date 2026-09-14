# BreachPilot reliability backlog

This folder turns the September 2026 repository assessment into assignable work
packets. The current milestone is reliability and proof, not expansion of the
scanner, attack-module, agent, integration, or UI surface.

## Milestone outcome

> Given a known vulnerable lab target, BreachPilot can autonomously pursue the
> correct branch, remain in scope, avoid repeating failed actions, declare
> success only after independent evidence, and reproduce that performance
> across repeated graded runs.

## Assignment board

| Order | Priority | Work packet | Suggested owner | Depends on |
|---:|:---:|---|---|---|
| 1 | P0 | [Restore green `main`](00-p0-restore-green-main.md) | CI/runtime maintainer | — |
| 2 | P1 | [Make live autonomous evaluation real](01-p1-live-autonomous-evaluation.md) | Evaluation/agent engineer | Green `main` |
| 3 | P1 | [Repair benchmark regression gating](02-p1-benchmark-regression-gating.md) | Evaluation/infrastructure engineer | Green `main` |
| 4 | P1 | [Establish repository governance](03-p1-repository-governance.md) | Repository maintainer | — |
| 5 | P2 | [Split the exploit runner](04-p2-exploit-runner-refactor.md) | Runtime architect | Live-eval safety net preferred |
| 6 | P2 | [Reduce type debt](05-p2-type-debt.md) | Runtime maintainers | Coordinate with runner split |
| 7 | P2 | [Retire Flow B](06-p2-flow-b-retirement.md) | Runtime architect | Reliable Flow A live eval |
| 8 | P2 | [Make documentation mechanically truthful](07-p2-documentation-truth.md) | Docs/CI maintainer | — |
| 9 | P1 | [Ship the reliability-focused 0.69 beta](08-p1-release-069-beta.md) | Release maintainer | Packets 1–3; governance readiness |

Packets 2 and 3 can proceed in parallel after the P0 repair. Packets 3, 4, and
8 can also be assigned independently, subject to the dependencies above.

## Current assessment snapshot

| Area | State | Assessment |
|---|---|---|
| Core product breadth | Strong | Already broad enough for beta |
| Safety/scope containment | Strong conceptually | Recent changes caused integration-test drift |
| WebUI | Healthy | Latest build and tests passed |
| Packaging | Healthy | Wheel and package smoke tests passed |
| Dependency/security scanning | Healthy | `pip-audit` and CodeQL passed |
| Main CI | Red | Immediate blocker |
| Autonomous live evaluation | Not effectively running | Major blocker |
| Benchmark regression system | Misconfigured | Major blocker |
| Architecture | Functional but heavy | Significant oversized-module debt |
| Type safety | Improving, with substantial debt | Baseline 278; latest assessed commit increased it |
| Release process | Stale | Published beta trails the source |
| Repository governance | Weak | No visible backlog; `main` was unprotected |
| Documentation | Broad, with some rot | Dead audit links and stale values |

These observations describe the assessed repository state. Re-check external
state, CI logs, release metadata, and exact counts before closing a packet.

## How to use these files

1. Assign one owner to a work packet and add their name near its title.
2. Link the tracking issue or pull request in the packet.
3. Check off tasks only after the listed evidence exists.
4. Keep changes to frozen Flow B safety files out of unrelated work.
5. Run tests in the repository-approved slices: one test file at a time,
   `-n 0` or `-n 2`; leave full-suite verification to CI.
6. Do not resume capability expansion until the 0.69 beta exit criteria are met.

## Shared definition of done

- Relevant focused tests pass on supported Python versions.
- `ruff check .`, `ruff format --check .`, and
  `mypy --follow-imports=skip tools` pass under the repository's ratchet rules.
- User-facing flags, configuration, or behavior changes are reflected in
  `README.md` and the relevant files under `docs/`.
- Target-touching execution continues through the allowlist-locked MCP layer
  and the default-on sandbox; no host-execution fallback is introduced.
- The pull request includes reproducible validation evidence and rollback notes.

