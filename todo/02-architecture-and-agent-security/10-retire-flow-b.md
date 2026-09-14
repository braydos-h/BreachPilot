# 10. Retire Flow B

| Field | Value |
| --- | --- |
| Status | DEFERRED (owner: Muse Spark, 2026-09-14 — prerequisites unmet, see below; frozen files untouched) |
| Suggested priority | P1 |
| Suggested horizon | 60-day |
| Theme | Architecture and agent security |
| Dependencies | [#02](../01-strategy-and-evaluation/02-live-autonomous-evaluation-needs-to-become-the-centre-of-development.md), [#09](../02-architecture-and-agent-security/09-the-giant-exploit-loop-is-now-an-architectural-liability.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [ ] **Flow A** — current exploit/MCP architecture;
- [ ] **Flow B** — legacy architecture.
- [ ] duplicated bug fixes;
- [ ] different policy semantics;
- [ ] different evidence behaviour;
- [ ] different security assumptions;
- [ ] regression surface;
- [ ] enormous cognitive load.

## Audit recommendation

Your own audit identified two substantial execution paths:

* **Flow A** — current exploit/MCP architecture;
* **Flow B** — legacy architecture.

There is already a backlog item for retirement.

I strongly agree.

Do not maintain two autonomous architectures.

That produces:

* duplicated bug fixes;
* different policy semantics;
* different evidence behaviour;
* different security assumptions;
* regression surface;
* enormous cognitive load.

Once Flow A has proven parity through evaluation:

```text
Deprecate Flow B
       ↓
migration shim
       ↓
remove execution implementation
       ↓
retain loaders only if needed
       ↓
delete legacy model
```

Aim for deletion, not "legacy but still supported forever."

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: deferral decision recorded (NOT retired)
- Design/issue: Wave 2 — retirement requires measured parity first
- Commits/PRs: none (deliberately zero — frozen Flow B files untouched)
- Tests/evaluations: prerequisites NOT met: no Flow A↔B parity harness, no
  migration coverage, live eval still building its baseline. Retiring now would
  remove tested safety code with no measured replacement.
- Documentation: this deferral record
- Follow-ups (prerequisites for revisit): Flow A live-eval baseline green (#02),
  parity test suite, caller migration map, maintainer approval + AGENTS.md update
  (deleting protected files requires both).

