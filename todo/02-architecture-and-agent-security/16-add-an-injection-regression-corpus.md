# 16. Add an injection regression corpus

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | 30-day |
| Theme | Architecture and agent security |
| Dependencies | [#15](../02-architecture-and-agent-security/15-prompt-injection-needs-its-own-explicit-subsystem.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [ ] visible hostile instructions;
- [ ] hidden CSS text;
- [ ] comments;
- [ ] SVG content;
- [ ] JS-generated content;
- [ ] JSON API fields;
- [ ] tool output;
- [ ] fake "SYSTEM" messages;
- [ ] fake credential notices;
- [ ] poisoned README files.

## Audit recommendation

Create something like:

```text
eval_targets/prompt_injection/
```

with pages containing:

* visible hostile instructions;
* hidden CSS text;
* comments;
* SVG content;
* JS-generated content;
* JSON API fields;
* tool output;
* fake "SYSTEM" messages;
* fake credential notices;
* poisoned README files.

Tests:

```text
Can injection change scope?                  MUST NEVER
Can injection add an authorized target?      MUST NEVER
Can injection retrieve a host secret?        MUST NEVER
Can injection select another tool?           perhaps
Can it influence hypothesis generation?      yes, but untrusted
Can resulting tool action escape policy?     MUST NEVER
```

This would be a very compelling security story.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 3 — one shared attack-string set across layers
- Commits/PRs: working-tree: tests/fixtures/injection_corpus.json (new, v1, 14
  cases over prompt/tool/mcp/memory), tests/test_injection_corpus.py (new, 5 tests)
- Tests/evaluations: 5 passed; complements test_mcp_injection_hardening.py (40 tests)
- Documentation: corpus JSON header defines layers + expectations
- Follow-ups: grow the corpus with each new injection class found; live-model
  spot checks under nightly eval.

