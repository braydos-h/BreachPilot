# 70. Separate facts from hypotheses

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Data, security, and release |
| Dependencies | [#69](../06-data-security-and-release/69-introduce-an-observation-schema.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Important for avoiding hallucinated attack state.

```text
FACT
port 8080 returned Server: nginx

INFERENCE
likely reverse proxy

HYPOTHESIS
backend may trust X-Forwarded-For

CLAIM
admin restriction bypassed

VERIFIED FACT
request with XFF returned independently verified protected resource
```

Store the epistemic state.

Your OutcomeJudge architecture is already moving in this direction.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 2 — the LLM cannot mint verified facts
- Commits/PRs: working-tree: tools/intelligence/belief/state.py (EpistemicKind
  FACT/INFERENCE/HYPOTHESIS/CLAIM/VERIFIED + Claim + promote_to_verified demanding
  a non-empty oracle ref), belief/__init__ exports, tests/test_intelligence_belief.py +2 tests
- Tests/evaluations: tests/test_intelligence_belief.py 16 passed
- Documentation: EpistemicKind docstring states the promotion invariant
- Follow-ups: enforce kind labels at finding/report/API surfaces (#04, #32).

