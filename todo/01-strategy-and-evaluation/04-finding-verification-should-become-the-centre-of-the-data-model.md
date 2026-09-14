# 04. Finding verification should become the centre of the data model

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P0 |
| Suggested horizon | 60-day |
| Theme | Strategy and evaluation |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

This is one of the project's best existing ideas:

> execution success ≠ evidential success.

Preserve this at all costs.

I would formalize a finding as:

```text
Finding
 ├── identity
 │    ├── fingerprint
 │    ├── weakness/CWE
 │    ├── endpoint/resource
 │    └── vulnerability family
 │
 ├── discovery
 │    ├── hypothesis
 │    ├── tool observations
 │    └── discovery trace
 │
 ├── verification
 │    ├── oracle
 │    ├── evidence
 │    ├── reproduction attempts
 │    ├── positive controls
 │    └── negative controls
 │
 ├── risk
 │    ├── CVSS
 │    ├── exploitability
 │    ├── impact
 │    └── confidence
 │
 ├── remediation
 │    ├── guidance
 │    ├── external ticket
 │    └── owner
 │
 └── retest
      ├── original evidence
      ├── new evidence
      └── fixed / vulnerable / inconclusive
```

And enforce lifecycle states:

```text
SUSPECTED
   ↓
OBSERVED
   ↓
VERIFIED
   ↓
REPORTED
   ↓
RETEST_PENDING
   ↓
FIXED

or

REFUTED
INCONCLUSIVE
REGRESSED
```

Do not let an LLM directly set `VERIFIED`.

Only an oracle/verifier should promote it.

ProjectDiscovery has converged on a similar "prove exploitability instead of infer from versions" philosophy for Nuclei. ([ProjectDiscovery](https://projectdiscovery.io/blog/from-detection-to-validation-fixing-broken-vulnerability-workflows?utm_source=chatgpt.com))

That is the correct competitive direction.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14 (central machine + existing pipeline revalidated)
- Design/issue: Wave 4 — verified findings as the core product object
- Commits/PRs: working-tree: tools/kernel/finding_lifecycle.py (new: 8-state
  machine, actor-gated transitions, terminal states), tests/test_finding_lifecycle.py
  (new, 6 tests); revalidated existing PROPOSED→APPROVED→VERIFIED→STILL_OPEN/FIXED
  pipeline (hitl.py human-only approval, verify.py N× re-proof, retest.py)
- Tests/evaluations: 6 passed; test_hitl + test_evidence suites green
- Documentation: lifecycle module is the enforcement contract for storage/API/UI/reports
- Follow-ups: consult allowed_transitions at every surface (storage, API, UI,
  reports, integrations); finding confidence calibration (#71).

