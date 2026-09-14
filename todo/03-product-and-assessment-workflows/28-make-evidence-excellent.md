# 28. Make evidence excellent

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14 — revalidated) |
| Suggested priority | P1 |
| Suggested horizon | 60-day |
| Theme | Product and assessment workflows |
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

A report should include, where appropriate:

```text
request
response
terminal output
browser screenshot
DOM excerpt
pcap-like metadata
credential identity used
timestamp
hash
tool
run
reproduction sequence
```

Every piece of evidence needs stable IDs.

For example:

```text
EV-2026-09-1181
SHA256 ...
Created by tool invocation TI-881
Finding BP-104
```

Then reports become traceable rather than prose generated after the fact.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14 (revalidation; deterministic IDs + excerpts + levels exist)
- Design/issue: Wave 4 — complete evidence with stable identifiers
- Commits/PRs: none; revalidation: EvidenceReference.create gives deterministic
  ref_id over (source, target, timestamp, content_hash), excerpt normalization,
  source/level enums incl. TARGET_SIDE_ORACLE; Observation (#69) bridges runtime
- Tests/evaluations: test_evidence suites green in CI
- Documentation: n/a
- Follow-ups: evidence browser UI (#18); bundle export (#30).

