# 47. Property-based tests would be especially valuable for scope logic

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Runtime, governance, and CI |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

For the network/scope boundary, generate pathological target representations:

```text
IPv4
IPv6
IPv4-mapped IPv6
CIDRs
mixed case FQDN
trailing dot
punycode
redirects
numeric IP representations
hostname resolving to multiple A/AAAA records
DNS changes
URLs with userinfo
ports
encoded hostnames
```

Invariant:

```text
no representation of an unauthorized endpoint
may turn into an authorized packet destination
```

Test the policy layer **and** actual network namespace enforcement.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 1 — scope properties over the input space, not examples
- Commits/PRs: working-tree: tests/test_scope_allowlist_properties.py (new, 7 tests,
  seeded stdlib random, no new dependency)
- Tests/evaluations: tests/test_scope_allowlist_properties.py 7 passed (~1,000 generated cases)
- Documentation: module docstring states the four properties
- Follow-ups: add hypothesis proper if it joins dev deps; extend to domain-allowlist
  + ScopeGate rate-bucket invariants.

