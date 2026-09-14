# 23. Authenticated web testing should be a major P1

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — vault + importer auth data exist, profiles pending) |
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

## Requirements called out by the audit

- [ ] IDOR/BOLA;
- [ ] broken access control;
- [ ] role escalation;
- [ ] multi-tenant isolation;
- [ ] workflow bypass;
- [ ] account takeover;
- [ ] API authorization flaws.
- [ ] username/password;
- [ ] cookies;
- [ ] bearer token;
- [ ] API key;
- [ ] OAuth;
- [ ] scripted login;
- [ ] browser login capture.

## Audit recommendation

This is probably the largest product capability opportunity.

Support first-class:

### Credential profiles

```text
Anonymous
Normal user
Admin
User A
User B
API service account
```

Then BreachPilot can reason across identities.

This is essential for:

* IDOR/BOLA;
* broken access control;
* role escalation;
* multi-tenant isolation;
* workflow bypass;
* account takeover;
* API authorization flaws.

### Session acquisition

Support:

* username/password;
* cookies;
* bearer token;
* API key;
* OAuth;
* scripted login;
* browser login capture.

And make secrets handles—not strings freely injected into model context.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 5 — first-class authenticated testing
- Commits/PRs: none yet; revalidation: encrypted credential vault with
  target_host scoping exists; OpenAPI importer now records per-operation auth
  requirements; no session-acquisition flow or multi-identity profiles found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: secure session acquisition + credential-profile switching across
  identities during differential tests.

