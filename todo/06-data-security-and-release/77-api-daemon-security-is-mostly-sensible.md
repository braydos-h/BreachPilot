# 77. API daemon security is mostly sensible

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14 — revalidated, remote profile stays separate) |
| Suggested priority | P2 |
| Suggested horizon | Backlog |
| Theme | Data, security, and release |
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

- [ ] loopback-only serving;
- [ ] bearer authentication;
- [ ] stable API v1;
- [ ] authenticated WebSockets;
- [ ] no token-returning endpoint.

## Audit recommendation

The docs indicate:

* loopback-only serving;
* bearer authentication;
* stable API v1;
* authenticated WebSockets;
* no token-returning endpoint.

That's appropriate for the local-first model.

If you ever make it remotely accessible, **do not simply change `--api-host` to `0.0.0.0`.**

Remote operation should be a different deployment profile with:

```text
TLS
proper identities
RBAC
per-user API tokens
audit identity
CSRF/session considerations
rate limits
reverse proxy policy
```

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14 (revalidation; no code change needed)
- Design/issue: Wave 3 — keep the safe local API safe
- Commits/PRs: none; revalidation: bearer token on every route but /health,
  256-bit token in gitignored file, loopback-only bind with no v1 public
  override, WS auth + origin check (tools/api/auth.py)
- Tests/evaluations: API suites green in CI (Tier 1)
- Documentation: n/a
- Follow-ups: any remote operation ships as a separate hardened deployment
  profile (never a flag on v1).

