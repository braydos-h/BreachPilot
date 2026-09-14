# 79. Fix GitHub metadata/details

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — badges/docs exist, admin settings pending) |
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

- [ ] issues enabled;
- [ ] eight open issue/PR-count entries;
- [ ] wiki enabled;
- [ ] discussions disabled;
- [ ] Apache-2.0;
- [ ] website configured.

## Audit recommendation

Minor compared with core engineering, but worthwhile:

Current topics include a typo:

```text
security-automaion
```

rather than likely:

```text
security-automation
```

GitHub also currently has:

* issues enabled;
* eight open issue/PR-count entries;
* wiki enabled;
* discussions disabled;
* Apache-2.0;
* website configured.

I'd also enable Discussions once there are enough users to justify it, rather than sending support questions into Issues.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 7 — appropriate community settings
- Commits/PRs: none yet; revalidation: badges, website link, SECURITY.md,
  CONTRIBUTING.md exist; no CODE_OF_CONDUCT.md; repo settings need admin
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups (needs admin): community settings + CODE_OF_CONDUCT decision.

