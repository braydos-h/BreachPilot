# 19. Assessment creation should be a wizard

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — survey done) |
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

This is one area where I would deliberately trade configuration flexibility for clarity.

### Step 1 — target

```text
○ Web application
○ API
○ Network
○ Active Directory
○ Repository + running app
```

### Step 2 — import context

```text
OpenAPI
Postman collection
HAR
Burp export
Repository
Credentials
Cookies/session
```

### Step 3 — scope

```text
example.com
*.example.com

Excluded:
admin.vendor.example
10.0.7.0/24

Resolved IPs:
...
```

### Step 4 — testing profile

```text
○ Recon only
● Guided penetration test
○ Autonomous penetration test
○ Custom
```

### Step 5 — safety preview

```text
BreachPilot CAN:
✓ interact with *.example.com
✓ authenticate as test-user
✓ perform active vulnerability testing

BreachPilot CANNOT:
✕ contact third-party domains
✕ leave authorised network destinations
✕ run outside disposable sandbox
```

### Step 6 — launch

This should become the product's strongest UX.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: survey slice (no code change yet)
- Design/issue: Wave 6 — target/context/scope/profile/safety/launch wizard
- Commits/PRs: none yet; revalidation: NewRunPage.tsx exists (single page);
  no stepped wizard found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: stepped wizard with scope preview + safety summary + launch gate.

