# 54. Installation should have a "minimal useful" profile

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14 — revalidated) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | WebUI, delivery, and ecosystem |
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

You currently support substantial tooling.

I'd make install profiles explicit:

```text
Core
  WebUI + Python + provider

Web
  + browser + HTTP tooling

Network
  + nmap + network tooling

Full
  + Metasploit + impacket + Kali arsenal
```

The user should not need all offensive tooling to evaluate a web application.

This lowers installation failure rates.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14 (revalidation)
- Design/issue: Wave 7 — Core/Web/Network/Full profiles
- Commits/PRs: none; revalidation: install.sh ships --minimal (core) /
  --standard (core+WebUI+nmap, default) / --full (+Kali arsenal) with
  BP_PROFILE/BP_WITH_KALI/BP_WITH_SCANNERS overrides
- Tests/evaluations: installer-windows workflow + setup scripts in CI
- Documentation: install.sh --help documents profiles
- Follow-ups: point profiles at pinned prebuilt image once #55 lands.

