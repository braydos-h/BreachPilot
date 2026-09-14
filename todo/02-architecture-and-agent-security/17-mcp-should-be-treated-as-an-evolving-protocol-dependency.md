# 17. MCP should be treated as an evolving protocol dependency

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — pinned, compat tests pending) |
| Suggested priority | P1 |
| Suggested horizon | Backlog |
| Theme | Architecture and agent security |
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

The current pyproject pins:

```text
mcp>=1.27.0,<2.0.0
```

which is reasonable.

But MCP itself has moved significantly. The July 28, 2026 MCP spec introduced a stateless core, authorization changes, routing changes, task capabilities and a formal extension model. ([Model Context Protocol Blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/?utm_source=chatgpt.com))

I would create:

```text
docs/mcp-compatibility.md
```

with:

```text
Protocol version
SDK version
Transport
Features implemented
Extensions used
Security assumptions
Known incompatibilities
```

and run a protocol conformance test in CI.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 2 — MCP SDK is a protocol dependency, not stdlib
- Commits/PRs: none yet; revalidation: mcp>=1.27,<2.0.0 pinned in
  requirements.txt; _EXC_GROUP_CATCH discipline + bare-except CI guard exist;
  no protocol-version negotiation or SDK-upgrade compat matrix found
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: protocol-version floor test, SDK upgrade checklist, stateless/
  authorization deltas review per MCP spec evolution.

