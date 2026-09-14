# 07. Remove "native execution" from normal product UX

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P0 |
| Suggested horizon | Backlog |
| Theme | Strategy and evaluation |
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

Current source appears to have already moved the **schema/default configuration to `fallback_native: false`**, which is correct.

But portions of `docs/sandbox.md` and `docs/safety-model.md` still describe default `fallback_native: true`, while the current README says the default is false.

That's exactly the sort of semantic documentation disagreement your documentation-truth checker does not yet catch.

For a production-quality application I would go further:

```text
Normal installation:
sandbox required

Developer-only:
--unsafe-native-execution
```

And require something obvious, e.g.:

```text
BREACHPILOT_ALLOW_NATIVE_EXECUTION=I_UNDERSTAND_THIS_RUNS_ON_THE_HOST
```

not merely:

```yaml
sandbox:
  enabled: false
```

The normal product should never silently drift toward native execution.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 1 — native execution is developer-only, never silent
- Commits/PRs: working-tree: tools/sandbox/manager.py (NATIVE_CONSENT_ENV gate in
  resolve_manager_with_fallback for enabled:false + fallback_native:true without consent
  → blocked manager), tools/sandbox/exceptions.py + mcp_bridge.py stale-default fixes,
  tests/test_sandbox_native_fallback.py (consent matrix + 3 new tests, 2 updated),
  docs/sandbox.md + README.md consent documentation
- Tests/evaluations: tests/test_sandbox_native_fallback.py 29 passed;
  tests/test_sandbox_manager.py 29 passed; tests/test_sandbox_mcp_exec.py 11 passed
- Documentation: docs/sandbox.md config comments + README fail-closed bullet name the env gate
- Follow-ups: surface consent state in WebUI sandbox banner (#52); doctor hint for
  blocked-by-consent mode; consider --unsafe-native-execution CLI flag as explicit alternative.

