# 12. Turn tools into declarative capabilities

| Field | Value |
| --- | --- |
| Status | DONE (owner: Muse Spark, completed: 2026-09-14) |
| Suggested priority | P1 |
| Suggested horizon | 30-day |
| Theme | Architecture and agent security |
| Dependencies | [#11](../02-architecture-and-agent-security/11-type-debt-matters-more-here-than-in-most-python-projects.md), [#69](../06-data-security-and-release/69-introduce-an-observation-schema.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [x] Record completion evidence below and update [the backlog index](../README.md).

## Requirements called out by the audit

- [ ] Which tools can touch the network?
- [ ] Which consume credentials?
- [ ] Which require root?
- [ ] Which can modify targets?
- [ ] Which are allowed in recon?
- [ ] Which don't have integration tests?
- [ ] Which aren't benchmarked?
- [ ] Which lack evidence schemas?

## Audit recommendation

The project has reached the point where manually reasoning about 160+ tools is difficult.

Every tool should have metadata like:

```yaml
id: web.sqlmap
version: 2
family: web
capabilities:
  - target.http
effects:
  network: true
  filesystem: workspace
  credentials: consume
risk:
  active: true
  destructive: false
sandbox:
  required: true
inputs:
  target:
    type: endpoint
scope_fields:
  - target
evidence:
  output_schema: sql_injection_result_v1
```

Then registration, UI, authorization, docs, tool catalog and audit rules come from the manifest.

## Benefits

You get automatic answers to:

* Which tools can touch the network?
* Which consume credentials?
* Which require root?
* Which can modify targets?
* Which are allowed in recon?
* Which don't have integration tests?
* Which aren't benchmarked?
* Which lack evidence schemas?

That would be much more valuable than another 30 manually wired tools.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: 2026-09-14
- Design/issue: Wave 2 — static capability answer without booting a server
- Commits/PRs: working-tree: tools/mcp_tools/manifest.py (new: ToolManifest v1 +
  collect_manifests over the decorator-validator AST seam + catalog_hash),
  tests/test_kernel_contracts.py (2 manifest tests, >100 tools covered)
- Tests/evaluations: manifests derived from real source; check_os allowlisted,
  run_hash_crack local-only; hash stable across calls
- Documentation: module docstring; MANIFEST_VERSION fail-closed rule
- Follow-ups: surface manifests in planner gating + release provenance;
  rule: new tools get manifests automatically (same AST seam).

