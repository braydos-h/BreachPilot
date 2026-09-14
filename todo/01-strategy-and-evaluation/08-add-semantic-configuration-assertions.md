# 08. Add semantic configuration assertions

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14) |
| Suggested priority | P0 |
| Suggested horizon | 30-day |
| Theme | Strategy and evaluation |
| Dependencies | None recorded; confirm during scoping. |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [x] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [x] Add or update focused tests and evaluation coverage where applicable.
- [x] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

Audit claim revalidated 2026-09-14: accurate. `docs/sandbox.md:127,251,262` and
`docs/troubleshooting.md:408,563` claimed `fallback_native` defaults `true`;
schema (`tools/config/schema.py:879`), `config.yaml:542`, and README:278 say
`false`. CLAUDE.md:389 even documented the contradiction as known-inconsistent.
Syntax/link/version guard (`scripts/docs_truth_audit.py`) cannot catch this class.

## Requirements called out by the audit

- [ ] README config tables;
- [ ] WebUI labels;
- [ ] CLI help;
- [ ] docs/config-reference;
- [ ] install messages.

## Audit recommendation

The documentation checker you recently added is a good idea, but syntax/link/version checks don't find contradictions such as:

```text
document A: fallback_native defaults true
document B: fallback_native defaults false
schema: false
config.yaml: false
```

Generate operational documentation straight from config schemas.

Better:

```python
ConfigField(path="sandbox.fallback_native", default=False, risk="critical", description="...")
```

Then generate:

* README config tables;
* WebUI labels;
* CLI help;
* docs/config-reference;
* install messages.

One truth source.

The existing generated config reference is already heading there.

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: (slice 1 done; full ConfigField codegen still open — see follow-ups)
- Design/issue: Wave 0 — semantic truth slice 1: safety-critical default assertions
- Commits/PRs: working-tree (uncommitted): docs/sandbox.md + docs/troubleshooting.md +
  CLAUDE.md fallback_native→false; tests/test_config_semantic_truth.py (new, 5 tests)
- Tests/evaluations: `tests/test_config_semantic_truth.py` 5 passed; `ruff check .` clean
- Documentation: fixed 3 files; schema remains single source
- Follow-ups: full `ConfigField` codegen (README tables, WebUI labels, CLI help,
  docs/config-reference, install messages from one source) is the remaining scope;
  current guard fails closed on drift but does not yet generate docs.

