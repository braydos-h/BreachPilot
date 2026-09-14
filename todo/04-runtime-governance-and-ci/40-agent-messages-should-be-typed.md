# 40. Agent messages should be typed

| Field | Value |
| --- | --- |
| Status | IN PROGRESS (owner: Muse Spark, started: 2026-09-14 — blackboard is dict-based, typing pending) |
| Suggested priority | P2 |
| Suggested horizon | Backlog |
| Theme | Runtime, governance, and CI |
| Dependencies | [#39](../04-runtime-governance-and-ci/39-dont-overuse-multi-agent-architecture.md), [#69](../06-data-security-and-release/69-introduce-an-observation-schema.md) |
| Audit snapshot | `main` at `75e0ba9df21311f8441b98e884610d36fa91f1af` (2026-09-14) |

## Work checklist

- [x] Re-check the current implementation and note whether the audit is still accurate.
- [x] Define the smallest safe deliverable and list affected modules and contracts.
- [ ] Implement without weakening scope, allowlist, sandbox, or evidence guarantees.
- [ ] Add or update focused tests and evaluation coverage where applicable.
- [ ] Update generated and user-facing docs/config contracts where applicable.
- [ ] Record completion evidence below and update [the backlog index](../README.md).

## Audit recommendation

Avoid unrestricted agent-to-agent prose being interpreted as commands.

Use:

```json
{
  "type": "hypothesis_request",
  "target_ref": "asset_17",
  "evidence_refs": ["ev_19"],
  "question": "...",
  "capabilities": []
}
```

Agent communication becomes data.

Authorization remains external.

This helps against the agent-to-agent trust problems now recognized in agentic-security guidance. ([OWASP Gen AI Security Project](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/?utm_source=chatgpt.com))

## Completion record

- Owner: Muse Spark
- Started: 2026-09-14
- Completed: revalidation slice (no code change yet)
- Design/issue: Wave 2 — typed inter-agent data, authorization stays external
- Commits/PRs: none yet; revalidation: swarm blackboard/negotiation pass plain
  dicts; no TypedDict/dataclass message envelope found; Observation (#69) is
  the candidate payload type
- Tests/evaluations: n/a
- Documentation: n/a
- Follow-ups: typed message envelope (sender/kind/payload/observation-id)
  with runtime validation at blackboard write.

