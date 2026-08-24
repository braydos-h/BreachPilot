---
title: "Tool Family: peer-models"
sources:
  - tools/mcp_tools/peer_models.py
  - tools/mcp_tools/registry.py
  - tools/model_router.py
  - tools/providers/chatgpt_provider.py
tests:
  - tests/test_mcp_tool_registration.py
  - tests/test_peer_models.py
subsystem: mcp
---

# Tool Family: peer-models

- **Registration source:** `tools/mcp_tools/peer_models.py:38 register_peer_model_tools(mcp, *, ctx)` — auto-discovered but **conditionally registers** only when `_multi_model_enabled(config)` (`tools/mcp_tools/registry.py:225-230`): `multi_model.enabled: true` OR `AI_NMAP_MULTI_MODEL_ENABLED` env var truthy override. Otherwise no tools.
- **Gate:** both `@audit_tool` (no target touch — peer models receive no tool schemas, return suggestions only).

## Tools Exported (2) — conditional

| Tool | Params | Result Shape | Notes |
|------|--------|--------------|-------|
| `consult_peer_models` | `question: str`, `context: str=""`, `preferred_aliases: str=""` (comma/space CSV from `models.registry`) | `PEER_MODEL_CONSULTATION: BLOCKED|UNAVAILABLE|BUDGET_EXHAUSTED|COMPLETED\nCONSULTED: ...\nSKIPPED: ...\nREMAINING_BUDGET: N\n\n[alias]\nanswer...` | Budget `max_consultations` (default 10 via `_positive_int`), `max_question_chars` 4000, `max_answer_chars` 8000, both via `multi_model.*`. Truncates inputs. Builds peer list: `available = _resolve_consult_aliases(config)` = intersection of `multi_model.consult_aliases` (default `kimi,deepseek,deepseek_flash,glm,minimax`) with `models.registry` keys, minus active `AI_NMAP_ACTIVE_MODEL_ALIAS` / `models.default_alias`. Intersects with `preferred_aliases` when supplied; tracks `skipped`. `get_model_router` (`tools/mcp_tools/registry._get_model_router`) may return `None` → `UNAVAILABLE`. Reserves budget atomically under `_consultation_lock` (`tools/mcp_tools/registry.py:147`) + `_get_consultation_count`/`_set_consultation_count` (mirrors `mcp_exploit_server._consultation_count`). For each alias: `router.get_client(alias).chat(alias, messages=[system ASSUMPTIONS/RISKS/RECOMMENDATION prompt, user Question/Context], tools=None, stream=False)` → `_chat_content` + truncate. Peers get no tools. |
| `peer_review_outcome` | `verdict: str`, `evidence: str`, `planner_alias: str=""`, `preferred_grader_aliases: str=""` | `PEER_REVIEW_OUTCOME: BLOCKED|DISABLED|UNAVAILABLE|BUDGET_EXHAUSTED|COMPLETED\nPLANNER_ALIAS: ...\nGRADERS: ...\nDISAGREEMENT: yes|no\nREMAINING_BUDGET: ...\nAUTHORITY: deterministic OutcomeJudge (this review is advisory)\n\n[alias]\njson ...` | Advisory cross-model outcome judging (D3). Requires `multi_model.enabled: true` **and** `outcome_judgment.peer_review: true` else `DISABLED`. Excludes `planner_alias` from graders (model never grades own plan); filters by `preferred_grader_aliases` when supplied. Shares same `max_consultations` counter with `consult_peer_models`. System prompt grades `verdict` vs `evidence` to JSON `{"agree":bool,"confidence":0..1,"reason":"..."}`; tracks `DISAGREEMENT` when any answer contains `"agree": false`. |

## Budget & Lock

- Single per-run counter `_consultation_count` (process singleton, `tools/mcp_tools/registry.py:143` + `tools/mcp_tools/peer_models.py:22-35` mirror on `mcp_exploit_server._consultation_count`) + `_consultation_lock` (`threading.Lock`) serializes reservation.
- `remaining = max_consultations - current`; selected sliced to remaining; incremented atomically; `BUDGET_EXHAUSTED` when `remaining <= 0`.
- Both tools share the counter — using both drains the same budget.

## Dependencies

- `tools/model_router.build_router`, `tools/config_manager.get_ai_provider`, `get_chatgpt_config`
- `tools/mcp_tools/registry._get_model_router`, `_resolve_consult_aliases`, `_multi_model_enabled`, `_chat_content`, `_truncate_text`, `_positive_int`

## Config

- `multi_model.enabled: bool` (default false) + `AI_NMAP_MULTI_MODEL_ENABLED=1/0` env override
- `multi_model.consult_aliases: list[str]` (default `kimi,deepseek,...`)
- `multi_model.max_consultations: int` (default 10), `max_question_chars: int` (4000), `max_answer_chars: int` (8000)
- `models.registry: map[alias] -> {provider, model}`, `models.default_alias: str` (active model excluded)
- `outcome_judgment.peer_review: bool` (gates `peer_review_outcome`)

## Auditing

- Both `@audit_tool` — `question/context` not wholesale-redacted but inline secrets masked; no target IP in these entries.
- Budget state not persisted — process lifetime only.

## Validation

- Empty `question`/`verdict`/`evidence` → `BLOCKED`; unavailable router → `UNAVAILABLE` with `AVAILABLE_PEERS` listed.
- `preferred_aliases` filtered to actual registry keys; unknown aliased → `SKIPPED`.

## Tests

- `tests/test_mcp_tool_registration.py` — expects `consult_peer_models` when `multi_model.enabled: true` and registry has peers
- `tests/test_peer_models.py` (if present) — budget exhaustion, peer_review disabled, planner exclusion

## Related Docs

- `docs/mcp/registration.md`
- `tools/model_router.py` — router seam
- `docs/providers.md` — ChatGPT vs Ollama provider path
