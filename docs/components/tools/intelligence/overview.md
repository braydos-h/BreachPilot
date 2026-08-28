---
title: Intelligence — Overview
package: tools/intelligence
subpackages: [belief, evidence, fingerprint, graph, schemas, adapters]
---

# Intelligence — Overview (`tools/intelligence/`)

AttackGraph v2, belief modelling, evidence provenance, attempt fingerprinting,
structured schemas, and legacy adapters. 26 Python files across 6 subpackages + package `__init__.py`.

**Wiring status (verified against callers — do not describe all of this as a
Flow A primitive):**

- `graph/` — **active production path**: wrapped by `tools/api/graph_service.py`
  and `tools/api/graph_builder.py` behind the WebUI attack-path DAG API
  (`GET /api/v1/runs/{run_id}/graph`, `api.graph_route`).
- `adapters/` — **legacy Flow B path (best-effort)**: `legacy/observer.py`
  (ObserverAdapter) and `legacy/finding_verifier.py` (FindingAdapter) import
  them lazily; the other adapters are test-only.
- `belief/`, `evidence/`, `fingerprint/`, `schemas/` — **scaffold / test-only**.
  Nothing in Flow A (`main.py`, the exploit loop, `mcp_exploit_server.py`)
  imports them; `fingerprint.tracker.is_permanent_failure` is used only by the
  legacy observer adapter. `SafeSchemaLoader` has no production caller.

## Layout

| Subpackage | Files | Purpose | Status |
|---|---|---|---|
| `belief/` | `state.py`, `confidence.py`, `store.py` | Hypothesis state + confidence calculus | scaffold (legacy adapter consumer) |
| `evidence/` | `reference.py`, `store.py`, `provenance.py` | Immutable refs + store + lineage | scaffold / test-only |
| `fingerprint/` | `attempt.py`, `tracker.py` | Safe retry/fingerprinting | scaffold (tracker used by legacy adapter) |
| `graph/` | `types.py`, `store.py`, `merge.py`, `traversal.py` | Attack graph | **active (WebUI API)** |
| `schemas/` | `base.py`, `validator.py`, `graph.py`, `outcome.py`, `planner.py`, `critic.py`, `strategy.py` | LLM output contracts | scaffold / test-only |
| `adapters/` | `planner_adapter.py`, `finding_adapter.py`, `memory_adapter.py`, `observer_adapter.py`, `target_graph_adapter.py` | Bridge to legacy surfaces | legacy Flow B (observer + finding adapters) |

---

## Belief (`belief/`)

### `state.py`

| Symbol | Kind | Line |
|---|---|---|
| `HypothesisStatus` | Enum | `open|inconclusive|confirmed|refuted|exhausted` |
| `EvidencePolarity` | Enum | `supports|contradicts|unpolarized` |
| `EvidenceObservation` | dataclass | `evidence_ref, polarity, confidence, ts` |
| `HypothesisState` | dataclass | `_apply_evidence`, `register_evidence/observation`, `next_discriminating_check` |
| `BeliefState` | class | `add_hypothesis, get, register_observation, snapshot/load, top_unresolved, to_json/from_json` |

Confirmed when posterior ≥ `confirmation_threshold` (0.75); refuted ≤ `1-refutation_threshold`; capped attempts → `exhausted` (uses `EvidenceObservation` + `ConfidenceCalculator` with `EvidenceUpdateRule.decay`). `BeliefState` aggregates `HypothesisState`s + per-hypothesis attempts.

### `confidence.py`

| Symbol | Kind | Line |
|---|---|---|
| `ConfidenceCalculator` | class | Bayesian beta posterior via `EvidenceUpdateRule` |
| `DeterministicUpdater` | class | Threshold-based `apply` |
| `NonModelConfidence` / `TaggedConfidence` | class | Sentinel posteriors |

`_bayesian_beta` fuses observations weighted by `EvidenceUpdateRule.confidence` and `decay` (time/decay half-life via `experience_time_decay_days`). `_clamp01`, `_independence_bonus` helpers.

### `store.py`

| Symbol | Kind | Line |
|---|---|---|
| `BeliefStore` | class | `upsert/get/delete/list_all/list_by_status/find_by_statement` |

Thresholded in-memory store keyed by `HypothesisState.id` (or `statement`), supports confidence gating.

---

## Evidence (`evidence/`)

### `reference.py`

| Symbol | Kind | Line |
|---|---|---|
| `EvidenceSource` | Enum | `tool_output|file|api_response|agent_action|user_input` |
| `EvidenceLevel` | Enum | `low|medium|high|confirmed` |
| `EvidenceReference` | dataclass | `ref_id, source, level, hash_content, create/from_dict/to_dict/normalize` |

`EvidenceReference.create(content, source, level)` hashes content (`hash_content`), `normalize()` redacts secrets, `_make_ref_id` stable. `from_reference` on `GraphNode` bridges to graph.

### `store.py`

| Symbol | Kind | Line |
|---|---|---|
| `EvidenceStoreV2` | class | `put/get/list_all/find_by_source_tool/find_by_target/count` |

Immutable append-only keyed by `ref_id`.

### `provenance.py`

| Symbol | Kind | Line |
|---|---|---|
| `ProvenanceEntry` | dataclass | `ref_id, source_tool, derived_from[]` |
| `ProvenanceChain` | class | `walk, find_by_source, lineage, confidence_at, to_dict/from_dict` |
| `ProvenanceTracker` | class | `register_root/derived, chain_for, summary` |

DAG lineage for `HypothesisState` evidence chain; `confidence_at` interpolates posterior over time.

---

## Fingerprint (`fingerprint/`)

### `attempt.py`

| Symbol | Kind | Line |
|---|---|---|
| `AttemptStatus` | Enum | `pending|success|failed|blocked` |
| `ActionFamily` | Enum | `exploit|enumerate|credential|pivot|recon|unknown` |
| `Attempt` | dataclass | `for_tool, fingerprint, mask_secrets` |
| `RetryJustification` | dataclass | `should_retry, reason` |
| `RetryJustifier` | class | `evaluate, describe, is_permanent_failure` |

`fingerprint` normalizes `params` (`_normalize_params`), hashes stable key; `mask_secrets` redacts `password/pass/secret/hash/token`. `RetryJustifier.evaluate(AttemptSnapshot)` returns `should_retry` only when evidence changed since last attempt, failure class retryable, and not `blocked`.

### `tracker.py`

| Symbol | Kind | Line |
|---|---|---|
| `AttemptTracker` | class | `record, has_attempted, status_of, is_repetition, all_fingerprints, retry_history, register_evidence_change, summary` |

Bounded record with `_Record {fingerprint, status, failure_class, evidence_refs, ts}`. `is_repetition` compares current fingerprint param hash vs last recorded for same tool/target. Used by orchestrator retry engine.

---

## Graph (`graph/`)

### `types.py`

| Symbol | Kind | Line |
|---|---|---|
| `NodeType` | Enum | `host|service|credential|finding|evidence|observation` |
| `EdgeType` | Enum | `has_service|exposes|requires|produces|confirms|refutes|derived_from|observed_by` |
| `NodeStatus` | Enum | `unresolved|resolved|failed` |
| `GraphNode` / `GraphEdge` / `GraphUpdate` | dataclass | `to_dict/from_dict, redact_properties, make_evidence_ref` |

`GraphNode` holds `id, type, value, status, properties, evidence_refs[], redacted` via `redact_properties`. `make_evidence_ref`/`_cred_evidence_ref` create `EvidenceReference`s. `_enum_or_default` safe coercion.

### `store.py`

| Symbol | Kind | Line |
|---|---|---|
| `AttackGraphStore` | class | `upsert_node/get_node/get_node_by_value/upsert_edge/delete_node/query_nodes/query_edges/neighbors/paths/summary/to_graph_nodes/to_graph_edges` |

In-memory + SQLite-backed (via legacy `target_graph.py` bridge in `adapters/target_graph_adapter.py`). `_norm_value` deduplicates `value` case-insensitively per `NodeType`; `_node_to_row`/`_edge_to_row` serialization, `_new_id` uuid; `summary` = counts per type/status.

### `traversal.py`

| Symbol | Kind | Line |
|---|---|---|
| `GraphTraversal` | class | `nodes_of_type, edges_of_type, neighbors, paths(path_exists), subgraph, walk` |

BFS/DFS over `AttackGraphStore` adjacency; `paths` enumerates all simple paths bounded by depth.

### `merge.py`

| Symbol | Kind | Line |
|---|---|---|
| `GraphMergeEngine` | class | `apply(GraphUpdate), preview, _check_node_conflict, _conflict` |

Applies `GraphUpdate {add_nodes[], add_edges[], update_nodes[]}` with conflict detection via `_index_nodes` key `(NodeType,value)`; `GraphMergeConflict` on mismatch.

---

## Schemas (`schemas/`)

| File | Export | Contract |
|---|---|---|
| `base.py` | `BaseSchema, ValidationResult` | `validate(data)→ValidationResult{ok,errors,warnings}`, `repair`, `coerce`, `safe_load`; helpers `_safe_enum, _require_str, _clamp_float` |
| `validator.py` | `SafeSchemaLoader` | `extract_json_block`, `parse_json_block`, `load(schema_class, llm_text)` |
| `graph.py` | `GraphMutationProposal, GraphMutationSchema` | Nodes/edges to add + evidence_refs |
| `outcome.py` | `OutcomeAssessment, OutcomeAssessmentSchema` | `exploit_outcome, shell_type, privilege_level, confidence, evidence_refs` |
| `planner.py` | `PlannerProposal, CandidatePath, HypothesisUpdate + schemas` | `paths[{steps[], confidence, evidence_refs}], hypothesis_updates[]` |
| `critic.py` | `CriticReview, CriticReviewSchema` | `decision ∈ approve|deny|modify, reasoning, modifications` |
| `strategy.py` | `StrategyReview, StrategyReviewSchema` | `strategy_shift, confidence, why, new_hypothesis` |

All schemas implement `validate`/`repair`/`coerce` + `log_validation`/`dump_telemetry`. `SafeSchemaLoader` extracts JSON block (` ```json ` or bare `{…}`) then `validate` and `repair` once; never raises.

---

## Adapters (`adapters/`)

| File | Class | Bridge |
|---|---|---|
| `planner_adapter.py` | `PlannerAdapter` + `AttackPhaseBridge` | `planning_score_to_confidence`, `task_confidence`, `attach_planning_metadata`, `to_orchestrator`, `to_attack_planner` |
| `finding_adapter.py` | `FindingAdapter` | `ensure_reproduction_steps, dedupe_findings, link_to_graph(findings→GraphUpdate)` |
| `memory_adapter.py` | `MemoryAdapter` | `remember_graded, find_existing, dedup_remember, confidence_rank` |
| `observer_adapter.py` | `ObserverAdapter` | `populate_hypothesis_evidence, populate_graph_updates, infer_confidence, classify_dead_end` |
| `target_graph_adapter.py` | `TargetGraphV2Adapter` | `resolve_node_id, add_edge_by_value, edges_summary` vs legacy `target_graph.TargetGraph` |

Adapters are pure transforms + dedupe guards; no new persistence.

---

## Config keys

| Key | Module |
|---|---|
| `outcome_judgment.confirmation_threshold` / `refutation_threshold` / `min_evidence_references` / `max_inconclusive_attempts` | `belief/state.py` thresholds |
| `memory.experience_time_decay_days` | `belief/confidence.py` decay |
| `agent.max_retries_per_task` | `fingerprint/tracker.py` retry budget (via orchestrator) |
| No dedicated `intelligence.*` block | Intelligence is library-only; orchestrator wires config explicitly |

## Tests

| File | Verified | Covers |
|---|---|---|
| `tests/test_intelligence_belief.py` | yes | `HypothesisState`/`BeliefState` thresholds + transitions |
| `tests/test_intelligence_evidence.py` | yes | `EvidenceReference`/`EvidenceStoreV2`/`ProvenanceTracker` |
| `tests/test_intelligence_evidence_adversarial.py` | yes | Secret redaction, hash collision |
| `tests/test_intelligence_fingerprint.py` | yes | `Attempt.fingerprint`, `RetryJustifier` |
| `tests/test_intelligence_fingerprint_adversarial.py` | yes | Masqueraded secrets + replay |
| `tests/test_intelligence_graph_store.py` | yes | `AttackGraphStore` CRUD + `neighbors`/`paths` |
| `tests/test_intelligence_graph_store_adversarial.py` | yes | Duplicate `value` norm, conflict merge |
| `tests/test_intelligence_graph_types.py` | yes | `GraphNode`/`GraphEdge` ser/deser + redact |
| `tests/test_intelligence_schemas.py` | yes | All 5 schemas validate/repair/coerce |
| `tests/test_intelligence_schemas_adversarial.py` | yes | Malformed JSON block + overflow |
| `tests/test_intelligence_adapter_planner.py` | yes | `PlannerAdapter` score↔confidence |
| `tests/test_intelligence_adapter_graph.py` | yes | `TargetGraphV2Adapter` |
| `tests/test_intelligence_adapter_finding.py` | yes | `FindingAdapter` dedupe |
| `tests/test_intelligence_adapter_memory.py` | yes | `MemoryAdapter` grading |
| `tests/test_intelligence_adapter_observer.py` | yes | `ObserverAdapter` classify |
| `tests/test_bel_adversarial.py` | yes | Belief thresholds under adversarial drift |
