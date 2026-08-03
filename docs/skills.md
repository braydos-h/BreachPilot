# Runtime Skills

Runtime skills are an **advisory prompt-context layer**. Each skill is a
`SKILL.md` file (YAML frontmatter + markdown body) under `skills/`.
The engine indexes them, deterministically selects a small set for the current
assessment context, and exposes them to the LLM as compact hints plus
read-only MCP tools. **Skills never grant execution authority.**

## Pipeline

```
skills/**/SKILL.md
        │
        ▼
tools/skill_registry.load_skill_registry   (parse + sanitize + cache)
        │
        ▼
tools/skill_selector.select_runtime_skills (deterministic tag scoring
        │                                    + feedback boost + semantic rank)
        ▼
tools/skill_pipeline.build_skill_selection_for_context
        │
        ├─ main.py            (CLI: initial selection + mid-run re-selection)
        └─ tools/swarm/       (phase-relevant hints per specialist agent)
```

### 1. Selection

`select_runtime_skills` scores every candidate by:

- configured `default_enabled` skills (weight `default_skill_weight`),
- configured `include_tags` (`context_skill_weight`),
- dynamic tags derived from goal / discovered services / CVEs / recent
  tools,
- token-aware, field-weighted lexical search for sparse-tag skills,
- a **boost-only** cross-mission feedback term (see §3), and
- a **semantic** cosine-similarity term over `nomic-embed-text` embeddings
  (see §4).

Attack-only skills (tags like `exploit`, `credential`, `post-exploit`) are
excluded in `recon` mode. Mode itself is not treated as goal evidence, so a
reporting task in recon mode does not fill its slots with generic recon
skills. A tag-overlap diversity penalty keeps near-duplicate methodologies
from consuming the context budget. The top `max_active_skills` are rendered
into the `skill_hints` / `active_skills` / `skill_context` fields of the
target context.

### 2. Mid-run re-selection

As recon reveals new services/CVEs, `tools.exploit_agent._maybe_reselect_skills`
rebuilt the selection and announces it to the model as a `[SKILL UPDATE]`
user-role message (the system prompt is baked once and never mutated mid-run).
Rate-guarded by:

- `reselect_max_per_run` (default 3),
- `reselect_min_interval_actions` (default 5),
- `reselect_sticky_defaults` (configured defaults are retained across
  re-selections so safety-relevant methodology is not rotated out),
- a known-set tracker so only genuinely new services/CVEs trigger a rebuild,
- an identical-set no-op so the same active set causes no prompt churn.

Re-selection never touches `permission`, `scope_gate`, `workspace_root`, or
audit — asserted by `tests/test_skill_reselection.py`.

### 3. Cross-mission feedback (ExperienceStore)

`tools/skill_feedback.py` records, into the same `lessons` table the exploit
loop uses:

- `skill_loaded` (a neutral `partial` outcome) when the model calls
  `load_runtime_skill` — recorded in the agent process, not the MCP
  subprocess,
- `skill_outcome` (`success`/`failure`) at phase end from the reflection
  agent, one per active skill (success = the phase had at least as many
  wins as failures).

`skill_prior(name)` is the Beta posterior mean. The selector applies
`int((prior - 0.5) * 2 * feedback_skill_weight)` as a **boost-only** term once
`feedback_min_observations` is reached. A prior ≤ 0.5 contributes nothing —
negative outcomes never exclude a skill (advisory invariant: safety-relevant
methodology must not be hidden because it once underperformed).

### 4. Semantic matching (default-on, graceful fallback)

`tools/skill_embeddings.py::SkillEmbedder` wraps
`SemanticMemoryManager.embed` with a per-process text→vector cache. When
`skills.semantic_matching` is true (default) and an embedder is available,
`semantic_rank` embeds the query + each skill's search text and ranks by
cosine similarity. When embeddings are unavailable (Ollama down, model
missing, offline), it emits one
`[WARN] skills: embeddings unavailable, falling back to tag matching` and
returns `[]` — deterministic tag matching remains the floor. Attack-only
gating applies to semantic hits too.

## Adding a skill

1. Create `skills/<skill-name>/SKILL.md` (or
   `skills/maybe/<skill-name>/SKILL.md` for a gated experimental
   skill — ignored unless `skills.maybe_enabled: true`).
2. Frontmatter:

   ```yaml
   ---
   name: my-skill
   description: One-line summary used for selection + display.
   domain: web
   subdomain: api
   tags:
     - api
     - owasp
     - sql-injection
   nist_csf:
     - PR.IP
   mitre_attack:
     - T1190
   ---
   ```

3. Body: `## When to Use` and `## Workflow` sections. The body is **untrusted
   imported markdown** — role-directive lines (`## SYSTEM:`, `[SYSTEM]`,
   `<<SYSTEM>>`, `<|...|>`) and tool-call mimics (`- run tool: ...`) are
   stripped by `_sanitize_skill_body` before the body reaches any prompt, and
   the rendered output is wrapped in an `<untrusted_skill_guidance>` fence.
   Do not rely on such constructs — they will not survive.
4. Optional `references/*.md` bundle: paths are listable via the
   `list_skill_references` MCP tool and surfaced in rendered metadata when
   `skills.include_metadata: true`. Contents are never inlined into a prompt.
5. Tune selection in `config.yaml`: add the skill to `default_enabled`, or
   match it via `include_tags` / its tags.

## Config keys (all under `skills:`)

| Key | Default | Purpose |
| --- | --- | --- |
| `enabled` | `true` | Master toggle. |
| `inject_startup_context` | `false` | Inject selected bodies into the initial prompt (eager). |
| `maybe_enabled` | `false` | Include `skills/maybe/` skills. |
| `reselect_mid_run` | `true` | Re-select skills as new services/CVEs appear. |
| `reselect_max_per_run` | `3` | Max re-selections per run. |
| `reselect_min_interval_actions` | `5` | Min actions between re-selections. |
| `reselect_sticky_defaults` | `true` | Retain `default_enabled` across re-selections. |
| `swarm_inject` | `true` | Build a shared selection for the swarm. |
| `swarm_phase_hints_only` | `true` | Non-exploit swarm agents get hints only, never bodies. |
| `feedback_enabled` | `true` | Apply the cross-mission feedback boost. |
| `feedback_skill_weight` | `8` | Boost-only score weight. |
| `feedback_min_observations` | `3` | Min observations before the boost applies. |
| `semantic_matching` | `true` | Embedding-based ranking (with graceful fallback). |
| `semantic_skill_weight` | `16` | Semantic score weight. |
| `semantic_min_similarity` | `0.35` | Ignore weak semantic matches below this cosine score. |
| `semantic_model` | `nomic-embed-text` | Embedding model. |
| `diversity_penalty` | `12` | Penalize redundant skills with heavily overlapping tags. |
| `include_metadata` | `false` | Append References/NIST/MITRE summaries in rendered context. |
| `allow_reference_listing` | `true` | Allow the `list_skill_references` MCP tool. |

## CLI flags

`--skills {on,off,hints,lookup}`, `--skills-list`, `--skills-include NAME`,
`--skills-exclude NAME`, `--no-skills-reselect`. See the README Runtime Skills
section. These mutate the in-memory `config["skills"]` dict only — advisory,
never permission/scope/audit.

## Invariant

Skills are advisory prompt context only. They never change
`ExploitPermission`, widen `scope_gate`, bypass `require_allowlist` /
command-safety / workspace containment, or suppress audit logging. The
read-only MCP skill tools remain the only way the model *pulls* a full skill
body mid-run; re-selection only changes which hints are pre-injected.
