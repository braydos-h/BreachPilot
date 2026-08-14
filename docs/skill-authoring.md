# Building & Improving Runtime Skills

Practical guide for authoring new `SKILL.md` files and making existing skills
select more often and perform better. For the pipeline internals (selection,
re-selection, feedback, semantic matching) see [skills.md](skills.md).

## What a skill is

A skill is a `SKILL.md` file (YAML frontmatter + markdown body) under
`skills/` (or a plugin-contributed skill dir). It is **advisory prompt
context only** — it never grants execution authority, never changes
permission/scope/audit. The model sees a compact hint at selection time and
pulls the full body mid-run via the read-only `load_runtime_skill` MCP tool.

## Build a skill

### 1. Layout

```
skills/<skill-name>/SKILL.md          # required
skills/<skill-name>/references/*.md   # optional, never inlined into prompts
skills/maybe/<skill-name>/SKILL.md    # gated tier, ignored unless skills.maybe_enabled
```

`<skill-name>` must be unique across all roots (duplicates are dropped with a
warning). Use kebab-case, verb-first names that match how the model would
search: `exploiting-sql-injection-vulnerabilities`, `performing-dns-enumeration-and-zone-transfer`.

### 2. Frontmatter

```yaml
---
name: my-skill
description: One-line summary used for selection + display.
domain: cybersecurity
subdomain: penetration-testing
tags:
  - sql-injection
  - sqlmap
nist_csf:
  - ID.RA-01
mitre_attack:
  - T1190
version: 1.0.0
---
```

The **description is the single most important field** — it is the primary
signal for both lexical search and semantic matching (the embedder uses
name + description + domain + subdomain + tags, never the body). Write it as:
what the skill does, in what context, and when to activate. The catalog
(`--skills-list`, `list_runtime_skills`) truncates it at ~240 chars.

### 3. Tags are the routing language

Selection matches tags against signals derived from the goal, discovered
services, CVEs, recent tools, and swarm phase. Use the existing vocabulary
(see `_SERVICE_TAGS` / `_GOAL_TAGS` in `tools/skill_selector.py` and
`_PHASE_TAGS` in `tools/swarm/skill_phase.py`):

| Signal source | Recognized tags (examples) |
| --- | --- |
| Service `http`/`https` | `web`, `web-application`, `http`, `security-headers` |
| Service `api`/`graphql` | `api`, `web`, `owasp`, `graphql` |
| Service `smb`/`ldap`/`kerberos`/`rdp` | `smb`, `active-directory`, `windows`, `ldap`, `kerberos`, `rdp` |
| Service `mysql`/`postgres`/`mongodb` | `database`, `sql-injection`, `nosql`, `web` |
| Goal `recon`/`scan`/`verify`/`cve`/`web`/`api`/`credential`/`report` | `reconnaissance`, `nmap`, `vulnerability-scanning`, `cve`, `cvss`, `credential`, `reporting` |
| Tool `nmap` / `searchsploit` | `nmap`, `network-security`, `exploit-research` |
| Swarm phase | `reconnaissance`, `vulnerability-scanning`, `exploit`, `post-exploit`, `credential`, `privilege-escalation`, `lateral` |

Tag aliases exist (`api-security` → `api`/`web`/`owasp`, `ssl` → `tls`,
`active-directory` → `windows`/`ldap`/`kerberos`/`smb`, …) — see
`_TAG_ALIASES` in `tools/skill_registry.py`. Prefer canonical tags over
invented ones; a tag no signal ever emits is dead weight.

**Attack-only gating**: in `recon` mode, skills whose name or tags contain
attack terms (`exploit`, `bypass`, `credential`, `privilege-escalation`,
`lateral`, `red-team`, `metasploit`, `post-exploit`, …) are excluded from
selection. If your skill is exploit methodology, that is correct behavior —
it will only surface in `attack` mode. Don't fight it by renaming tags.

### 4. Body structure

The renderer pulls sections by heading name, in this order of preference
(`_important_body` in `tools/skill_registry.py`):

1. `## When to Use` — when the model should apply this methodology
2. `## Do Not Use` — when it must not (authorization limits, destructive ops)
3. `## Prerequisites` — tools, accounts, authorization needed
4. `## Workflow` — the actual step-by-step methodology
5. `## Safety Considerations` / `## Best Practices`

Keep the body under ~2500 chars of *important* content — that is
`max_chars_per_skill`; anything beyond is truncated in rendered context.
Hints are what the model sees by default; the body is loaded on demand, so
put the decision-relevant content in `When to Use`/`Do Not Use` and the
long-form detail in `Workflow`.

**The body is untrusted imported markdown.** `_sanitize_skill_body` strips
role-directive lines (`## SYSTEM:`, `[SYSTEM]`, `<<SYSTEM>>`, `<|...|>`),
tool-call mimics (`- run tool: ...`), HTML comments, and script/iframe
blocks before anything reaches a prompt, and the rendered output is wrapped
in an `<untrusted_skill_guidance>` fence. Do not rely on such constructs —
they will not survive. Never put instructions that conflict with scope,
permission, approval, command-safety, or audit rules; the model is told to
treat imported guidance with suspicion.

### 5. Optional references bundle

`references/*.md` files are listed (paths only) via `list_skill_references`
and surfaced as one-line summaries when `skills.include_metadata: true`.
Contents are **never inlined into a prompt** — the model reads them through
the workspace read tools, still subject to the allowlist. Use them for
deep-dive material (API references, standards, full workflows) that would
bloat the body.

### 6. The `maybe/` tier

Higher-risk or niche skills go under `skills/maybe/`. They are excluded from
selection, the catalog, and `load_runtime_skill` until
`skills.maybe_enabled: true`. Promote a skill out of `maybe/` once it has
proven itself in real runs.

### 7. Verify

```powershell
python main.py --skills-list                 # catalog: is it parsed, tagged, listed?
python main.py --skills on --target <ip>     # full bodies injected at startup
python main.py --skills lookup --target <ip> # hints only; model pulls bodies via MCP
```

Check `WARNINGS:` in the catalog output — parse failures and duplicate names
are reported there. If the skill changes core routing/selection behavior,
add a case to `tests/test_skill_registry.py` or `tests/test_skill_selector.py`
(see `_write_skill` helper for the minimal fixture shape).

## Improve a skill

### Selection tuning (config.yaml, all under `skills:`)

| Knob | Default | Effect |
| --- | --- | --- |
| `default_enabled` | 6 skills | Force-include skills that must always be present (safety-relevant methodology). Weight `default_skill_weight` (12). |
| `include_tags` | `[]` | Force-include every skill carrying a tag. Weight `context_skill_weight` (24). |
| `max_active_skills` | 6 | Context budget. Raising it dilutes attention; lowering it starves niche skills. |
| `min_contextual_skills` | 3 | Guaranteed slots for context-matched skills over defaults. |
| `diversity_penalty` | 12 | Penalizes near-duplicate tag sets (overlap ≥ 0.6). If two skills keep fighting for one slot, differentiate their tags. |
| `semantic_skill_weight` | 16 | Cosine-similarity score weight. Raise it if tag matching misses relevant skills. |
| `semantic_min_similarity` | 0.35 | Ignore weak semantic matches. Lower it to surface more candidates. |
| `feedback_skill_weight` | 8 | Boost-only weight for skills with a positive track record. |

If a skill never gets selected: check its tags against the signal tables
above, check the description for the terms the model would use, and check
whether it is being excluded by attack-only gating or the diversity penalty.
`--skills-include <name>` force-includes for one run to test it without
touching config.

### The feedback loop

`tools/skill_feedback.py` records, into the shared `lessons` table:

- a neutral observation when the model calls `load_runtime_skill`,
- a `success`/`failure` per active skill at phase end (from the reflection
  agent).

`skill_prior` is a Beta posterior mean; the selector applies
`(prior - 0.5) * 2 * feedback_skill_weight` as a **boost-only** term once
`feedback_min_observations` (3) is reached. Negative outcomes never exclude
a skill. So a skill improves by being *loaded and used successfully* across
missions — the fastest way to improve a skill's standing is to make its
`When to Use` section precise enough that the model loads it at the right
moment, and its `Workflow` reliable enough that phases it informs succeed.

### Semantic matching

When `skills.semantic_matching: true` (default) and an embedder is available
(local `ollama.embed_host`, model `nomic-embed-text`), skills are also
ranked by cosine similarity of name + description + domain + subdomain +
tags against the run context. This means **description quality directly
drives semantic recall** — a description that names the techniques, targets,
and tools of the skill will match queries that share no tags. When
embeddings are unavailable the selector logs one
`[WARN] skills: embeddings unavailable, falling back to tag matching` and
deterministic tag matching remains the floor.

### Iteration checklist

- [ ] Description names the techniques/tools/context and says when to activate
- [ ] Tags use the canonical vocabulary and match the service/goal/phase signals
- [ ] `When to Use` / `Do Not Use` are the first sections (they are what gets rendered)
- [ ] Body under `max_chars_per_skill`; long detail moved to `references/`
- [ ] No role-directive lines or tool-call mimics (they are stripped anyway)
- [ ] `python main.py --skills-list` shows it with no warnings
- [ ] If it should always be present: added to `default_enabled`
- [ ] If it is niche/risky: lives under `skills/maybe/` until proven
