---
title: Run-Create Components — Wizard, Steps, Profiles
sources:
  - webui/src/components/run-create/RunWizard.tsx
  - webui/src/components/run-create/RunStepper.tsx
  - webui/src/components/run-create/RunReview.tsx
  - webui/src/components/run-create/RunSummary.tsx
  - webui/src/components/run-create/ModeSelector.tsx
  - webui/src/components/run-create/TargetField.tsx
  - webui/src/components/run-create/GoalSelector.tsx
  - webui/src/components/run-create/ModelSelector.tsx
  - webui/src/components/run-create/ExecutionProfile.tsx
  - webui/src/components/run-create/AdvancedExecutionSettings.tsx
  - webui/src/components/run-create/SkillsSettings.tsx
  - webui/src/components/run-create/OpsecSettings.tsx
  - webui/src/components/run-create/profile.ts
  - webui/src/lib/targetValidation.ts
  - webui/src/components/ProviderSetup.tsx
tests:
  - webui/src/components/run-create/RunWizard.test.tsx
subsystem: webui
---

# Run-Create Components (`components/run-create/*`)

All 14 files verified under `webui/src/components/run-create/*.tsx|.ts` (glob). The wizard mirrors the CLI `questionary` flow.

## Architecture

```
NewRunPage (route wrapper)
  └─ RunWizard (src/components/run-create/RunWizard.tsx:34)
       ├─ RunStepper  (opsec → settings → target → review) — STEPS const
       ├─ OpsecSettings (mode recon/attack/fast advisory)
       ├─ ModeSelector
       ├─ GoalSelector
       ├─ ModelSelector
       ├─ ExecutionProfile (standard/fast/deep/custom)
       ├─ AdvancedExecutionSettings (power-ups + observer + recon_first)
       ├─ SkillsSettings (skillsMode + include/exclude)
       ├─ TargetField
       ├─ RunReview (+ DecisionCard for start_confirm)
       └─ RunSummary (sticky rail, re-rendered inline on mobile)
  profile.ts (pure preset → field values)
```

Legacy `components/RunForm.tsx` still exports shared toggles (`SegmentedControl`, `TriStateToggle`, `ToggleRow`, `SkillMultiSelect`) consumed by `AdvancedExecutionSettings` / `SkillsSettings` for consistent style.

## Wizard state (`RunWizard.tsx:34`)

| Hook/state | Default | Setter touch |
|------------|---------|--------------|
| `mode:RunMode` | `searchParams.get("path")` → `recon` unless `attack|fast` | `handleModeChange` (fast resets `powerUps` off etc.) |
| `modelAlias` | `""` → seeded from `useDefaultModel()` (`ProviderSetup.tsx`) via `useEffect` `RunWizard.tsx:77` | `setModelAlias` via `ModelSelector` |
| `profile:ExecutionProfileId` | `"standard"` | `applyProfile` sets fields in batch with `applyingRef` to suppress `custom` flip |
| `powerUps:Record<string,bool>` | `{}` | `togglePowerUp(key)` → `touch()` flips profile to `custom`; gated `!!swarm` guards `critic/reflection` in `buildRequest` |
| `reconFirst:boolean|null` | `true` | `setReconFirst` |
| `observerMode:ObserverMode` | `"hybrid"` | provider: `hybrid|heuristic|llm` |
| `skillsMode:SkillsMode` | `"off"` | `null` when `off`, else `on|lookup|hints` |
| `skillsInclude/Exclude:string[]` | `[]` | multi-select |
| `yes:boolean` | `false` | `Checkbox id skip-confirm` |
| `goalMode:"preset"|"custom"` + `goal:string` + `customGoal:string` | `preset/""` | `GoalSelector` |
| `target:string` | `""` | `TargetField` |
| `createdRun:CreateRunResponse|null` + `createError` | `null/""` | set by `createTheRun()` |

Goals groups `goalGroups {safe,gated,high}` (`RunWizard.tsx:81`) from `useGoals` (`api/hooks.ts:336`, `staleTime Infinity`).

`?goal=<name>` preselect only when `found.compatible` (`RunWizard.tsx:88`), else null (no auto-pick).

`flags = capabilities.run_options.flags ?? []`; `visiblePowerUps = [swarm,parallel_swarm,critic,reflection,adaptive_exploits,long_session,multi_model_consult,ultrathink].filter(isInFlags)`.

### Navigation

`STEPS` (`RunStepper.tsx`): `["opsec","settings","target","review"]`. `stepIndex = indexOf(step)`. `canGoNext = (opsec||settings) || (target && isValidTarget(target))`. `canVisit` (`RunWizard.tsx:192`): backward steps always if `i<=stepIndex && i!==stepIndex` (clickable), next only if `i===stepIndex+1 && canGoNext`. `goNext/goBack` move index or `navigate(-1)` at start. `review` is only reached by `canGoNext` from `target`.

### Request builder (`RunWizard.tsx:147`)

```ts
buildRequest():RunCreateRequest = {
  target:trimmed, mode, goal:(preset?goal:""), custom_goal:(custom?trimmed:""),
  recon_first, model:alias||undefined,
  swarm, parallel_swarm, critic:swarm&&critic, reflection:swarm&&reflection,
  adaptive_exploits, long_session, multi_model_consult??null, observer_mode,
  ultrathink, skills: (off?null:skillsMode), skills_include/exclude, kind:"agent", yes
}
```

Matches `RunCreateRequest` (`api/types.ts:249`: `RunMode`, `SkillsMode`, `ObserverMode`). `critic/reflection` are forced `false` when `!swarm` (gating invariant).

`createTheRun(): void` (`RunWizard.tsx:170`): clears error, `createRun.mutate(buildRequest(), onSuccess setCreatedRun; if queued|running → onCreated(id,state) navigate)`.

`summaryProps` passed to `RunSummary` twice (desktop sticky `lg:sticky` + mobile below `lg:hidden`).

## Steps

### 1. OpsecSteps (`OpsecSettings.tsx`)

Advisory only (server remains authority). Banner per `mode` explaining scope vs attack vs fast. No controls — informational.

### 2. Settings (`RunWizard.tsx:234`)

Stack: `ModeSelector → GoalSelector → ModelSelector → ExecutionProfile → AdvancedExecutionSettings/SkillsSettings (collapsible) → Skip-confirm checkbox`.

#### `ModeSelector.tsx`

Segmented control `recon|attack|fast`. `handleModeChange` handles `fast` reset:

```ts
if(next==="fast"){ applyingRef=true; reconFirst=true; observerMode="hybrid";
  powerUps=all false; applyingRef=false }
```

`fast` does not force profile id — stays `standard` but fields are fast-optimized, overrideable in Advanced.

#### `GoalSelector.tsx`

`mode` (attack path only), `goalMode preset|custom`, preset `Select` grouped by `risk` (`safe/gated/high` via `goalGroups`), disabled custom text area when `preset`, free `customGoal` when `custom`. Setting a goal on attack path toggles recon-first off (UX hint, not enforced).

#### `ModelSelector.tsx`

Provider-aware:

| Provider | Source | Picker |
|----------|--------|--------|
| `ollama` | `useLiveModels` (`hooks.ts:198` → `GET /models/live` `source ollama|registry|chatgpt`) + registry `useModels` (`hooks.ts:189`) | list with provider badges + refresh |
| `chatgpt` | `chatgpt.configured_models` + discovery | `chatgpt.default_model` surfaced |

Uses `useDefaultModel` (`ProviderSetup.tsx`): `default_alias` or first registry entry.

#### `ExecutionProfile.tsx`

Four pills driven by `profileFieldValues(id, flags)` (`profile.ts:52`):

| id | powerUps biased | observer | skills |
|----|-----------------|----------|--------|
| `standard` | `OFF` (all false) | `hybrid` | `off` |
| `fast` | `OFF` | `heuristic` | `off` |
| `deep` | all `on(key)` where `flags.includes(key)` | `llm` | `on` |
| `custom` | — (null) | — | — |

`OFF` const (`profile.ts:35`). Manual edit of any controlled field flips to `custom` via `touch()` (`RunWizard.tsx:108`) suppressed during `applyProfile` batch (`applyingRef`).

`executionProfileLabel` (`profile.ts:82`) for summaries.

#### `AdvancedExecutionSettings.tsx`

Gated rows: each `ToggleRow` for a flag in `flags` (`visiblePowerUps`). Disabled `critic/parallel_swarm/reflection` unless `swarm` on. `observerMode SegmentedControl (heuristic/hybrid/llm)` via `setObserverMode+touch`. `reconFirst TriStateToggle true|false|null` (null=auto). Bounded to `visiblePowerUps` only — an unsupported flag is never enabled.

#### `SkillsSettings.tsx`

`SegmentedControl` `off|on|hints|lookup`; when not `off`, shows include/exclude `SkillMultiSelect` (populated `skillsList = skills.map(name)`). Include/exclude arrays are always arrays (empty when none) per `types.ts:257`.

#### Skip confirmation

`Checkbox id skip-confirm` (`RunWizard.tsx:295`) + `Label` with blurb "Start immediately without requiring the normal confirmation step." Maps to `yes` in request.

### 3. Target (`TargetField.tsx`)

Single `Input` validated by `isValidTarget` (`lib/targetValidation.ts:20`): strict IPv4 regex (`STRICT_IPV4`), IPv6 (`IPV6` with `:`) loose structural, FQDN (`FQDN label·TLD≥2`). `autoFocus`, error message when `!isValidTarget`, `canGoNext` gating. Trimmed on build, never logged beyond request.

### 4. Review (`RunReview.tsx`)

Handoff from wizard to server gate.

Props (`RunReview.tsx`): `mode/target/goalMode/goal/customGoal/model/profile/powerUpCount/skillsMode/observerMode/reconFirst/yes + isCreating/createError/createdRun/onCreate/onRetry/onCreated/onEdit`.

Subsections:

| Area | Render |
|------|--------|
| Summary card | `RunSummary` reuse showing all collected fields |
| `onEdit(step)` | jump back to `opsec|settings|target` |
| `onCreate` button → `createTheRun` | triggers `useCreateRun`; `isCreating` shows `Loader2` |
| Error | `ApiError.message` in `createError` |
| Gate (`createdRun.state` not `queued|running`) | `start_confirm` decision (`types.ts:299` `{id,kind: start_confirm,required_text,prompt_text}`) rendered via `DecisionCard` (`components/DecisionCard.tsx`): destructive (`permission full_access+attack_mode`) requires typing exact `required_confirmation_text` (e.g. `ALLOW 10.0.0.50`) button disabled until match; non-destructive → single `Proceed` sending `"y"` via `useAnswerDecision(runId)` `POST /runs/<id>/decisions/<decId> {answer}` |

When server returns `state queued|running` (e.g. `yes:true`), `RunWizard onCreated` → navigation skips gate.

## Helpers

| Helper | File | Purpose |
|--------|------|---------|
| `isValidTarget` | `lib/targetValidation.ts:20` | mirror of `tools/validation_utils.py _STRICT_IPV4_RE/_FQDN_RE` client-side |
| `validate_target_or_ip` pattern | backend | allowlist + domain/CIDR matcher `tools/validation_utils.py:380` (notes only) |
| `useCapabilities` | `api/hooks.ts:114` | flags → `visiblePowerUps` + power-up gating |
| `useGoals` | `api/hooks.ts:336` | presets |
| `useSkills` | `api/hooks.ts:344` | include/exclude options |
| `useDefaultModel` | `components/ProviderSetup.tsx` | default alias seeding |

## Testing

`RunWizard.test.tsx` — mocked `createRun` / `capabilities` / `goals`; asserts `buildRequest` shape for swarm-critic gating, goal preselect compatibility, target validation blocking `review`.
