---
title: Settings Page
sources:
  - webui/src/features/settings/SettingsPage.tsx
  - webui/src/features/settings/useSettingsDraft.tsx
  - webui/src/features/settings/settingMeta.ts
  - webui/src/features/settings/SettingsNav.tsx
  - webui/src/features/settings/SettingsSearch.tsx
  - webui/src/features/settings/SettingsSection.tsx
  - webui/src/features/settings/StatusOverview.tsx
  - webui/src/features/settings/GeneralSettings.tsx
  - webui/src/features/settings/ProviderSettings.tsx
  - webui/src/features/settings/FeatureSettings.tsx
  - webui/src/features/settings/AdvancedSettings.tsx
  - webui/src/features/settings/ConfigField.tsx
  - webui/src/features/settings/ConfigEditor.tsx
  - webui/src/features/settings/DangerZone.tsx
  - webui/src/routes/SystemPage.tsx
tests:
  - webui/src/features/settings/SettingsPage.test.tsx
subsystem: webui
---

# Settings (`/system`)

Route: `webui/src/App.tsx:74` → `webui/src/routes/SystemPage.tsx:6` (thin wrapper) → `webui/src/features/settings/SettingsPage.tsx:20` (`SettingsPage`).

Wraps content with `SettingsDraftProvider` (`features/settings/useSettingsDraft.tsx`) — single shared draft for all categories; `PATCH /config` is atomic on save, deep-merge on server (`docs/api.md: PATCH /config`).

## Layout (`SettingsPage.tsx:28`)

```
<StatusOverview>  // read-only summary (providers, models, secrets, plugins)
header: title "Settings" + savedAt (formatSavedAt) + Diagnostics button → category "advanced" + <SettingsSearch>
body: <SettingsNav> (sidebar 44 on desktop, segmented on mobile) + <ActiveCategory>
<UnsavedChangesBar>  // sticky footer when draft !== server
```

| Component | File | Role |
|-----------|------|------|
| `SettingsNav` | `features/settings/SettingsNav.tsx` | 4 categories `general|ai|features|advanced` (icons from `settingMeta.ts`) |
| `SettingsSearch` | `features/settings/SettingsSearch.tsx` | global search across all `SECTIONS`; `onSearchSelect(cat,section,field) → setCategory(cat) + requestAnimationFrame scrollIntoView #setting-${section}-${field}` |
| `StatusOverview` | `features/settings/StatusOverview.tsx` | compact read-only chips from `capabilities/config/secrets/models/providers` |
| `UnsavedChangesBar` | `features/settings/UnsavedChangesBar.tsx` | appears when draft dirty; Save → `usePatchConfig` (`api/hooks.ts:142`), Discard → revert |
| `SettingRow` | `features/settings/SettingRow.tsx` | label+help+field+validation error wrapper |
| `ConfigField` / `ConfigEditor` | `features/settings/ConfigField.tsx`, `ConfigEditor.tsx` | typed inputs, redacted preview (`sanitize()` server-side) |

Categories:

## General (`GeneralSettings.tsx`)

| Section | Fields (config keys) | Control |
|---------|----------------------|---------|
| API | `api.enabled`, `api.host`, `api.port`, `api.event_buffer_size`, `api.shutdown_timeout_seconds`, `api.max_concurrent_runs`, `api.multi_operator`, `api.graph_route` | `number/input/switch`; `allowed_origins` validated loopback-only on PATCH |
| Reports | `reports.dir` | path |
| Assessment | `assessment.max_commands`, `assessment.max_rounds`, `assessment.max_duration_seconds` | numbers |

Mirrors `docs/api.md: Config Reference` `api` block. Validation errors surface from `400 config_invalid` `details.errors` via `ConfigValidationErrorResponse` (`api/types.ts:783`).

## AI Provider (`ProviderSettings.tsx`)

Provider card as in `docs/webui.md: System Page` — segmented `Ollama` / `ChatGPT` bound to `models.provider`; switching `PATCH /config` deep-merge (`→ chatgpt.enabled:true` for ChatGPT) and invalidates `models/modelsLive/providers` via `usePatchConfig.onSuccess` (`api/hooks.ts:152`).

| Subsection | Hook / Endpoint | Detail |
|------------|-----------------|--------|
| Provider picker | `useModels` (`hooks.ts:189`), `useProviders` (`hooks.ts:248`), `useSetModelProvider` (`hooks.ts:236` → `POST /models/provider`) | registry vs `chatgpt.configured_models` |
| Live models | `useLiveModels` (`hooks.ts:198` → `GET /models/live`) | source badge `ollama|registry|chatgpt`; error line; for ChatGPT auto-starts proxy |
| ChatGPT status | `GET /providers` (`hooks.ts:248`) | `host:port`, `default_model`, badges signed-in/proxy-running/we_started |
| OAuth | `useChatgptLogin` (`hooks.ts:294` → `POST /providers/chatgpt/login`) | surfaces URL link, tokens never reach SPA |
| Proxy lifecycle | `useChatgptProxyStart/Stop` (`hooks.ts:302` → `POST /providers/chatgpt/proxy/{start,stop}`) | Stop gated `we_started` |
| Ollama note | static | embeddings stay on Ollama under either provider |
| Secrets | `useSecrets / usePutSecrets` (`hooks.ts:169` → `GET/PUT /secrets`) | write-only inputs, `configured/missing` status |

## Features (`FeatureSettings.tsx`)

Feature-flag toggles surfaced from `config` + `capabilities.features` / `run_options.flags`:

| Flag | Config section | Effect |
|------|----------------|--------|
| `swarm / parallel_swarm` | `swarm` | gated `powerUps` in `RunWizard` |
| `critic / reflection` | `swarm` | only when `swarm` on |
| `adaptive_exploits` | `exploits` | |
| `long_session` | `session` | enables `Campaign` tab on `RunPage` |
| `multi_model_consult` | `models` | |
| `ultrathink` | `session` | |
| `recon_first` | run-level | tri-state in wizard |
| `skills` | `skills` | master + lookup/inject switches (see `SkillsPage`) |
| `graph_route` | `api` | enables `/graph` + `GET /graph/*` |
| `threat_intel / mitre / poc_verification / replay_simulator / peer_review` | `features` | gate Advisory tools (`RunPage AdvisoryPanel`) |

`FeatureSettings.tsx` renders switches via `ConfigField` bound to draft; `settingMeta.ts` defines labels/help/defaults per field.

## Advanced (`AdvancedSettings.tsx`)

| Section | Component / Hook | Detail |
|---------|------------------|--------|
| Raw config | `ConfigEditor` (`features/settings/ConfigEditor.tsx`) | read-only redacted `GET /config` (`hooks.ts:124`), editable JSON-ish form + `PATCH /config` |
| Secrets (expanded) | `useSecrets / usePutSecrets` | per-key `configured/missing`, write-only `PUT /secrets {secrets:{...}}` |
| Plugins | `usePlugins` (`hooks.ts:318` → `GET /plugins`) | `name/version/loaded/capabilities/enabled` list |
| Telemetry | `useTelemetry` (`hooks.ts:266` → `GET /system/telemetry`) | summary + recent records |
| System info | `useSystemInfo` (`hooks.ts:257` → `GET /system/info`) | `hostname/platform/os/python/local_ips/public_ip` |
| Danger zone | `DangerZone` (`features/settings/DangerZone.tsx`) + `useResetSystem` (`hooks.ts:409` → `POST /system/reset`) | deletes runs + artifacts + workspaces |
| Diagnostics | `useDiagnostics` (`hooks.ts:401` → `POST /diagnostics/{doctor,self-test}`) | exit code + output `<pre>` |

Search indexes `AdvancedSettings` fields under "advanced" so `SettingsSearch` can jump to e.g. `api.graph_route`.

## Draft machinery (`useSettingsDraft.tsx`)

| Export | Role |
|--------|------|
| `SettingsDraftProvider` | fetches `GET /config` + `GET /config/schema` (`hooks.ts:124,133`), seeds `draft = config`; exposes `draft, patchDraft(path,value), reset, save, dirty, saving, error, savedAt` |
| `useSettingsDraft()` | consumer hook; `patchDraft` deep-merges a partial (e.g. `{skills:{enabled:true}}`), `save()` calls `usePatchConfig` mutation, on success writes `data.config` back and sets `savedAt=Date.now()` (`SettingsPage.tsx:30` `formatSavedAt`) |
| `formatSavedAt` | `features/settings/format.ts` — `just now / Ns ago` |

Dirty check is shallow diff of drafted keys vs server snapshot; `UnsavedChangesBar` enables Save/Discard accordingly.

## `settingMeta.ts`

Declarative registry drives search + nav + field rendering. Each entry: `category, section, field, label, help, type (switch/input/select/number), default, schemaRef`. `SettingsSearch` flattens all entries, fuzzy-matches query across label/help/field; nav renders category counts from meta. Adding a config key = add an entry there first.

## Validation

Server is author of truth. `PATCH /config` (`api/hooks.ts:145`) runs `ConfigValidator`; failure `400 config_invalid` with `details.errors[]` rendered inline per field. `allowed_origins` validated loopback-only before write (`docs/api.md: PATCH /config`). Errors shown via `useToast` (`hooks/use-toast.ts`) + per-field messages.
