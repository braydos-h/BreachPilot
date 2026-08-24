---
title: Other Pages — Artifacts, Memory, Loot, Skills, Goals, Help, Stats, Modules
sources:
  - webui/src/routes/ArtifactsPage.tsx
  - webui/src/routes/MemoryPage.tsx
  - webui/src/routes/LootPage.tsx
  - webui/src/routes/SkillsPage.tsx
  - webui/src/routes/GoalsPage.tsx
  - webui/src/routes/HelpPage.tsx
  - webui/src/routes/StatsPage.tsx
  - webui/src/routes/AttackModulesPage.tsx
  - webui/src/routes/SystemPage.tsx
  - webui/src/api/hooks.ts
  - webui/src/api/types.ts
tests: []
subsystem: webui
---

# Other Pages

Covers pages not given a dedicated file: artifacts/workspace/audit/logs, memory, loot/credentials, skills catalog, goal catalog, help, stats/telemetry, attack modules. System is under `docs/webui/pages/settings.md`.

## Artifacts (`/runs/:runId/artifacts`)

`webui/src/routes/ArtifactsPage.tsx:23` (`ArtifactsPage`, lazy). Four tabs inside `Tabs` + `ScrollArea`.

| Tab | Gate | Hook / URL | Component |
|-----|------|------------|-----------|
| Artifacts | always | `useArtifacts(runId)` (`hooks.ts:599` → `GET /runs/<id>/artifacts` → `ArtifactListResponse` `types.ts:474`) | left file list (`FileText` + `formatBytes`) + `ArtifactViewer` (`components/ArtifactViewer.tsx`, `useFetchArtifactBlob` raw `Blob`) |
| Workspace | always | `useWorkspace(runId)` (`hooks.ts:725` → `GET /runs/<id>/workspace` → `WorkspaceListResponse` `types.ts:771`) | `WorkspacePanel` (`ArtifactsPage.tsx:149`): filter `Input`, list with `formatBytes`, `WorkspaceViewer` (`components/WorkspaceViewer.tsx`) |
| Audit | `tab==="audit"` | `useAudit(runId)` (`hooks.ts:619` → `GET /runs/<id>/audit` → `AuditResponse` `types.ts:538` `{records, chain_valid, chain_reason}`) | `AuditRecordsTable` + `Badge success|danger` chain banner |
| Logs | always | `useRunLog(runId,name,tail,attemptId,targetIp)` (`hooks.ts:656` → `GET /runs/<id>/logs/<name>?tail&attempt_id&target_ip` → `LogResponse` `types.ts:553`) | `LogsPanel` (`ArtifactsPage.tsx:217`): log select (optgroups Run-level vs Per-attempt) + Tail `1–2000` + Attempt/Target selects |

Artifacts header shows mono `runId` + refresh (`RefreshCw` spin) for artifacts. Attempt candidates derived from artifact names matching `^exploit_workspace/(?:(?<ip>[^/]+)/)?(?<attempt>[^/]+)/` (`ArtifactsPage.tsx:41`). `RUN_LOGS = [mcp_exploit_server.log, session_error.log, recon_first_error.log]`, `ATTEMPT_LOGS = [terminal.log, python_run.log, msf_output.log, run_active_check.ps1]`. When `isAttemptLog && candidates empty`, amber notice explains discovery heuristic.

`ArtifactViewer` uses `useFetchArtifactBlob` (`hooks.ts:759` → `GET /runs/<id>/artifacts/<path>` raw) with `useArtifactUrl` for download link. `WorkspaceViewer` same pattern via `useFetchWorkspaceFile` (`hooks.ts:742`).

## Memory (`/memory`)

`webui/src/routes/MemoryPage.tsx:9` (`MemoryPage`). `useMemory` (`hooks.ts:275` → `GET /system/memory` → `MemoryResponse` `types.ts:762` `{lessons:MemoryLesson[], confidence:MemoryConfidence[], attack_memory:AttackMemoryItem[]}`).

Three cards:

| Card | Data | Columns / UI |
|------|------|--------------|
| Skill outcome confidence | `confidence` | table `action|obs|success|failure|partial|confidence%(fixed0)|last seen(formatRelative)` (`MemoryPage.tsx:63` `isLoading SkeletonRows`, error +Retry) |
| Cross-mission learnings | `lessons` | list `Badge outcome(success green/failure red/outline)` + `action_type` + `target_signature` + `created_at` |
| Attack memory | `attack_memory` | filterable list. Controls: target `select` (derived `[...new Set(target_ip)]` `MemoryPage.tsx:19`), category `select` (`category` set). Row: `category Badge` + `target_ip` + `source_tool` + `ok/fail` + `last_seen_at` + `item_key: item_value ×seen_count` |

Header: `Brain` + title + `RefreshCw` (`memory.refetch()`). Empty states per card.

## Loot (`/runs/:runId/loot`)

`webui/src/routes/LootPage.tsx:12` (`LootPage`). Header mono `runId` + refresh. Two sections:

| Section | Hook / URL | Component |
|---------|------------|-----------|
| Credentials | `CredentialTable` (`components/CredentialTable.tsx`, `useCredentials` `hooks.ts:679` → `GET /runs/<id>/credentials` → `CredentialsResponse` `types.ts:574`, `useRevealCredential` `hooks.ts:688` → `POST /credentials/<index>/reveal` → `CredentialRevealResponse` `types.ts:580`) | masked table with Reveal/Confirm (`useConfirmCredential` `hooks.ts:701`) |
| Loot | `useLoot(runId)` (`hooks.ts:716` → `GET /runs/<id>/loot` → `LootResponse` `types.ts:594` `LootItem[]`) | expandable `Card` per `loot_type` + `description`, expand toggle `Expand rotate-180`, `<pre>` `content||path` |

`loot.isLoading → SkeletonCards(2)`, `error → ApiError.message + Retry`, empty → "No loot captured."

## Skills (`/skills`)

`webui/src/routes/SkillsPage.tsx:223` (`SkillsPage`). Most complex catalog page.

| Concern | Hook / Type | Detail |
|---------|-------------|--------|
| Catalog | `useSkills` (`hooks.ts:344` → `GET /skills` → `{skills:SkillSummary[], error?}`) + `useSkillSearch(q)` debounced 250ms (`hooks.ts:354`) + `useSkillDetail(name)` (`hooks.ts:370` → `GET /skills/<name>` → `SkillDetail` `types.ts:207`) | `search` maps to `SkillSummary` via `tagByName` when searching |
| Config | `useConfig` + `readSkillsConfig(cfg)` (`SkillsPage.tsx:91`) → `SkillsConfig {enabled, default_enabled[], exclude_names[], allow_model_lookup, inject_startup_context}` + `usePatchConfig` → `PATCH /config {skills:…}` | `skillState(name,cfg)` → `enabled|blocked|auto` + `STATE_META` dot/icon |
| Derived | `topTags` (20 most frequent), `filtered` (search + tag + status + sort), `enabled/blocked/auto` counts, `hasActiveFilters` | sort `default|name|state` (`SkillsPage.tsx:213`) |

Layout: header (title + `Refresh` + `Add skill`) + stat strip (`HeaderStat` `SkillsPage.tsx:977`: Total/Enabled/Auto/Blocked) + `Skills Configuration` card (master `enabled` switch + `allow_model_lookup` + `inject_startup_context`, `showFilters` toggle) + two-col workspace (`lg:grid-cols-[360px_1fr]`): left `Catalog` card (search + status segment + sort `Select` + tag `Popover` + count + list), right `Detail` card (empty/select/loading/error `SkillDetailView`).

`SkillMarkdown` (`SkillsPage.tsx:159`) — `ReactMarkdown + remarkGfm`, `prose-invert` with overrides + external `a(target _blank)`, `pre` scroll, table wrapper.

`SkillDetailView` (`SkillsPage.tsx:1030`): state badge + actions popover (`SkillRowActions` `SkillsPage.tsx:997`: Enable/Auto/Block + Delete), sections map + expand-all, metadata (`tags`, `nist_csf`, `mitre_attack`, `references` URLs valid via `isValidUrl`), `CopyButton` for code blocks.

Add skill dialog (`SkillsPage.tsx:811`): `draftName` validated `/^[a-z0-9][a-z0-9-]{1,63}$/`, `draftMarkdown` required, template `SKILL_TEMPLATE` (`SkillsPage.tsx:127`), Write/Preview tabs (mobile + desktop), `previewTab`, `useInstallSkill` (`hooks.ts:379` → `POST /skills`) on success selects new skill. Delete dialog (`SkillsPage.tsx:934`) → `useRemoveSkill` (`hooks.ts:389` → `DELETE /skills/<name>`) + cleanup `default_enabled/exclude_names` refs.

## Goals (`/goals`)

`webui/src/routes/GoalsPage.tsx:81` (`GoalsPage`). `useGoals` (`hooks.ts:336` → `GET /goals` → `{goals:GoalPreset[]}` `types.ts:59` `{name,description,risk:RiskTag,compatible}`; `staleTime Infinity`).

| Feature | Detail |
|---------|--------|
| `RISK_META` (`GoalsPage.tsx:38`) | `safe` `success ShieldCheck` `Standard / safe goal`, `gated` `warn Lock` `Requires standard_authorized…`, `high` `danger ShieldAlert` `Requires high_authorized_testing` |
| Summary | `GoalStats` (`GoalsPage.tsx:211`): tiles Total/Safe/Gated/High/Available (compatible count) |
| Search+filter | `query` (name/desc/risk/label includes), `filter RiskFilter all|safe|gated|high` pill group (`RiskFilterButton` `GoalsPage.tsx:236`), `RiskLegend` (`GoalsPage.tsx:272`) |
| Grid | `GoalCard` (`GoalsPage.tsx:291`): icon tint per risk, `compatible?` else `Unavailable` Badge, desc `line-clamp-3`, footer requirement text + `Use goal` button when compatible → `navigate(/runs/new?path=<recon if safe else attack>&goal=<encode name>)` |
| States | `isLoading → GoalCardGridSkeleton(6)` (`GoalsPage.tsx:395`), error → destructure + Retry, empty → `EmptyGoals` + Clear filters |

Compatible check mirrors wizard's `?goal=` preselect compatibility gate (`RunWizard.tsx:90`).

## Help (`/help`)

`webui/src/routes/HelpPage.tsx:27` (`HelpPage`). Static reference, no hooks. Cards:

| Card | `CardHeader` icon | Content |
|------|-------------------|---------|
| Quick start | `Zap` | 4 ordered steps: Sessions → New run, stream + `DecisionCard`, Recon/Attack/Report tabs, Artifacts/Loot/Graph tabs |
| Permission modes | `ShieldAlert` | 3 `MODES` (`read_only` default mute, `approve` warn, `full_access` danger) + yellow allowlist-notice (`KeyRound`) |
| How a run flows | `Terminal` | 3 `PHASES` Recon/Attack/Report numbered row |
| Documentation | `BookOpen` | 6 `DOC_LINKS` external (`Getting Started`, `Safety Model`, `Attack Modules`, `WebUI`, `Model Providers`, `Troubleshooting` → GitHub `docs/*.md`) + `ExternalLink` |

## Stats (`/stats`)

`webui/src/routes/StatsPage.tsx:218` (`StatsPage`). `useRuns(RUN_LIMIT=200,0)` + `useTelemetry` (`hooks.ts:266` → `GET /system/telemetry` → `TelemetryResponse` `types.ts:720` `{summary:TelemetrySummary, recent:TelemetryRecord[]}`).

Constants: `DAYS=14`, `RECENT_RUN_COUNT=8`, `AXIS_RATIOS=[1,0.75,0.5,0.25,0]`. Helpers `aggregateRunsByDay(days,rows):RunDay` (`StatsPage.tsx:177` completed/failed/other), `aggregateTokensByDay:TokenDay` (`StatsPage.tsx:191` prompt/completion/unattributed), `formatChartDay/fullDay`, `safeNonNegative`, `formatCount/Percent/Rate/Tokens`.

Sections:

| Section | Component | Data |
|---------|-----------|------|
| Overview KPIs | `KpiOverview` (`StatsPage.tsx:386`) | 6 `StatCard` (`StatsPage.tsx:486`): Runs loaded / Success rate / Failed runs / LLM volume / LLM reliability / Throughput. Tones `neutral|success|danger|warning` with `loading/skeleton` + `available` fallback |
| Run analytics (when `rows>0`) | `RunsChart` (`StatsPage.tsx:533` expected segments completed/failed/other) + `StateDistribution` (`StatsPage.tsx:761` bar per `RunState` `STATE_META` colors) on `xl:grid-[1.25fr_0.75fr]`, else `EmptyRunsState` | `runDays` |
| Recent runs | `RecentRuns` (`StatsPage.tsx:941`) | 8 newest rows (sorted `timestampMs`) sorted list with `StatusBadge` + title/target + mode/goal/model + `formatRelative` + `ArrowUpRight` |
| LLM telemetry | `TokenUsageChart` (`StatsPage.tsx:585` prompt/completion/unattributed segments) + `TelemetryOverview` (`StatsPage.tsx:807` 6 `TelemetryMetric` + 2 `ContextMeter` with `Gauge`/`Timer` etc.) on same grid; telemetry empty → `EmptyTelemetryState`, error/loading → skeleton/unavailable | `tokenDays`, `summary` |

Real data only; `DailyStackedBarChart` (`StatsPage.tsx:644`) handles max-axis + hover `Tooltip`(`ChartTooltip` `StatsPage.tsx:729`) + `ChartLegend`.

## Attack Modules (`/modules`)

`webui/src/routes/AttackModulesPage.tsx:29` (`AttackModulesPage`). `useAttackModules` (`hooks.ts:327` → `GET /attack/modules` → `AttackModulesResponse` `types.ts:182` `{modules:AttackModuleSummary[]}`).

`FAMILY_LABELS` map 15 families (`web→Web`, `network_smb→SMB / Network`, etc.). Controls: `query` (searches `name/description/target_services/required_cves` lowercased), `family` select (`all` + derived `families` sorted unique from `modules`).

`FamilyChip` rounded pill (`AttackModulesPage.tsx:95`) + `ModuleRow` card (`AttackModulesPage.tsx:112`): mono `name` + family `Badge outline` + `destructive_ics danger ShieldAlert` + desc + `Services: …` (`Target`) + `Ports:` + `CVEs:` (`BookOpen`). States: `isLoading SkeletonRows(8)`, error, empty "No modules match.", grid `gap-2.5`.

Aligned with `tools/attack_modules/` as backend source (`docs/webui.md`).
