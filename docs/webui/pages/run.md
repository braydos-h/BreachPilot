---
title: Run Pages — Run List, New Run, Live Run
sources:
  - webui/src/routes/RunListPage.tsx
  - webui/src/routes/RunPage.tsx
  - webui/src/routes/NewRunPage.tsx
  - webui/src/components/run-create/RunWizard.tsx
  - webui/src/components/run/*.tsx
  - webui/src/api/hooks.ts
  - webui/src/api/types.ts
  - webui/src/lib/deriveRun.ts
  - webui/src/lib/permissionMode.ts
tests:
  - webui/src/components/run-create/RunWizard.test.tsx
subsystem: webui
---

# Run Pages

## Run List (`/sessions`)

`webui/src/routes/RunListPage.tsx:64` (`RunListPage`, lazy via `App.tsx:16`).

### Controls

| Control | State | Backend mapping |
|---------|-------|----------------|
| Search input | `q` → debounced 300ms (`RunListPage.tsx:84`) → `debouncedQ` | `GET /runs?limit&offset&sort&q&state` (`api/hooks.ts:432`, `queryKeys.runs`) |
| State filter | `stateFilter` (`RunListPage.tsx:68`) | `&state=<RunState>` (draft..cancelling etc., `api/types.ts:1`) |
| Sort select | `sortKey` persisted `localStorage breachpilot.runSort` (`RunListPage.tsx:54`) → `RUN_SORT_OPTIONS` (`api/types.ts:345`) | `&sort=created_desc|created_asc|title_{asc,desc}|state_{asc,desc}` |
| Pagination | `page` × `PAGE_SIZE=50` (`RunListPage.tsx:38`) | `offset, limit` |

`useRuns(PAGE_SIZE, page*PAGE_SIZE, sortKey, debouncedQ, stateFilter)` (`RunListPage.tsx:70`) adaptive poll `5s` active else `60s` (`hooks.ts:441`). `maxConcurrent` from `capabilities.constraints.max_concurrent_runs` gates `New run` button (`RunListPage.tsx:72`).

### Active banner

When `activeRuns.length>0` (`RunListPage.tsx:180`): `Card border-yellow-500/40` + `Badge Active (n)` + cap hint (`maxConcurrent>1`) + per-run `Open` links.

### Table

Columns: `ID | Title | State | Target | Mode | Goal | Model | Created | Actions`. Row data `RunListRow` (`api/types.ts:319`: `id, state, created_at, target, mode, goal_name, target_ip, model_alias, title?`). `truncateId` + `CopyButton` for ID, `StatusBadge` for state, `formatRelative` for created.

Actions per row (`RunListPage.tsx:266`):

| Action | Hook | Enabled | Note |
|--------|------|---------|------|
| Open | `Link /runs/<id>` | always | `ghost` |
| Regen title | `useRetitleRun` (`hooks.ts:517`) → `POST /runs/<id>/title {regen:true}` | always | `Sparkles`, `retitling===id` spinner |
| Resume | `useResumeRun` (`hooks.ts:492`) → `POST /runs/<id>/resume` | `isTerminalState` only | `RotateCw`, navigates to new id |
| Delete | `useDeleteRun` (`hooks.ts:503`) → `DELETE /runs/<id>?purge=true` | `!isActiveState` | `Trash2`, confirm `Dialog` (`RunListPage.tsx:330`) |

Pagination footer (`RunListPage.tsx:312`) when `total>PAGE_SIZE`: `total / totalPages` + Prev/Next.

## New Run (`/runs/new`)

`webui/src/routes/NewRunPage.tsx` — thin wrapper `→ <RunWizard onCreated>` that navigates to `/runs/<id>` with `state.justCreated`.

See `docs/webui/components/run-create.md` for wizard internals. Create flow: `RunWizard.tsx:170` `createTheRun()` → `useCreateRun` (`hooks.ts:467`) → `POST /runs` (`RunCreateRequest` `types.ts:249`). If response `state queued|running` (e.g. `yes:true`) → immediate navigate; else stays on `review` step to answer `start_confirm`.

## Live Run (`/runs/:runId`)

`webui/src/routes/RunPage.tsx:75` (`RunPage`). Central surface for execution + decisions + telemetry + artifacts.

### Hooks

| Hook | Call | Interval / Gate |
|------|------|-----------------|
| `useRun(runId)` | `RunPage.tsx:79` | 5s while `running/queued/cancelling` (`hooks.ts:456`) |
| `useDecisions(runId)` | `RunPage.tsx:80` | 5s while pending (`hooks.ts:542`) |
| `useRunEvents(runId)` | `RunPage.tsx:81` | WS/SSE live stream (see `docs/webui/state.md`) |
| `useArtifacts(runId)` | `RunPage.tsx:93` | 30s while active (`hooks.ts:610`) |
| `useAudit(runId, tab==="audit")` | `RunPage.tsx:84` | `GET /runs/<id>/audit` |
| `useSwarmState(..., tab==="swarm")` | `RunPage.tsx:86` | 3s while active |
| `useCampaignState(..., tab==="campaign")` | `RunPage.tsx:87` | 3s while active |
| `useWitness(..., is swarm && capabilities has witness)` | `RunPage.tsx:88` | advisory flags |
| `useRunTools(..., tab in tools|advisory && active)` | `RunPage.tsx:90` | `GET /runs/<id>/tools` only meaningful while active |
| `useCapabilities / useConfig` | `RunPage.tsx:85,89` | capabilities guard advisory tools |
| `useCancelRun / useResumeRun / useCallTool / useFetchArtifactBlob` | mutations | `POST /cancel`, `/resume`, `/tools/<name>/calls`, `GET /artifacts/<name>` (raw blob) |

Artifact readiness gate (`RunPage.tsx:98`): `artifactReady(name)= !isActiveState || artifactNames.has(name)` — avoids 404-loop while recon still in progress.

### Merged state

- `mergedDecisions` (`RunPage.tsx:111`): dedup REST `decisions` + WS `approval` events by `decision_id`. WS `answer` overrides REST when reconciling.
- `currentState` (`RunPage.tsx:151`): last `state` event payload else `run.state`.
- `derived` (`RunPage.tsx:159`): single-pass `deriveRunState(events)` (`lib/deriveRun.ts:122`) — `phase`, `round`, `actions`, `elapsedSeconds`, `currentTool/lastTool`, `telemetry`, `eventsPerMin`, etc.
- `telemetry` (`RunPage.tsx:160`): `derived.lastTelemetry ?? run.result.telemetry`.
- Permission auto-answer (`RunPage.tsx:169`): `usePermissionMode().mode !== "read_only"` → `autoAnswerFor(d,mode)` + `useAnswerDecision` (`hooks.ts:563`) with `inFlight` dedup ref. `autoAnsweringIds` marks cards as "auto-answering…".
- `transportLabel` (`RunPage.tsx:196`): `SSE|WS|reconnecting|offline|connecting|error|—`.

### Layout

```
<RunCommandHeader>  — target hero + state/phase/connection + meta + Cancel/Resume/Artifacts/Loot
<RunAttentionBanner> — authError / pending banner / status
<PhaseTracker>       — derived.phase stepper
[fast mode → <FastReconProgress>]
┌──────────────┬─────────────────┐
│ PendingDecisionPanel (top)     │  Rail
│ RunOutcomeCard / RunNowCard    │  <RunTelemetryCard>
│ EventViewer (1.35 flex)        │  <LiveRunSummary>
│ Tabs (recon/graph/summary/     │  <DecisionHistoryCard>
│       tools/advisory/audit/    │
│       swarm/campaign)          │
└──────────────┴─────────────────┘
<Cancel Dialog>
```

#### Header (`components/run/RunCommandHeader.tsx:33`)

`target = preview.original_target ?? request.target ?? preview.target_ip`, `resolvedIp` when differs. `phaseInfo(derived.phase)` (`lib/deriveRun.ts:36`). `ConnectionBadge` maps `WsStatus` to `● Live / ○ Connecting / ◌ Reconnecting / ● Offline / ⚠ Error` + transport suffix. Actions: `Cancel` (active), `Resume` (terminal), `Artifacts`, `Loot` links. Meta row: `truncateId(run.id,12,4)+CopyButton`, `mode/goal/model/permission`, `formatRelative(created_at)`, `fmtElapsed(elapsedSeconds)`.

#### Cards

| Component | File | Shown when | Content |
|-----------|------|------------|---------|
| `RunNowCard` | `components/run/RunNowCard.tsx` | `!terminal` | current tool + elapsed + phase from `derived` |
| `RunOutcomeCard` | `components/run/RunOutcomeCard.tsx` | `terminal` | outcome summary + summary/Resume CTA |
| `RunTelemetryCard` | `components/run/RunTelemetryCard.tsx` | always (rail) | tokens/calls/ctx% + `Sparkline` (`components/run/Sparkline.tsx`) from `telemetry` + `derived.telemetrySeries` |
| `RunAttentionBanner` | `components/run/RunAttentionBanner.tsx` | error/pending/active mismatch | authError + pending count + reconnect hint |
| `PendingDecisionPanel` | `components/run/PendingDecisionPanel.tsx` | `pendingDecisions>0` | one `DecisionCard` per pending (`start_confirm|goal_select|tool_approval|campaign_next_step`) via `useAnswerDecision` |
| `DecisionHistoryCard` | `RunPage.tsx:884` | rail bottom | collapsible answered history (prompt/options/required_text/timestamps) |

#### EventViewer

`components/events/EventViewer.tsx` — renders `events.events` (deduped by `sequence`, capped `MAX_EVENTS_PER_RUN=1000`). Correlation of `tool_request → tool_start → tool_result` by `action/correlation_id` into `ToolCallCard` (`components/ToolCallCard.tsx`). `boot|ok` → `BootChecklist`, `recon_assessment` → `ReconAssessmentCard`, `goal_suggestions` → `GoalSuggestionCard`, `state/progress/assistant/swarm/artifact/completion/error/heartbeat` inline. Sticky-to-bottom + "jump to latest", `dropped` banner.

#### Tabs (`RunPage.tsx:321`)

| Tab | Gate | Component / Hook |
|-----|------|-------------------|
| Recon | always | `ReconTab` → `fetchArtifact.mutate("recon_assessment.json")` gated on `artifactReady`; renders `ReconAssessmentCard` |
| Attack Path | always | `AttackGraphDag` + `AttackGraph` + `Open in full page → /runs/<id>/graph` |
| Summary | always | `SessionSummaryCard` (`components/SessionSummaryCard.tsx`) from `run.result` |
| Tools | always | `ManualToolPanel` (`RunPage.tsx:459`): live `tools` schemas, JSON textarea, `POST /tools/<name>/calls` via `useCallTool`, result `<pre>` + `CopyButton` |
| Advisory | always | `AdvisoryPanel` (`RunPage.tsx:708`): 5 advisory tools (`verify_poc`, `replay_simulate`, `peer_review_outcome`, `export_attack_navigator`, `search_threat_intel`) filtered by `capabilities.features`; per-tool result renderers (`PocVerifyResult` etc.) |
| Audit | always | `AuditView` (`RunPage.tsx:572`): `chain_valid` banner + `AuditRecordsTable` |
| Swarm | `request.swarm` | `SwarmView` (`components/OrchestrationViews.tsx`) + witness flags |
| Campaign | `request.long_session` | `CampaignView` (`components/OrchestrationViews.tsx`) |

#### Dialogs

Cancel confirm (`RunPage.tsx:432`): explains cooperative cancellation (`api/docs: Cancel`). `cancel.mutate` → `POST /runs/<id>/cancel`, waits `api.shutdown_timeout_seconds`.
