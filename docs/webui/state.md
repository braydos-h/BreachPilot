---
title: State — Hooks, Stores, Event Handling, WS/SSE
sources:
  - webui/src/api/hooks.ts
  - webui/src/api/types.ts
  - webui/src/api/client.ts
  - webui/src/api/ws.ts
  - webui/src/api/sse.ts
  - webui/src/api/eventBuffer.ts
  - webui/src/api/eventStore.ts
  - webui/src/lib/deriveRun.ts
  - webui/src/lib/permissionMode.ts
  - webui/src/lib/useTheme.ts
  - webui/src/components/run-create/RunWizard.tsx
tests:
  - webui/src/lib/stateShape.test.ts
  - webui/src/lib/campaignCheckpoint.test.ts
subsystem: webui
---

# State

## Query layer (`api/hooks.ts:63`, `api/types.ts`, `api/client.ts`)

### `queryKeys`

`hooks.ts:63` central factory:

| key | value | invalidation fans |
|-----|-------|-------------------|
| `capabilities` | `["capabilities"]` | capabilities guard |
| `config/schema/secrets` | `["config"]`, `["config","schema"]`, `["secrets"]` | settings |
| `models / modelsLive / providers` | `["models"]` etc. | `usePatchConfig` (`hooks.ts:152`) invalidates modelsLive/providers only when patch keys contain `models|ollama|chatgpt|provider` |
| `plugins / goals / skills / skillsSearch(q) / skill(name)` | `["skills"...]` | skills page |
| `runs(limit,offset,sort,q,state)` | `["runs",{limit,offset,sort,q,state}]` (`hooks.ts:78`) | `useRuns` 50/200 |
| `run(runId)` | `["runs",runId]` | `patchCaches` on `state` event (`ws.ts:68`) |
| `runDecisions/run(runId,decId)` | `["runs",runId,"decisions"]` | `approval` event + answer mutation |
| `runTools/Artifacts/Audit/Swarm/Campaign/runLog/runCredentials/runLoot/runWorkspace/runGraph/runWitness` | `["runs",runId,...]` | narrow per-panel |

`defaultQueryOptions` (`hooks.ts:107`): `retry:DEFAULT_RETRY` (no retry on 4xx except 408/429; 0 is network `failureCount<3`), `staleTime 15s`, `gcTime 5m`, `meta.onErrorAuthClear`. `QueryClient` in `App.tsx:30` additionally `refetchOnWindowFocus:false`.

### Hooks inventory

| Group | Hook | Endpoint | Notes |
|-------|------|----------|-------|
| System | `useCapabilities` | `GET /capabilities` `60s` | |
| Config | `useConfig` `30s`, `useConfigSchema ∞`, `usePatchConfig PATCH /config` | sets cache directly + conditional model invalidation | |
| Secrets | `useSecrets 30s`, `usePutSecrets PUT /secrets {secrets}` | invalidates `secrets` | |
| Models | `useModels 60s`, `useLiveModels 30s` (swallows 503 payload as data), `useAddModel POST /models`, `useRemoveModel DELETE /models/<alias>`, `useSetModelProvider POST /models/provider` | `providers/modelsLive/models` invalidation |
| Providers | `useProviders 15s`, `useInvalidateProviders`, `useChatgptLogin POST /providers/chatgpt/login`, `useChatgptProxyStart/Stop POST /providers/chatgpt/proxy/{start,stop}` | invalidates providers+modelsLive+models on settle |
| Misc | `useSystemInfo 60s`, `useTelemetry 15s`, `useMemory 15s`, `usePlugins 60s`, `useAttackModules 60s`, `useGoals ∞`, `useSkills 60s` + `useSkillSearch` debounce 250ms + `useSkillDetail` | `useGoals` groups `safe|gated|high` |
| Diagnostics | `useDiagnostics POST /diagnostics/{doctor,self-test}` + `useResetSystem POST /system/reset` invalidates `runs/telemetry/memory` | |
| Runs | `useRuns(limit,offset,sort,q,state)` | adaptive `refetchInterval 5s` if any `isActiveState` else `60s` (`hooks.ts:441`), `keepPreviousData` | |
| Run | `useRun(runId)` | `5s` while `running|queued|cancelling` else false | |
| Create/cancel/resume/delete/retitle | `useCreateRun POST /runs`, `useCancelRun POST /runs/<id>/cancel`, `useResumeRun POST /…/resume`, `useDeleteRun DELETE /…?purge`, `useRetitleRun POST /…/title {title||regen}` | invalidate `["runs"]` + `run(runId)` |
| Decisions | `useDecisions` (5s while pending), `useDecision`, `useAnswerDecision POST /runs/<id>/decisions/<decId> {answer}` invalidates `runDecisions+run+runs` | |
| Artifacts/tool gateway | `useRunTools GET /runs/<id>/tools` `15s` (enabled only while active), `useCallTool POST /…/tools/<name>/calls {arguments}`, `useArtifacts GET /…/artifacts` 30s while active else off (reads run cache), `useAudit`, `useSwarmState` (404 no retry), `useCampaignState`, `useRunLog tail+attempt/target`, `useCredentials` + `useRevealCredential/ConfirmCredential POST /credentials/<i>/{reveal,confirm}`, `useLoot`, `useWorkspace` + `useWorkspaceFileUrl/useFetchWorkspaceFile` raw, `useArtifactUrl/useFetchArtifactBlob` raw, `useRunGraph` (404 no retry), `useWitness` | |
| Graph explorer | re-exported from `features/graph/graphApi.ts` — own `graphKeys` prefix, 10s polling while active | |

All mutating hooks set/ invalidate related queries — see table `onSuccess`.

## Live event transport

### `eventBuffer.ts:4` + `eventStore.ts:19`

| Module | Symbol | Semantics |
|--------|--------|-----------|
| `eventBuffer.ts` | `MAX_EVENTS_PER_RUN=1000`, `appendBounded(prev,batch):AppendResult` | bounded chronological append; `over` calc keeps only tail, `batch>=MAX` slices batch; pure, never mutates `prev` |
| `eventStore.ts` | `EventStore` class, `MAX_RUNS=10` LRU (`Map` reinsert on `get`), `entry:{events,cursor,dropped}` | `get(runId)` re-orders LRU; `set(runId,events,cursor)` trims via `appendBounded([])`; `append(runId,event)` dedupes `sequence<=cursor`, `appendBounded` + `dropped+=over`; `clear(evict beyond MAX_RUNS)`; singleton `eventStore` exported |

### `sse.ts:1` — fetch-backed SSE

Native `EventSource` cannot send `Authorization`; token was leaking in URL (`?token=`). This module streams over `fetch`.

| Symbol | Detail |
|--------|--------|
| `SseParser` (`sse.ts:76`) | incremental lineBuffer parser: `push(chunk)` splits on `\n`, `processLine` handles `:` comments, `field: value` strip leading space, cases `data→push`, `event→set`, `id→set if !\0`, `retry→int`, blank line → `dispatch` joining `data` with `\n` |
| `streamSSE(options:StreamSseOptions)` (`sse.ts:155`) | `url: string|()=>string` (cursor factory), `token→ Authorization: Bearer`, `signal:AbortSignal`, callbacks `onEvent/onOpen/onStatus/onFatal`, `maxRetries`, returns `SseHandle{close,restart}`. States `connecting|open|reconnecting|closed`. On `fetch` status 401/403→ fatal `authError`, other `!ok` fatal; missing `body` fatal. Reader loop: `getReader()` + `TextDecoder stream:true` + `parser.push` per chunk; flush decoder+parser on done; on server close emits `reconnecting` + `scheduleReconnect` with `backoffMs = min(10000,1000*2**attempt)` (`sse.ts:66`). Abort never fatal. Token never logged/exposed |
| `isAbortError` (`sse.ts:288`) | `DOMException name AbortError` guard |

### `ws.ts:36` — primary transport

`useRunEvents(runId, {after,enabled})` (`ws.ts:36`) returns `{events,status,authError,transport,reconnect,lastSeq,dropped}`.

| Concern | Detail |
|---------|--------|
| Refs state | `lastSeqRef`, `eventsRef` (mirror for pure append), `droppedRef`, `wsRef`, `sseHandleRef/sseAbortRef`, `attemptRef`, `reconnectTimer`, `closedByUnmount`, `wsFailureCount`, `runIdRef`, `pendingRef`, `rafRef` |
| Seed | `seedEvents(id, cancelled)` (`ws.ts:202`): `GET /runs/<id>/events?tail=MAX` (`EventReplayResponse` `types.ts:664` includes `events,latest_sequence,total_lines_in_file,has_more_before`) → `eventStore.set(id,seeded,latest, older=has_more_before?oldest-1:0)` + local `setEvents/setDropped` |
| WS | `connectWs(id)` (`ws.ts:231`): `ws(s)://<host>/api/v1/ws/v1/runs/<id>` (`scheme` from `location.protocol`), `send {auth:token, after:lastSeq}` on open, `onmessage→JSON RunEvent→handleEvent`, `onclose` handles `WS_CLOSE_*`: `4401 auth clear+error, 4403 origin, 4404 not found, 4400 invalid cursor→ resetSeq0+clear+seed`, else `wsFailureCount++ → if >=SSE_FALLBACK_THRESHOLD=3 → connectSse` else `setTimeout(backoffMs(attempt), connectWs)` |
| SSE fallback | `connectSse(id)` (`ws.ts:158`): `streamSSE({url:()=>origin/api/v1/runs/<id>/events/stream?after=<lastSeq>, token, signal, onEvent:JSON.parse(data), onStatus, onFatal:auth→clear})`, `setTransport("sse")` |
| Event handling | `handleEvent(event)` (`ws.ts:114`): drop `heartbeat` (only bump `lastSeq`), dedupe `sequence<=lastSeq`, `eventStore.append`, `patchCaches`, then batch: `IMMEDIATE_EVENT_TYPES = Set(state,approval,error,title)` → flush immediate (cancel raf, `appendBounded([...pending,event])`); others → `pendingRef.push` + `requestAnimationFrame(flushPending)` → `appendBounded(eventsRef, batch)` + `dropped` |
| Cache patching | `patchCaches(event)` (`ws.ts:62`): on `state` → `setQueryData run(runId) {state,result?}`, invalidate `["runs"]`; on `approval` → invalidate `runDecisions`; on `artifact` → invalidate `runArtifacts` + `["graphExplorer",id]` |
| Effect | `useEffect([runId,enabled])` (`ws.ts:331`): if cached `eventStore.get(runId)` reuse cursor/events else seed then connect; cleanup `closedByUnmount=true`, clear raf/reconnect/sse/ws |
| Types | `WsStatus idle|connecting|open|reconnecting|closed|error` (`ws.ts:10`), `MAX_BACKOFF 10000`, `backoffMs` exp |

### Telemetry derivation (`lib/deriveRun.ts:122`)

`deriveRunState(events):DerivedRun` — single O(n) scan producing everything header/Now/telemetry/phase need. Tracks `phase` via `phase|progress` events, `PHASES` map + `PHASE_ORDER` (`lib/deriveRun.ts:14`), `requestByAction/runningByAction` across `tool_request→tool_start→tool_result` to compute `currentTool/lastTool` + `toolErrors`, `bootSteps Map` from `boot|ok`, `lastTelemetry/telemetrySeries` (cap 200) from `progress.payload.telemetry:RunResultTelemetry`, `eventsPerMin` from first/last timestamps. Returns `phase,phaseIndex,lastReachedIndex,round,actions,elapsedSeconds,source,lastAssistant, currentTool/lastTool/toolCount/toolErrors, bootDone/bootTotal/bootFailed, artifacts,errorEvents, tokens,lastTelemetry,telemetrySeries, eventsPerMin,lastMeaningfulAt,lastEventType`.

## Client-only state

| Store | Key | API | Used in |
|-------|-----|-----|---------|
| API token | `sessionStorage netattackai.apiToken.v1` (`api/client.ts:6`) | `getStoredToken/setStoredToken/clearStoredToken`, injected `Authorization: Bearer` | `TokenGate`, `ws.ts`, `sse.ts`, `Layout signOut` |
| Onboarding dismissed | `sessionStorage netattackai.onboarding.v1` | `OnboardingGate` | |
| Welcome tour open | event `netattackai:open-welcome` + `sessionStorage` dismiss flag (`components/WelcomeScreen.tsx`) | `HomePage Take the tour`, `App WelcomeGate` | |
| Theme | `localStorage netattack.theme` + `lib/useTheme.ts` | `toggle` `dark↔light`, script in `index.html` removes `dark` on `light` | `Layout` (`Layout.tsx:59`) |
| Permission mode | `localStorage permissionMode` (`lib/permissionMode.ts`) | `read_only|approve|full_access`, `autoAnswerFor` returns `answer|null`, `RunPage` auto-answers pending decisions with `useAnswerDecision` + `inFlight Set` dedup | |
| Run sort | `localStorage netattack.runSort` | `RunListPage.tsx:54` | |
| Graph explorer | `AttackGraphPage.tsx:38` React local state (filters, selection, expansions) — no store | | |

## Decision + checkpoint wiring

`campaignCheckpoint.ts:25` helpers: `checkpointVisual(kind→borderClass/badgeClass)`, `detectCheckpointKind(promptText first line VERIFIED ACCESS vs NO VERIFIED ACCESS → access|no_path)`, `parseCheckpointOptions(options→CampaignNextStepOption[])`, `encodeCheckpointAnswer(option,goalName?,customText?)` → sent as `POST /decisions/<id> {answer}` per `docs/api.md: CAMPAIGN_NEXT_STEP` spec.

`DecisionCard.tsx` renders all `DecisionKind` (`start_confirm|goal_select|tool_approval|campaign_next_step`) via `CampaignCheckpointKind` branching, with `DecisionKind` shape `DecisionsListRow options_json/options` merged from WS `approval` payloads.
