---
title: API Integration — Endpoint Mapping & Types
sources:
  - webui/src/api/client.ts
  - webui/src/api/types.ts
  - webui/src/api/hooks.ts
  - webui/src/api/ws.ts
  - webui/src/api/sse.ts
  - webui/src/features/graph/graphApi.ts
  - webui/src/features/graph/graphTypes.ts
  - docs/api.md
tests: []
subsystem: webui
---

# API Integration

SPA targets same `/api/v1` REST + WebSocket as `docs/api.md`. Base `http://127.0.0.1:8765`, dev `vite.config.ts:22` `/api` proxy (`VITE_API_URL` override). All routes except `GET /health` require `Authorization: Bearer` (`api/client.ts:75`).

## Client core (`api/client.ts:69`)

| Symbol | Detail |
|--------|--------|
| `get/set/clearStoredToken` | `sessionStorage netattackai.apiToken.v1`, defensive try/catch, `removeItem` when empty |
| `ApiError extends Error` (`client.ts:29`) | `{status,code,details,requestId,raw}` + `isAuth(401)` `isNotFound(404)` `isConflict(409)` |
| `apiFetch<T>(path, {method,body,signal,headers,raw})` | injects `Accept: application/json` + bearer + `Content-Type` on writes; prefixes `/api/v1` unless `http` or `/api/`; 204→undefined; `fetch` throws → `ApiError status0 network`; else read `content-type` + `json/text`; on `!ok` → `normalizeError`, on `raw` blob mode returns `Blob`; `normalizeError(status,body)` (`client.ts:125`): if `body.error`→ from envelope, if `body.detail`→ `http_error`, else `responseStatusText(map 400/401/403/404/409/422/500/502/503/504)` |

Prefix constant `API_PREFIX="/api/v1"` (`client.ts:67`).

## Types (`api/types.ts:879`)

| Export | Shape |
|--------|-------|
| `RunState` | `draft|awaiting_confirmation|queued|running|awaiting_input|completed|failed|cancelled|interrupted|cancelling` |
| `DecisionKind/Status/RiskTag/RunMode/RunKind/SkillsMode/ObserverMode` | `"start_confirm"|"goal_select"|"tool_approval"|"campaign_next_step"` etc. |
| `CampaignCheckpointKind` `access|no_path` + `CampaignNextStepOption {action,label,goals?:{name,desc}[]}` | mid-run checkpoint |
| `Capabilities` | `{api_version, features[], constraints{max_concurrent_runs,loopback_only,manual_tool_calls}, run_options{modes,kinds,flags}}` |
| `GoalPreset {name,description,risk,compatible}` + `SuggestedGoal` + `ReconAssessment {target_ip,os_verdict,open_ports,services,cve_findings,overall_risk_score}` + `ModelInfo/ChatgptModelsBlock/ModelRegistryInfo/LiveModelsResponse/ChatgptProviderStatus/ProvidersResponse/ChatgptLoginResponse/ChatgptProxyResponse` + `SkillSummary/Detail/SearchResult/AttackModuleSummary/PluginSummary/SecretsStatus/SecretWriteResult/ConfigSchema` | |
| `RunCreateRequest {target,mode,goal,custom_goal,recon_first,model,swarm,parallel_swarm,critic,reflection,adaptive_exploits,long_session,multi_model_consult,observer_mode,ultrathink,skills,skills_include/exclude,resume,kind,yes}` | `POST /runs` body |
| `RunPreview {run_id,target_ip,original_target,resolved_*,mode,goal_name/model_alias/transport_summary/permission/attack_mode/destructive/required_confirmation_text/budgets/swarm/…}` + `CreateRunResponse {run_id,preview,state,decision?}` + `RunListRow/Response` + `RUN_SORT_OPTIONS` + `RunDetail {id,state,created_at,updated_at,request:RunDetailRequest,preview,result:RunResult,error,title,cancelled_at,decisions:DecisionListRow[]}` + `RunResult {run_id,target_ip,mode,goal_name,total_actions,workspace,audit_path,outcome_summary,telemetry:RunResultTelemetry,active_skills,safety_review,swarm_result,…}` | |
| `DecisionListRow/DecisionOut/DecisionAnswerResponse` + `ArtifactSummary/Response` + `ChainEntry/ExploitationChain/CVSSScore/TechnicalFinding/EnhancedReport` (`exploitation_chains+technical_findings` for `AttackGraph`) + `AuditResponse/SwarmState/CampaignState/LogResponse/CredentialRecord/LootItem/ToolSchema/ToolsResponse/DeleteRunResponse` | |
| `EventType` | `state|boot|ok|progress|phase|recon_assessment|goal_suggestions|assistant|tool_request|tool_start|tool_result|approval|swarm|artifact|completion|error|title|heartbeat|fast_recon_*|ai_takeover_started` |
| `RunEvent {sequence,timestamp,run_id,type,payload}` + `EventReplayResponse {run_id,events,oldest/latest_sequence,has_more_before}` | events replay |
| `TelemetrySummary/Record/Response`, `MemoryLesson/Confidence/AttackMemoryItem/MemoryResponse`, `WorkspaceFile/Response`, `ConfigPatchResponse/ConfigValidationErrorResponse/ApiErrorEnvelope/Shape`, `ACTIVE_RUN_STATES/TERMINAL_RUN_STATES`, `isActiveState/isTerminalState/stateCategory`, `GraphNode/Edge/RunGraphResponse`, `WitnessFlag/Response` | |

## Hook → endpoint map (`api/hooks.ts:63` + `docs/api.md`)

| Hook | Method | URL pattern | Docs ref |
|------|--------|-------------|----------|
| `useCapabilities` | `GET` | `/capabilities` | `docs/api.md: GET /capabilities` |
| `useConfig / useConfigSchema / usePatchConfig` | `GET/PATCH` | `/config`, `/config/schema`, `PATCH /config` body patch merged | `PATCH /config` atomic + `allowed_origins` loopback validate |
| `useSecrets / usePutSecrets` | `GET / PUT` | `/secrets`, `PUT /secrets {secrets}` write-only, redacted | `GET /secrets` vs `PUT /secrets` |
| `useModels / useLiveModels / useAddModel / useRemoveModel / useSetModelProvider` | `GET/POST/DELETE` | `/models`, `/models/live` (503 payload swallowed), `/models` `POST {alias,model}`, `DELETE /models/<alias>`, `POST /models/provider {provider}` | `GET /models`, `/models/live` branches ollama/chatgpt |
| `useProviders` (+ chatgpt login/proxy) | `GET/POST` | `/providers`, `POST /providers/chatgpt/login`, `POST /providers/chatgpt/proxy/{start,stop}` | `docs/api.md: GET/POST /providers/*` |
| `useSystemInfo / useTelemetry / useMemory` | `GET` | `/system/info`, `/system/telemetry`, `/system/memory` | System routes |
| `usePlugins / useAttackModules / useGoals` | `GET` | `/plugins`, `/attack/modules`, `/goals` | `GET /plugins` def `[]` on error; goals `stale Infinity` |
| `useSkills / useSkillSearch / useSkillDetail / useInstallSkill / useRemoveSkill` | `GET/POST/DELETE` | `/skills`, `/skills/search?q`, `/skills/<name>`, `POST /skills {name,markdown}`, `DELETE /skills/<name>` | |
| `useDiagnostics / useResetSystem` | `POST` | `/diagnostics/{doctor,self-test}`, `POST /system/reset` invalidates `runs/telemetry/memory` | |
| `useRuns` | `GET` | `/runs?limit&offset&sort&q&state` `limit 1-200` | `docs/api.md: GET /runs` |
| `useRun / useCreateRun / useCancelRun / useResumeRun / useDeleteRun / useRetitleRun` | `GET/POST/DELETE` | `/runs/<id>`, `POST /runs` body `RunCreateRequest`, `POST /runs/<id>/{cancel,resume,title}` `title POST {title regen}` | `docs/api.md: POST /runs`, `POST /runs/*` |
| `useDecisions / useDecision / useAnswerDecision` | `GET/POST` | `/runs/<id>/decisions`, `POST /runs/<id>/decisions/<decId> {answer}` invalidates `runDecisions+run+runs` | `docs/api.md: Decision Routes` |
| `useRunTools` / `useCallTool` | `GET / POST` | `/runs/<id>/tools`, `POST /runs/<id>/tools/<name>/calls {arguments}` policy-gated via `tool_lock`, `403 tool_denied` | `docs/api.md: GET /runs/<id>/tools`, `POST …/tools/<name>/calls` |
| `useArtifacts / useAudit / useSwarmState / useCampaignState / useRunLog` | `GET` | `/runs/<id>/artifacts` `30s while active`, `/audit`, `/swarm` & `/campaign` 404 no retry, `/logs/<name>?tail&attempt_id&target_ip` | `docs/api.md: Artifacts/Audit/Logs` |
| `useCredentials / useRevealCredential / useConfirmCredential / useLoot` | `GET/POST` | `/runs/<id>/credentials`, `POST /credentials/<i>/reveal`, `POST …/confirm`, `GET /…/loot` | cred masked |
| `useWorkspace / useWorkspaceFileUrl / useFetchWorkspaceFile` | `GET` raw | `/runs/<id>/workspace`, `/workspace/<path>` `raw:true Blob` | |
| `useArtifactUrl / useFetchArtifactBlob` | raw | `/runs/<id>/artifacts/<name>` `raw Blob` | download |
| `useRunGraph / useWitness` | `GET` 404 no retry | `/runs/<id>/graph`, `/witness` | `docs/api.md: Graph Explorer Routes` when gated |
| Graph explorer (`graphApi.ts`) | `GET` | `/graph/runs/<id>`, `/…/summary`, `/…/conflicts`, `/…/nodes/<nid>`, `/…/nodes/<nid>/neighbors?max_hops&max_nodes`, `/…/paths?start&end&max_length&max_paths` | `docs/api.md: Graph Explorer Routes` bounds `limit≤500` caps |

## Real-time transport

| Transport | URL pattern (from `ws.ts:239`, `sse.ts:195`) | Auth | Route |
|-----------|----------------------------------------------|------|-------|
| WebSocket (primary) | `ws(s)://<host>/api/v1/ws/v1/runs/<runId>` then send `{auth:token, after:N}` | first message `auth` + `hmac.compare_digest` | `docs/api.md: WS /ws/v1/runs/<runId>` heartbeats every 30s |
| SSE fallback (after 3 WS failures) | `<origin>/api/v1/runs/<runId>/events/stream?after=<seq>` + `Authorization: Bearer` header (`sse.ts:200`) | header bearer | `GET /runs/<id>/events/stream` (SSE) |
| Replay | `GET /runs/<id>/events?tail=MAX` | bearer | `docs/api.md: GET /runs/<id>/events?after` |

Close codes handled in `ws.ts:275`: `4400 invalid cursor`, `4401 auth`, `4403 origin`, `4404 run not found`, `1011 server not configured`. SSE status `401/403` → fatal `authError`. Reconnect backoff `min(10000, 1000*2**attempt)` + on attempts both layers.

## `defaultQueryOptions` (`hooks.ts:107`) polling

`useRuns` adaptive 5s active vs 60s idle; `useRun` 5s while `running|queued|cancelling`; `useDecisions` 5s while pending; `useArtifacts` 30s while active reading `qc.getQueryData(run)`.

## Deserialization notes

- `useLiveModels` catches `ApiError status 503 && raw` and returns `raw as LiveModelsResponse` instead of throwing so UI can show daemon error payload (`hooks.ts:205`) with `LiveModelsResponse.source ∈ {ollama,registry,chatgpt}`.
- `Graph` explorer 404 (disabled route or no graph) disables retry (`ApiError.isNotFound` guard).
- `Swarm/Campaign` 404 similarly gated as optional artifacts.
- `apiFetch` `raw:true` path returns `Blob` for workspace/artifact download; non-JSON non-raw returns `text` (`client.ts:121`).

## Where consumers use it

| Frontend | Consumes |
|----------|----------|
| `TokenGate` | `useCapabilities` verify token |
| `OnboardingGate` | `useSecrets` keys status |
| `ProviderSettings` | `useModels/useLiveModels/useProviders` + chatgpt login/proxy mutations |
| `RunWizard` | `useCapabilities` flags + `useGoals/useSkills/useDefaultModel` + `useCreateRun` |
| `RunPage` | `useRun/useDecisions/useRunEvents/useArtifacts/useAudit/useSwarmState/useCampaignState/useWitness/useRunTools/useCallTool/useFetchArtifactBlob/useCapabilities/useConfig` |
| `AttackGraphPage` | `features/graph/graphApi` explorer hooks (not `api/hooks` graph) |
| `RunListPage` | `useRuns` (50), `useDeleteRun/useResumeRun/useRetitleRun/useCapabilities` |
| `StatsPage` | `useRuns(200)+useTelemetry` aggregations |
| `MemoryPage` | `useMemory` |
| `LootPage` | `useLoot` + `CredentialTable` → `useCredentials/useRevealCredential` |
| `ArtifactsPage` | `useArtifacts/useWorkspace/useAudit/useRunLog` |
| `SkillsPage` | `useSkills/useSkillSearch/useSkillDetail/useConfig/usePatchConfig/useInstallSkill/useRemoveSkill` |
| `GoalsPage/AttackModulesPage` | `useGoals/useAttackModules` |
