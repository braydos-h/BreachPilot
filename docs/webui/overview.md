---
title: WebUI Overview — Bootstrap, Build, Routing, Auth, State
sources:
  - webui/src/main.tsx
  - webui/src/App.tsx
  - webui/index.html
  - webui/src/index.css
  - webui/vite.config.ts
  - webui/tsconfig.app.json
  - webui/tsconfig.json
  - webui/tailwind.config.ts
  - webui/src/components/Layout.tsx
  - webui/src/components/TokenGate.tsx
  - webui/src/components/OnboardingGate.tsx
  - docs/webui.md
  - docs/api.md
tests:
  - webui/src/features/settings/SettingsPage.test.tsx
  - webui/src/components/run-create/RunWizard.test.tsx
  - webui/src/lib/campaignCheckpoint.test.ts
subsystem: webui
---

# WebUI Overview

Vite + React 18 + TypeScript SPA under `webui/src/`. Loopback-only; all authority is server-side (`AssessmentService` / `ExploitPolicy`).

## Bootstrap

| Layer | File | Detail |
|-------|------|--------|
| HTML entry | `webui/index.html:2` | `<html class="dark">`, theme toggle script (`netattack.theme`), `#root` mount |
| React root | `webui/src/main.tsx:8` | `ReactDOM.createRoot` → `<ErrorBoundary>` → `<App />` |
| CSS | `webui/src/index.css:1` | Tailwind base/components/utilities, HSL CSS vars (`:root`/`.dark`), custom utilities (`bg-grid`, `glow-primary`, `animate-scan`, etc.) |
| Version inject | `webui/vite.config.ts:13` | `define.__APP_VERSION__` from `package.json:version` (`0.49.12`) |

`index.css` defines light `:root` + dark `.dark` HSL vars (`--background`, `--primary`, etc.). Default is dark via `index.html`.

## Build & Toolchain

| Concern | Config | Value |
|---------|--------|-------|
| Dev server | `webui/vite.config.ts:22` | `port 5173`, `strictPort:true`, `/api` proxy → `VITE_API_URL` or `http://127.0.0.1:8765` (`ws:true`, `secure:false`) |
| Preview | `vite.config.ts:32` | same proxy as dev |
| Build | `vite.config.ts:44` | `outDir: dist`, `sourcemap:false`, `target: es2020` |
| Alias | `vite.config.ts:18`, `tsconfig.app.json:19` | `@/*` → `src/*` |
| Plugins | `vite.config.ts:16` | `@vitejs/plugin-react` only |
| TS target | `tsconfig.app.json:2` | `ES2021`, `lib:[ES2023, DOM, DOM.Iterable]`, `strict`, `noUnusedLocals/Parameters`, `noFallthroughCasesInSwitch` |
| Tailwind | `tailwind.config.ts:5` | `darkMode:["class"]`, content `index.html + src/**/*.{ts,tsx}`, plugins `typography`+`animate`, HSL-var colors, `typography.invert` overrides |

See `docs/webui/build.md` for full build write-up.

## Routing

Defined in `webui/src/App.tsx:59`:

| Path | Component | Loader |
|------|-----------|--------|
| `/` | `HomePage` (eager) | `webui/src/routes/HomePage.tsx:62` |
| `/sessions` | `RunListPage` (lazy) | `webui/src/routes/RunListPage.tsx:64` |
| `/runs/new` | `NewRunPage` → `<RunWizard>` | `webui/src/routes/NewRunPage.tsx` + `src/components/run-create/RunWizard.tsx:34` |
| `/runs/:runId` | `RunPage` (lazy) | `webui/src/routes/RunPage.tsx:75` |
| `/runs/:runId/artifacts` | `ArtifactsPage` | `webui/src/routes/ArtifactsPage.tsx:23` |
| `/runs/:runId/loot` | `LootPage` | `webui/src/routes/LootPage.tsx:12` |
| `/runs/:runId/graph` | `GraphPage` | `webui/src/routes/GraphPage.tsx:11` |
| `/skills` | `SkillsPage` | `webui/src/routes/SkillsPage.tsx:223` |
| `/modules` | `AttackModulesPage` | `webui/src/routes/AttackModulesPage.tsx:29` |
| `/goals` | `GoalsPage` | `webui/src/routes/GoalsPage.tsx:81` |
| `/graph` | `AttackGraphPage` | `webui/src/features/graph/AttackGraphPage.tsx:37` |
| `/stats` | `StatsPage` | `webui/src/routes/StatsPage.tsx:218` |
| `/connections` | `ConnectionsPage` | `webui/src/routes/ConnectionsPage.tsx:9` |
| `/help` | `HelpPage` | `webui/src/routes/HelpPage.tsx:27` |
| `/memory` | `MemoryPage` | `webui/src/routes/MemoryPage.tsx:9` |
| `/system` | `SystemPage` → `SettingsPage` | `webui/src/routes/SystemPage.tsx:6`, `webui/src/features/settings/SettingsPage.tsx:20` |
| `*` | `→ /` | `App.tsx:76` |

All routes are nested under `<Layout>` (`src/components/Layout.tsx:50`) which provides sidebar/mobile nav + active-run pill + permission banner + footer. `Suspense` fallback is `Spinner` (`App.tsx:52`).

### SPA Serving

`python main.py --web` builds `webui/dist/` if missing, sets `api.serve_webui:true` in-memory, mounts `dist/` at `/` with deep-link fallback. Dev uses `npm run dev` against a separately running daemon.

## Auth

| Gate | File | Behaviour |
|------|------|-----------|
| `TokenGate` | `webui/src/components/TokenGate.tsx` | Reads `sessionStorage netattackai.apiToken.v1` via `api/client.ts:6`. Verifies via `GET /capabilities` (`api/hooks.ts:114`). 401→ clear+error. `status 0` → daemon unreachable hint. |
| `OnboardingGate` | `webui/src/components/OnboardingGate.tsx` | After token: `GET /secrets` (`api/hooks.ts:169`). If any `missing` and `sessionStorage netattackai.onboarding.v1 !== "1"`, shows provider+keys+ChatGPT setup. |
| `WelcomeGate` | `webui/src/components/WelcomeScreen.tsx` | First-visit tour (event `netattackai:open-welcome` from `HomePage`) |
| `ErrorBoundary` | `webui/src/components/ErrorBoundary.tsx` | Wraps entire app (`main.tsx:10`) |

Token storage: `sessionStorage` only (survives reload, clears on tab close). Header `Authorization: Bearer <token>` injected by `apiFetch` (`api/client.ts:75`). WS/SSE handshake also uses `sessionStorage` token (`api/ws.ts:236`, `api/sse.ts:200`).

`Layout.tsx:63` sign-out clears token and reloads.

## State Model

| State | Owner | Notes |
|-------|-------|-------|
| Server state | TanStack Query (`api/hooks.ts`) | Central `queryKeys` (`hooks.ts:63`), `defaultQueryOptions` (`hooks.ts:107`), no `refetchOnWindowFocus` (`App.tsx:40`) |
| Live events | `useRunEvents` (`api/ws.ts:36`) | WS-primary, SSE fallback, `sequence` dedupe, `appendBounded` + `requestAnimationFrame` batching |
| Event cache | `eventStore` (`api/eventStore.ts:19`) | In-memory LRU (10 runs), `MAX_EVENTS_PER_RUN=1000` (`api/eventBuffer.ts:4`) |
| Permission mode | `lib/permissionMode.ts` + `components/permission/PermissionControl.tsx` | `read_only`/`approve`/`full_access`, auto-answer via `autoAnswerFor` (`routes/RunPage.tsx:169`) |
| Theme | `lib/useTheme.ts` | `localStorage netattack.theme`, toggled in `Layout` |
| Wizard | `RunWizard.tsx:37` local `useState` | Lifted model/mode/target/goal/power-ups state, `buildRequest()` serialises to `RunCreateRequest` |
| Router | `react-router-dom 6.27` | `?path=recon|attack|fast` pre-selects mode; `:runId` params |

### Query Defaults

`App.tsx:30` — `QueryClient` retry: no retry on 4xx except 408/429, else `<2` failures; `refetchOnWindowFocus:false`. `defaultQueryOptions` (`hooks.ts:107`): `retry:DEFAULT_RETRY`, `staleTime:15s`, `gcTime:5m`. Per-hook overrides: `capabilities 60s`, `config 30s`, `skills 60s`, `goals/schema Infinity`.

## API Integration (summary)

`api/client.ts:69` `apiFetch<T>(path, opts)` — prefixes `/api/v1` unless absolute, injects bearer + `Content-Type`, normalises to `ApiError` (`api/client.ts:29`, `isAuth/isNotFound/isConflict`). `api/types.ts:879` defines all shapes (`RunState`, `DecisionKind`, `RunPreview`, `RunEvent`, etc.) plus helpers `isActiveState/isTerminalState/stateCategory`.

`api/hooks.ts` — 30+ hooks (see `docs/webui/state.md` + `docs/webui/api-integration.md`). Polling: `useRuns` adaptive 5s/60s (`hooks.ts:441`), `useRun` 5s while `running/queued/cancelling` (`hooks.ts:456`), `useDecisions` 5s while pending (`hooks.ts:542`), `useArtifacts` 30s while active (`hooks.ts:610`).

## Layout chrome

`Layout.tsx:15` `NAV_ITEMS` (Home/Sessions/**Connections**/Modules/Goals/Attack Graph/Stats/Skills/Memory/Settings/Help). Connections nav shows active-count badge (desktop `active` + mobile pill) via `useConnections()` (`Layout.tsx:55`). Desktop sidebar + mobile bottom bar. Active-run pill filters `isActiveState`. Permission banners for `approve`/`full_access`. Footer: loopback warning + GitHub link (`Layout.tsx:280`).
