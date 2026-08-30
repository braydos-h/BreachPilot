---
title: Home Page
sources:
  - webui/src/routes/HomePage.tsx
  - webui/src/api/hooks.ts
  - webui/src/lib/utils.ts
  - webui/src/components/Loading.tsx
  - webui/src/components/StatusBadge.tsx
  - webui/src/components/ui/badge.tsx
  - webui/src/components/ui/button.tsx
  - webui/src/components/ui/card.tsx
  - webui/src/components/ui/dialog.tsx
tests: []
subsystem: webui
---

# Home Page (`/`)

Route: `webui/src/App.tsx:61` → `webui/src/routes/HomePage.tsx:62` (`HomePage`, eager-loaded).

## Purpose

Landing dashboard. Mirrors CLI menu as web entry: hero + stats + active-run banner + two action cards + recent sessions list. Footer safety reminder.

## Data

| Hook | Call | Use |
|------|------|-----|
| `useRuns(50,0)` | `HomePage.tsx:63` | All header stats + banner + recent list. `queryKeys.runs(50,0,"created_desc")` (`api/hooks.ts:78`) |

Derived:

| Value | Expression | Note |
|-------|------------|------|
| `activeRun` | `rows.find(isActiveState)` | `HomePage.tsx:65` |
| `recent` | `rows.slice(0,5)` | top 5 |
| `doneCount` | `filter(isTerminalState)` | `HomePage.tsx:67` |
| `failedCount` | `filter(s==="failed")` | `HomePage.tsx:68` |
| `returning` | `rows.length>0 && !isLoading` | controls welcome vs returning hero copy |
| `lastTarget` | `lastRow.target \|\| target_ip` | fallback in subtitle |

`isActiveState / isTerminalState` from `api/types.ts:824`.

## Sections

### FullAccessNotice dialog

`FullAccessNotice` (`HomePage.tsx:29`) — `sessionStorage breachpilot.fullNotice.shown.v1` once-per-session. `Dialog` (`components/ui/dialog.tsx:Radix`) with `ShieldAlert` + read-only/approve blurb. Triggered via `useEffect` on mount.

### Hero (`HomePage.tsx:77`)

`bg-grid bg-radial-fade` + `animate-scan` + blurred primary orb. Conditional `h1`:

- returning: `Welcome back.` (`text-gradient-primary`)
- first visit: `BreachPilot`

Subtitle: returning → `"<n> runs on record, last targeting <target> <relative>"` using `formatRelative` (`lib/utils.ts:14`); first → authorized-assets tagline.

CTA row (`HomePage.tsx:110`):

| Button | Link | Icon | Note |
|--------|------|------|------|
| New recon | `/runs/new?path=recon` | `ScanSearch` | `glow-primary`, primary |
| Resume active | `/runs/<id>` (when `activeRun`) | `Activity` pulse | yellow outline `border-yellow-500/40` |
| Take the tour | dispatch `breachpilot:open-welcome` | `Compass` | opens `WelcomeGate` (`components/WelcomeScreen.tsx`) |

### Stats strip (`HomePage.tsx:142`)

Grid `cols-2 → cols-4`, `Stat` (`HomePage.tsx:244`) wrapper with accent color:

| Label | Value | Accent |
|-------|-------|--------|
| Total runs | `rows.length` | — (or `"loading"` hint while `isLoading`) |
| Active | `"1"` or `"0"` | `yellow` when active |
| Completed | `doneCount` | `emerald` |
| Failed | `failedCount` | `red` if `>0` |

### Active-run banner (`HomePage.tsx:156`)

When `activeRun`: `Card border-yellow-500/40 bg-yellow-500/5`, `Activity` pulse + `Badge variant="warn"` + mono target + `StatusBadge` + `Open run` link (`Button outline`).

### Action cards (`HomePage.tsx:171`)

`ActionCard` (`HomePage.tsx:278`) — `Link` styled as card with icon pill + title/desc + `Start →`:

| Card | `to` | Title | Desc |
|------|------|-------|------|
| Recon | `/runs/new?path=recon` | Recon & Suggest Goals | Scan first, AI-ranked goals |
| Attack | `/runs/new?path=attack` | Attack | Full exploitation |

Single accent `cyan` (`hover:border-primary/50 hover:glow-primary`, `text-primary`).

### Recent sessions (`HomePage.tsx:189`)

Header: `History` + `Recent sessions` + count + `View all → /sessions` (`ListFilter`).

States:

| Condition | Render |
|-----------|--------|
| `runs.error` | destructure + Retry button (`runs.refetch()`) |
| `recent.length===0 && !isLoading && !error` | empty (`Target` icon, "No past sessions yet.") |
| `isLoading && recent empty` | `SkeletonRows count=3` (`components/Loading.tsx`) |
| `recent>0` | `ul.divide-y` of `RecentRow` |

`RecentRow` (`HomePage.tsx:311`): `Link /runs/<id>` row with `truncateId` mono id, `StatusBadge`, title vs target fallback (title preferred), `mode` (hidden on mobile), `formatRelative(created_at)` timestamp.

### Safety footer

`"Run only against assets you own or are explicitly authorized to test."` with dot.

## Styling hooks

`Stat` uses `text-[10px] uppercase tracking-wide` label + `font-mono text-xl tabular-nums` value. Cards use `bg-card/30` (`tailwind.config.ts` HSL vars). Animations `animate-fade-in-up` with 0.1s/0.2s delays (`index.css:180`).
