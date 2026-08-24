---
title: Graph Pages — Attack Graph & Per-Run Path
sources:
  - webui/src/features/graph/AttackGraphPage.tsx
  - webui/src/features/graph/AttackGraphCanvas.tsx
  - webui/src/features/graph/GraphNodeTypes.tsx
  - webui/src/features/graph/GraphFilters.tsx
  - webui/src/features/graph/GraphToolbar.tsx
  - webui/src/features/graph/GraphStats.tsx
  - webui/src/features/graph/GraphDetailsPanel.tsx
  - webui/src/features/graph/GraphPathFinder.tsx
  - webui/src/features/graph/GraphActiveFilters.tsx
  - webui/src/features/graph/GraphSearch.tsx
  - webui/src/features/graph/GraphLegend.tsx
  - webui/src/features/graph/graphApi.ts
  - webui/src/features/graph/graphTransforms.ts
  - webui/src/features/graph/graphTypes.ts
  - webui/src/routes/GraphPage.tsx
  - webui/src/components/AttackGraph.tsx
  - webui/src/components/AttackGraphDag.tsx
tests:
  - webui/src/features/graph/__tests__
subsystem: webui
---

# Graph Pages

Two graph surfaces exist. They are distinct:

| Surface | Route | Component | Data source |
|---------|-------|-----------|-------------|
| Investigation workstation | `/graph` | `features/graph/AttackGraphPage.tsx:37` | Explorer API `/graph/runs/<id>/*` (`features/graph/graphApi.ts`) |
| Per-run mini graph | `/runs/:runId/graph` + inline `Attack Path` tab in `RunPage` | `routes/GraphPage.tsx:11` + `components/AttackGraph*.tsx` | Artifacts `enhanced/enhanced_report.json` + provider report DAG |

## Attack Graph (`/graph`) — Explorer

Route: `App.tsx:71` lazy → `features/graph/AttackGraphPage.tsx:37`. Mounted under `Layout`. Gated by `api.graph_route:true` (`docs/api.md: Graph Explorer Routes`).

### Endpoint mapping (from `graphApi.ts:8` + `docs/api.md`)

All `queryKeys graphExplorer` (`graphApi.ts:23`):

| Hook | Method & URL | Params | Notes |
|------|--------------|--------|-------|
| `useGraphRun` | `GET /graph/runs/<id>?node_type=&status=&q=&limit=` | `limit` default 300, cap 500 (`types.ts:57`) | `graphKeys.graph` (`graphApi.ts:25`) |
| `useGraphSummary` | `GET /graph/runs/<id>/summary` | — | counts + `stats` chips, `highest_degree_node`, `conflict_count` |
| `useGraphConflicts` | `GET /graph/runs/<id>/conflicts` | lazy when `conflictsOpen` | never hidden (`AttackGraphPage.tsx:69`) |
| `useGraphNode` | `GET /graph/runs/<id>/nodes/<nodeId>` |  | `GraphNodeDetail` (node + edges+neighbors) |
| `useGraphNeighbors` | `GET /graph/runs/<id>/nodes/<nodeId>/neighbors?max_hops&max_nodes` | `max_hops` 1–4, `max_nodes` 1–200 | BFS including start (`graphApi.ts:98`) |
| `useGraphPaths` | `GET /graph/runs/<id>/paths?start&end&max_length&max_paths` | `max_length` 1–8, `max_paths` 1–8 | unknown endpoints → `paths:[]` |
| `useGraphPolling` | invalidates `graphKeys.all(runId)` every 10s while `isActiveState(runState)` | — | `graphApi.ts:150` |
| `useInvalidateGraph` | `qc.invalidateQueries graphExplorer/<runId>` | — | WS artifact invalidates same key (`api/ws.ts:88`) |

Retry (`graphApi.ts:35`): no retry on 404 (disabled/no-graph). `staleTime 5s`.

DTOs mirror backend `to_dict()` exactly (`features/graph/graphTypes.ts:1`): `GraphExplorerNode/Edge`, `GraphRunResponse` (`nodes/edges/total_nodes/truncated`), `GraphSummaryResponse` (`summary.nodes/edges + stats`), `GraphConflict`, `GraphNeighborsResponse`, `GraphPathsResponse` (`distance 1…` steps omitting start node).

### Page state (`AttackGraphPage.tsx:37`)

```ts
filters: {runId, nodeTypes:[], statuses:[], q:"", minConfidence:0}
selectedNodeId, expandedNodes/Edges, pathNodeIds/pathEdgeIds,
pathMode, conflictsOpen, legendOpen, minimapOpen, filtersOpen, detailsOpen,
fitRequest, resetRequest, focusRequest, expansion:{nodeId,hops,ts}
```

- `useGraphRun(runId, {nodeTypes,statuses,q})` (`AttackGraphPage.tsx:63`) + `useGraphSummary` + `useGraphConflicts` (when open) + `useGraphPolling`.
- `useGraphNeighbors(runId, expansion.nodeId, hops, 200)` on demand; merge into `expandedNodes/Edges` via `mergeNodes/mergeEdges` (`AttackGraphPage.tsx:442`) when `expansion.ts !== lastExpansionTs`.
- Client-side `minConfidence` filter is view-only (`AttackGraphPage.tsx:108`).
- `viewNodes = mergeNodes(baseNodes, expandedNodes)`; `viewEdges = mergeEdges(graph.edges, expandedEdges)` filtered to edges where both ids in view (`AttackGraphPage.tsx:114`).
- Changing any server filter (`filterSig` JSON of `nodeTypes/statuses/q`) or `runId` resets expanded + path overlay (`AttackGraphPage.tsx:122`).
- `truncated = graph.truncated || total_nodes>500` → yellow banner (`AttackGraphPage.tsx:152`).
- `selectedNode` derived from `viewNodes`.

### Layout

```
<header> title + subtitle + RunSelect (label "Run (scope)")
<status bar> <GraphStats summary + conflict count + hub> + truncated banner
<GraphToolbar>
<GraphActiveFilters> chips
┌──────────────┬──────────────────┬──────────────┐
│ filters aside│ canvas (flex:1)  │ details aside│
│ <GraphFilters>│ <AttackGraphCanvas> + overlays │ <GraphDetailsPanel>
│ (GraphSearch) │  legend / conflicts / path finder│
└──────────────┴──────────────────┴──────────────┘
```

- Filters/details are absolute overlays on mobile (`lg:static` else) with scrim + X close (`AttackGraphPage.tsx:226`).
- `RunSelect` (`AttackGraphPage.tsx:353`): `useRuns(50,0)` sorted active-first, `<select>` with `runLabel` (`title || target`).
- `ConflictsPanel` (`AttackGraphPage.tsx:399`): absolute `right-3 top-3`, `AlertTriangle`, list of `conflicts` (`existing→proposed confidence` + reason), empty message when none.
- Errors: `graphLoading` → `Loader2 "Building graph…"`, `graphError` (404→ graph_disabled hint `api.graph_route:true`), no `runId` → "Select a run", zero nodes → "No graph nodes…" (`AttackGraphPage.tsx:278`).

### Filters (`GraphFilters.tsx:36`)

| Group | Server vs client | UI |
|-------|------------------|----|
| Search `q` | server (`?q=`) debounced 350ms (`GraphFilters.tsx:39`) | `Search` + `X` clear, `Input id graph-search` |
| Node types | server (`?node_type=` repeat) | grouped by `NODE_TYPE_CATEGORIES` (`graphTransforms.ts:107`), per-category `label`, filterable via `typeQuery`, `All`/`None`, each row shows `nodeTypeMeta(t).color` dot + count from `summary.summary.nodes` |
| Statuses | server (`?status=` repeat) | `NODE_STATUS_ORDER` (`graphTransforms.ts:135`) with `statusMeta` dot |
| Min confidence | client (`filters.minConfidence`) | `range 0–1 step 0.05`, `font-mono` value (`GraphFilters.tsx:176`) |

`GraphActiveFilters.tsx` — chip strip for current filters with clear actions.

### Toolbar (`GraphToolbar.tsx`)

`GraphToolbar` controls:

| Action | Prop | Effect |
|--------|------|--------|
| Fit | `onFit → setFitRequest++` | `AttackGraphCanvas:232` `fitView(padding 0.15, 300ms)` |
| Reset | `onReset → setResetRequest++` | clear `positions` back to deterministic grid |
| Center selected | `onCenterSelected → setFocusRequest` | `fitView(nodes:[selected])` |
| Expand 1/2 hops | `onExpand(hops)` disabled `!selectedNodeId` | `setExpansion` → `useGraphNeighbors` |
| Path mode | `onOpenPath` toggle | overlay `GraphPathFinder` (`AttackGraphPage.tsx:265`) |
| Clear path | `onClearPath` | `pathNodeIds/EdgeIds = empty` |
| Filters/Details/Legend/Minimap/Conflicts toggles | boolean flips | show/hide panels; conflicts badge `conflict_count` from `summary.stats.conflict_count ?? conflictsData.conflicts.length` |

`GraphSearch.tsx` inside toolbar focuses a node; `GraphStats.tsx` renders `summaryChips(stats)` (`graphTransforms.ts:310`) chips (Nodes/Hosts/Services/Findings/… + highest-degree hub).

### Canvas (`AttackGraphCanvas.tsx:58`)

`ReactFlowProvider → CanvasInner`. Stack: `reactflow@11.11.4` (`package.json:35`).

| Feature | Detail |
|---------|--------|
| Node mapping | `toFlowNodes(nodes)` (`graphTransforms.ts:199`): deterministic column-per-type grid `x = typeIndex*250, y = perTypeCount*86`, `Position.Right/Left`, `type: "graph"` → `GraphFlowNode` (`GraphNodeTypes.tsx`) |
| Edge mapping | `toFlowEdges(edges)` (`graphTransforms.ts:223`): `smoothstep`, `MarkerType.ArrowClosed`, color/dash from `edgeMeta` (`graphTransforms.ts:188`), label bg `rgba(2,6,23,0.75)` |
| Connected emphasis | when a node selected, adds connected nodes/edges sets (`AttackGraphCanvas:78`), dims non-connected (`opacity 40`) |
| Path emphasis | `pathNodeIds/EdgeIds` from `GraphPathFinder`; path nodes tinted, path edges emerald `rgb(52,211,153)` `2.75px`, others dimmed (`0.15`) |
| Edge labels | visible if `isPath || isConnected || isHover || edgeLabelsVisible` (`zoom>=0.6`, `EDGE_LABEL_ZOOM`) else blank; `onMove/onMoveEnd` toggles (`AttackGraphCanvas:214`) |
| Interactions | `onNodeClick → onSelectNode`, `onNodeDoubleClick → handleExpandNode(node,1)` (`AttackGraphPage.tsx:318`), `onPaneClick → clear selection`, `Escape` clears, `Enter/Space` on focused node selects; drag with `applyNodeChanges` + `positions` state; `nodesDraggable`, `minZoom 0.1/max 2.5` |
| Fit/reset/focus | `fitRequest` → fit whole graph; `resetRequest` → restore positions; `focusRequest` → `fitView(nodes:[target])` + 800ms highlight; path overlay frames `pathNodeIds`; initial load auto-fits (`AttackGraphCanvas:258`) |
| Minimap | `MiniMap` when `showMinimap`, node color `nodeTypeMeta(type).color` (`AttackGraphCanvas:298`) |

`GraphLegend.tsx` — floating palette of `NODE_TYPE_CATEGORIES` colors/icons.

### Node rendering (`GraphNodeTypes.tsx`)

`GraphFlowNode` (`GraphFlowNodeData: {node, path, focus, start, end, dimmed, selected}`): `nodeTypeMeta(node_type)` icon (`Network/Server/Globe/Layers/Plug/Link2/AppWindow/Cpu/Hash/User/BadgeCheck/KeyRound/Shield/Boxes/Bug/AlertTriangle/HelpCircle/FileText/Eye/Zap/ShieldCheck/Box`, `graphTransforms.ts:52`), color bg/border, confidence/status bar, value truncate, selection ring vs dim.

### Presentation helpers (`graphTransforms.ts`)

| Symbol | Source | Purpose |
|--------|--------|---------|
| `NODE_TYPE_META` | `graphTransforms.ts:52` | color+icon+category per `GraphNodeType` |
| `STATUS_META` | `graphTransforms.ts:115` | confirmed/likely/suspected/unknown/refuted/exhausted |
| `SEVERITY_META` | `graphTransforms.ts:147` | critical/high/medium/low/info for real `severity` prop |
| `EDGE_TYPE_META` | `graphTransforms.ts:167` | label+color+dash per `GraphEdgeType` |
| `toFlowNodes/toFlowEdges` | `graphTransforms.ts:199` | DTO → React Flow |
| `nodeMatchesQuery` | `graphTransforms.ts:250` | value/type/status/source/id/evidence_ref/cvss/severity/vuln_class/tags substring |
| `rankNodeMatches` | `graphTransforms.ts:272` | exact > prefix > other, then alpha |
| `parseEvidenceRef` | `graphTransforms.ts:299` | `ev:tool:target:hash12:timestamp` split |
| `summaryChips` | `graphTransforms.ts:311` | stats → chip array |

### Details panel (`GraphDetailsPanel.tsx`)

`GraphDetailsPanel` — when `nodeId` provided, calls `useGraphNode(runId, nodeId)`. Shows: `node_id`, `value`, `node_type` badge (color from `nodeTypeMeta`), `status` dot, `confidence` bar, `scope`, `source`, `first_seen/last_seen` (`formatRelative`), `observation/contradiction` counts, `properties` (merging dedicated rows for `severity/cvss_score/vuln_class` not repeated under generic Metadata), `evidence_refs` via `parseEvidenceRef`, `connected nodes` grouped by `edge_type` with `onSelect` focus.

Only renders real metadata; no invented severity when absent.

### Path finder (`GraphPathFinder.tsx`)

Form: start/end `<select>` from `nodes`, `max_length` (1–8) + `max_paths` (1–8). Calls `useGraphPaths`. Renders list of `paths: GraphPathStep[][]` — each path shows sequence `distance 1…` nodes+edges. `onShowPath` builds `Set<nodeId>` = `Set(start, ...steps.node.node_id)` + `Set(edge.edge_id)` + `focus` first node. Clear removes overlay.

## Per-Run Graph (`/runs/:runId/graph` + `RunPage` tab)

### `routes/GraphPage.tsx:11` (`GraphPage`)

Full-page wrapper (`Button ← Back` + `truncateId` + `Attack Path` title). `useArtifacts(runId)` → `artifactNames` set; `enhancedReady = includes("enhanced/enhanced_report.json")`. Height `DAG_HEIGHT = clamp(320..640, innerHeight-220)`. Renders `<AttackGraphDag runId height={DAG_HEIGHT}>` then `<AttackGraph runId ready={enhancedReady}>`. Artifacts fetch error shows Retry.

### `components/AttackGraphDag.tsx`

Lightweight DAG from `GET /runs/<id>/graph` (`RunGraphResponse` `api/types.ts:857` with `nodes: {id,type,label,status?,chain_id?} type tool|target|step` + `edges: {source,target,relation: enables|targets}`), or from explorer `nodes/edges`. Validates `type` and renders React Flow similar to `AttackGraphCanvas` but smaller. Used in `RunPage:Attacks Path` tab as primary viz.

### `components/AttackGraph.tsx`

Renders `enhanced/enhanced_report.json` (`EnhancedReport` `api/types.ts:528` with `exploitation_chains[]` + `technical_findings[]`) as chain cards + `CVSSScore` badge + remediation. Gate `ready` prop prevents 404 before artifact exists (see `RunPage:344`).

## Edge types (real backend only)

`GraphEdgeType` (`graphTypes.ts:15`): `resolves_to/hosts/exposes/runs/depends_on/reachable_from/authenticates_to/has_role/trusts/related_to/supported_by/contradicted_by/derived_from/affected_by/protected_by/connected_to/same_as/observed_on`. `GraphNodeType` (`graphTypes.ts:8`): `asset/host/domain/ip/service/port/endpoint/application/technology/version/identity/role/credential_reference/trust_boundary/network_segment/vulnerability_candidate/finding/hypothesis/evidence/capability/security_control/observation`. Never invent others (`graphTransforms.ts:52`, `graphTypes.ts:1` comment).
