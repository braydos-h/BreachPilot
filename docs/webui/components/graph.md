---
title: Graph Components — Canvas, Transforms, Filters
sources:
  - webui/src/features/graph/AttackGraphCanvas.tsx
  - webui/src/features/graph/GraphNodeTypes.tsx
  - webui/src/features/graph/GraphFilters.tsx
  - webui/src/features/graph/GraphToolbar.tsx
  - webui/src/features/graph/GraphStats.tsx
  - webui/src/features/graph/GraphDetailsPanel.tsx
  - webui/src/features/graph/GraphSearch.tsx
  - webui/src/features/graph/GraphPathFinder.tsx
  - webui/src/features/graph/GraphActiveFilters.tsx
  - webui/src/features/graph/GraphLegend.tsx
  - webui/src/features/graph/graphTransforms.ts
  - webui/src/features/graph/graphTypes.ts
  - webui/src/components/AttackGraph.tsx
  - webui/src/components/AttackGraphDag.tsx
tests:
  - webui/src/features/graph/__tests__
subsystem: webui
---

# Graph Components

## Canvas (`AttackGraphCanvas.tsx:58`)

`AttackGraphCanvas` is the `reactflow@11.11.4` canvas for `/graph` (`features/graph/AttackGraphPage.tsx:304`) and `/runs/:runId/graph`.

### Props (`AttackGraphCanvas.tsx:34`)

```ts
nodes:GraphExplorerNode[], edges:GraphExplorerEdge[],
selectedNodeId,onSelectNode, pathNodeIds?,pathEdgeIds?,pathStart/EndNodeId?,
focusRequest?,fitRequest?,resetRequest?,showMinimap?,onNodeDoubleClick?, className?
```

### Lifecycle

| Effect | Trigger | Action |
|--------|---------|--------|
| Seed reactflow state | `baseNodes/Edges` change | `setFlowNodes`/`setFlowEdges` merging `Map` to preserve drag positions (`AttackGraphCanvas:97`), only include edge when both endpoints present |
| Node emphasis | `pathNodeIds/selected/connected/focus` | `dimmed` opacity 40 vs 100, `path/focus/start/end/selected` data flags (`AttackGraphCanvas:114`) |
| Edge emphasis | `pathEdgeIds/selected/hover/zoom` | path `stroke emerald width2.75 opacity1`, selected-connected `width2 opacity1`, else `0.3` or `0.15` when path mode active; label show iff `isPath||isConnected||isHover||zoom>=0.6` (`AttackGraphCanvas:151`) |
| Drag | `onNodesChange` | `applyNodeChanges` + update `positions:Record<id,{x,y}>` |
| Visibility | `onMove` zoom | toggle `edgeLabelsVisible` at `EDGE_LABEL_ZOOM=0.6` (`AttackGraphCanvas:27`) |
| Fit | `fitRequest++` | `fitView(padding0.15,300ms)` |
| Reset | `resetRequest++` | `setPositions({})` + map `baseNodes` back |
| Focus | `focusRequest.ts` | `fitView(nodes:[node],padding0.4)` + 800ms `focusNodeRef` highlight, else fit whole |
| Initial fit | `flowNodes.length` 0→>0 | `fitView` |
| Path framing | `pathNodeIds` key change | `fitView(nodes:pathNodes, padding0.3)` |

Interactions: `onNodeClick→onSelectNode`, `onNodeDoubleClick→handleExpandNode(id,1)`, `onPaneClick→null`, `Escape→null`, `Enter/Space` on `data-id` → select, `onEdgeMouseEnter/Leave → hoverEdgeId`, `pnOnDrag`, `zoomOnScroll`, `min0.1/max2.5` (`AttackGraphCanvas:305`). Minimap optional (`AttackGraphCanvas:338`) with `nodeColor = nodeTypeMeta(type).color`.

Background: `Dots gap18 size1` themed (`AttackGraphCanvas:331`), `Controls showInteractive false`.

## Node types (`GraphNodeTypes.tsx`)

Single `GraphFlowNode = (GraphFlowNodeData:{node:GraphExplorerNode,path?,focus?,start?,end?,dimmed?,selected?})`. Visual: icon from `nodeTypeMeta(node_type).icon` (`graphTransforms.ts:53`), color dot/border, `value` truncate, `status` dot, `confidence` bar, selection `ring` (not color-only). Start/end variants visually distinct.

## Transforms (`graphTransforms.ts`)

Pure, no mutation of facts.

| Symbol | Lines | Description |
|--------|-------|-------------|
| `NODE_TYPE_META` | `:52` | color/bg/icon/category per `GraphNodeType` (20 entries + fallback `FALLBACK_NODE_META`) |
| `NODE_TYPE_CATEGORIES` | `:107` | 5 groups: infrastructure [domain,host,ip,network_segment,service,port], application [application,technology,version,endpoint], identity [identity,role,credential_reference,trust_boundary], intelligence [vuln_candidate,finding,hypothesis,evidence,observation], defense [capability,security_control,asset] |
| `STATUS_META` | `:115` | confirmed/likely/suspected/unknown/refuted/exhausted |
| `SEVERITY_META` | `:147` | critical/high/medium/low/info |
| `EDGE_TYPE_META` | `:167` | 17 `GraphEdgeType` labels+colors+dashed (e.g. `contradicted_by dashed`) |
| `toFlowNodes` | `:199` | deterministic grid `x=typeIndex*250,y=perTypeCount*86`, `minWidth150 max240`, `Position.Right/Left` |
| `toFlowEdges` | `:223` | `smoothstep`, `MarkerType.ArrowClosed`, dashed if specified |
| `nodeMatchesQuery` | `:250` | lowercased includes across `value/type/status/source/id/evidence_refs/cvss_score/severity/vuln_class/tags` |
| `rankNodeMatches` | `:272` | exact −20, prefix −10 scoring then alpha |
| `parseEvidenceRef` | `:299` | `ev:tool:target:hash12:timestamp` split (lenient) |
| `summaryChips` | `:311` | `GraphSummaryStats → {label,value,key}[]` (Nodes/Hosts/Services/Findings/Confirmed/Hypotheses) |
| `nodeTypeMeta/statusMeta/severityMeta/edgeMeta` | `:103,124,155,188` | lookups with fallback |

Types mirrored exactly (`graphTypes.ts:1`). `GraphNodeType` and `GraphEdgeType` unions are the real backend enums—never invent.

## Filters

### `GraphFilters.tsx:36`

| Group | Kind | Control |
|-------|------|---------|
| Search `q` | server, debounced 350ms | `Input id graph-search`, `Search+X` clear |
| Node types | server repeat `node_type` | grouped `NODE_TYPE_CATEGORIES`, per-type `Checkbox`, color dot, count from `summary.summary.nodes`, searchable via `typeQuery`, `All`/`None` |
| Statuses | server repeat `status` | `NODE_STATUS_ORDER` (`graphTransforms.ts:135`), 2-col grid, `statusMeta` dot |
| Min confidence | client | `range 0-1 step0.05`, value `toFixed(2)` |

Run scope selector lives in `AttackGraphPage` header (not in `GraphFilters`).

### `GraphActiveFilters.tsx`

Chips for `nodeTypes/statuses/q/minConfidence` with clear per-chip + `Clear all`.

### `GraphStats.tsx` + `GraphSearch.tsx`

`GraphStats` → `summaryChips` + `highest_degree_node` + `conflict_count` + hub click `onFocusNode`. `GraphSearch` → `nodeMatchesQuery` local filter for toolbar focus-jump.

## Toolbar (`GraphToolbar.tsx`)

Row of groups:

| Group | Buttons |
|-------|---------|
| View | Fit, Reset, Center selected (disabled `!selected`) |
| Expand | `+1 hop`, `+2 hops` (`onExpand(hops)`), disabled `!selected||!runId`, spinner `expanding` |
| Path | Path mode toggle, Clear path (when `pathActive`) |
| Panels | Filters, Details, Legend, Minimap, Conflicts (badge `conflictCount`) toggles |
| Search | `GraphSearch` focus box |

Conflicts count: `summary?.stats.conflict_count ?? conflictsData?.conflicts.length`.

## Details (`GraphDetailsPanel.tsx`)

Lazy `useGraphNode(runId, nodeId)`. When `nodeId==null` shows empty hint. When `node` present:

- Header: `value`, `node_type` badge color, `status` (`confirmed/likely/…` dot), `confidence` progress, `node_id` monos `CopyButton`.
- Meta grid: `scope`, `source`, `first/last_seen` (`formatRelative`), `observation/contradiction` counts.
- Properties: iterates `node.properties`, maps known keys (`severity` badge via `severityMeta`, `cvss_score` number, `vuln_class` tag) to dedicated rows, remaining keys under Metadata (not repeated).
- Evidence: `parseEvidenceRef` per `evidence_refs` rendering tool/target/hash/timestamp.
- Connected: grouped by `edge_type`, each neighbor clickable `onSelect` + `onFocus`.

No invented properties—if `severity`/`cvss_score` not in `properties`, none shown.

## Path finder (`GraphPathFinder.tsx`)

Controls: `start<select nodes>` + `end<select>` + `max_length 1-8` (`number`) + `max_paths 1-8`; calls `useGraphPaths(runId,start,end,maxLen,maxPaths)` (`graphApi.ts:118`). Result `paths: GraphPathStep[][]` — each path rendered as vertical list `distance:node —edge→`. Actions `Show path i` → `handleShowPath` builds `Set(nodeId)`/`Set(edgeId)` as above; `Clear` removes overlay. Overlay highlight is the only mutation (never mutates graph facts).

## Legend (`GraphLegend.tsx`)

Floating `absolute left-3 top-3` card: 5 category sections with `NODE_TYPE_CATEGORIES` swatches, `STATUS_META` row, `EDGE_TYPE_META` samples, close `X`. Toggleable from toolbar.

## Per-run mini graphs

| Component | File | Hook |
|-----------|------|------|
| `AttackGraphDag` | `components/AttackGraphDag.tsx` | `useRunGraph(runId)` (`api/hooks.ts:769` → `GET /runs/<id>/graph` → `RunGraphResponse tool|target|step + enables|targets` `api/types.ts:857`) |
| `AttackGraph` | `components/AttackGraph.tsx` | `useFetchArtifactBlob("enhanced/enhanced_report.json")` → `EnhancedReport` (`api/types.ts:528`) chains + `TechnicalFinding` CVSS + remediation cards |

Both gated by `enabled`/`ready`; `AttackGraphPage` shows them on per-run full page (`routes/GraphPage.tsx:34`), `RunPage` inline tab uses `artifactReady` gating.
