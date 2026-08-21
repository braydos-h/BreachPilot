import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, GitBranch, Loader2, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ApiError } from "@/api/client";
import { useRuns } from "@/api/hooks";
import { isActiveState } from "@/api/types";
import type { RunListRow } from "@/api/types";
import {
  useGraphConflicts,
  useGraphNeighbors,
  useGraphPolling,
  useGraphRun,
  useGraphSummary,
} from "@/features/graph/graphApi";
import { GraphFilters, type GraphFilterState } from "@/features/graph/GraphFilters";
import { GraphActiveFilters } from "@/features/graph/GraphActiveFilters";
import { GraphToolbar } from "@/features/graph/GraphToolbar";
import { GraphStats } from "@/features/graph/GraphStats";
import { GraphDetailsPanel } from "@/features/graph/GraphDetailsPanel";
import { GraphPathFinder } from "@/features/graph/GraphPathFinder";
import { GraphLegend } from "@/features/graph/GraphLegend";
import { AttackGraphCanvas } from "@/features/graph/AttackGraphCanvas";
import type { GraphConflict, GraphExplorerEdge, GraphExplorerNode } from "@/features/graph/graphTypes";

interface ExpansionRequest {
  nodeId: string;
  hops: number;
  ts: number;
}

// Full-viewport investigation workstation: compact header with the run scope
// selector, a status/summary bar, the grouped toolbar, an active-filter strip,
// and a canvas that dominates the remaining height. Side panels are static
// columns on xl screens and overlay drawers below.
export function AttackGraphPage() {
  const [filters, setFilters] = useState<GraphFilterState>({
    runId: "",
    nodeTypes: [],
    statuses: [],
    q: "",
    minConfidence: 0,
  });
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<GraphExplorerNode[]>([]);
  const [expandedEdges, setExpandedEdges] = useState<GraphExplorerEdge[]>([]);
  const [pathMode, setPathMode] = useState(false);
  const [conflictsOpen, setConflictsOpen] = useState(false);
  const [legendOpen, setLegendOpen] = useState(false);
  const [minimapOpen, setMinimapOpen] = useState(true);
  const [filtersOpen, setFiltersOpen] = useState(true);
  const [detailsOpen, setDetailsOpen] = useState(true);
  const [pathNodeIds, setPathNodeIds] = useState<Set<string>>(new Set());
  const [pathEdgeIds, setPathEdgeIds] = useState<Set<string>>(new Set());
  const [fitRequest, setFitRequest] = useState(0);
  const [resetRequest, setResetRequest] = useState(0);
  const [focusRequest, setFocusRequest] = useState<{ nodeId: string; ts: number } | null>(null);
  const [expansion, setExpansion] = useState<ExpansionRequest | null>(null);
  const lastExpansionTs = useRef(0);

  const runId = filters.runId;
  const { data: graph, isLoading: graphLoading, error: graphError } = useGraphRun(
    runId || null,
    { nodeTypes: filters.nodeTypes, statuses: filters.statuses, q: filters.q },
    !!runId,
  );
  const { data: summary } = useGraphSummary(runId, !!runId);
  const { data: conflictsData } = useGraphConflicts(runId, !!runId && conflictsOpen);
  useGraphPolling(runId, !!runId);

  const neighbors = useGraphNeighbors(
    runId,
    expansion?.nodeId ?? null,
    expansion?.hops ?? 1,
    200,
    !!expansion && !!runId,
  );

  // Merge a completed neighborhood expansion into the view state.
  useEffect(() => {
    if (!expansion || neighbors.isLoading || neighbors.isError || !neighbors.data) return;
    const resp = neighbors.data;
    if (!resp.start_node) return;
    if (expansion.ts !== lastExpansionTs.current) {
      lastExpansionTs.current = expansion.ts;
      setExpandedNodes((prev) => mergeNodes(prev, resp.nodes));
      setExpandedEdges((prev) => mergeEdges(prev, resp.edges));
    }
  }, [expansion, neighbors.data, neighbors.isLoading, neighbors.isError]);

  const handlePatchFilters = useCallback((patch: Partial<GraphFilterState>) => {
    setFilters((prev) => ({ ...prev, ...patch }));
  }, []);

  const handleExpand = useCallback((hops: number) => {
    if (!selectedNodeId || !runId) return;
    setExpansion({ nodeId: selectedNodeId, hops, ts: Date.now() });
  }, [selectedNodeId, runId]);

  const handleExpandNode = useCallback((nodeId: string, hops: number) => {
    if (!runId) return;
    setSelectedNodeId(nodeId);
    setExpansion({ nodeId, hops, ts: Date.now() });
  }, [runId]);

  // Client-side confidence filter (view-only; never mutates graph facts).
  const baseNodes = useMemo(() => {
    const nodes = graph?.nodes ?? [];
    if (filters.minConfidence <= 0) return nodes;
    return nodes.filter((n) => n.confidence >= filters.minConfidence);
  }, [graph, filters.minConfidence]);

  const viewNodes = useMemo(() => mergeNodes(baseNodes, expandedNodes), [baseNodes, expandedNodes]);
  const viewEdges = useMemo(() => {
    const ids = new Set(viewNodes.map((n) => n.node_id));
    const edges = mergeEdges(graph?.edges ?? [], expandedEdges);
    return edges.filter((e) => ids.has(e.source_node_id) && ids.has(e.target_node_id));
  }, [graph, expandedEdges, viewNodes]);

  // Changing filters returns to the base graph (drop neighborhood + path overlay).
  const filterSig = JSON.stringify([filters.nodeTypes, filters.statuses, filters.q]);
  useEffect(() => {
    setExpandedNodes([]);
    setExpandedEdges([]);
    setPathNodeIds(new Set());
    setPathEdgeIds(new Set());
  }, [filterSig, runId]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSelectNode = useCallback((id: string | null) => setSelectedNodeId(id), []);
  const handleFocusNode = useCallback((nodeId: string) => {
    setSelectedNodeId(nodeId);
    setFocusRequest({ nodeId, ts: Date.now() });
  }, []);
  const handleShowPath = useCallback((nodeIds: Set<string>, edgeIds: Set<string>) => {
    setPathNodeIds(nodeIds);
    setPathEdgeIds(edgeIds);
    setPathMode(false);
    const first = nodeIds.values().next().value as string | undefined;
    if (first) setFocusRequest({ nodeId: first, ts: Date.now() });
  }, []);
  const handleClearPath = useCallback(() => {
    setPathNodeIds(new Set());
    setPathEdgeIds(new Set());
  }, []);

  const closePanels = useCallback(() => {
    setFiltersOpen(false);
    setDetailsOpen(false);
  }, []);

  const truncated = graph?.truncated === true || (graph?.total_nodes ?? 0) > 500;
  const selectedNode = useMemo(
    () => viewNodes.find((n) => n.node_id === selectedNodeId) ?? null,
    [viewNodes, selectedNodeId],
  );
  const pathActive = pathNodeIds.size > 0;
  const anyPanelOpen = filtersOpen || detailsOpen;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Header: identity + run scope selector */}
      <header className="flex flex-wrap items-center gap-3 border-b px-4 py-2">
        <h1 className="flex items-center gap-2 text-sm font-semibold">
          <GitBranch className="h-4 w-4 text-primary" />
          Attack Graph
        </h1>
        <p className="hidden text-xs text-muted-foreground md:inline">
          Scope-isolated investigation of a run&apos;s attack graph.
        </p>
        <div className="ml-auto flex min-w-0 items-center gap-2">
          <Label htmlFor="graph-run-select" className="shrink-0 text-xs">Run (scope)</Label>
          <RunSelect
            id="graph-run-select"
            value={filters.runId}
            onChange={(runId) => handlePatchFilters({ runId })}
          />
        </div>
      </header>

      {/* Status bar */}
      <div className="flex flex-wrap items-center gap-2 border-b px-3 py-1.5">
        <GraphStats summary={summary} onFocusNode={handleFocusNode} onOpenConflicts={() => setConflictsOpen(true)} />
        {truncated && (
          <span className="inline-flex items-center gap-1.5 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-2 py-0.5 text-[11px] text-yellow-300" role="status">
            <AlertTriangle className="h-3 w-3" />
            Graph is large — refine filters to narrow the view.
          </span>
        )}
      </div>

      {/* Investigation toolbar */}
      <GraphToolbar
        nodes={viewNodes}
        selectedNodeId={selectedNodeId}
        onFit={() => setFitRequest((n) => n + 1)}
        onReset={() => setResetRequest((n) => n + 1)}
        onCenterSelected={() => selectedNodeId && setFocusRequest({ nodeId: selectedNodeId, ts: Date.now() })}
        onExpand={handleExpand}
        canExpand={!!selectedNodeId && !!runId}
        expanding={!!expansion && neighbors.isLoading}
        onOpenPath={() => setPathMode((v) => !v)}
        pathOpen={pathMode}
        pathActive={pathActive}
        onClearPath={handleClearPath}
        onToggleFilters={() => setFiltersOpen((v) => !v)}
        filtersOpen={filtersOpen}
        onToggleDetails={() => setDetailsOpen((v) => !v)}
        detailsOpen={detailsOpen}
        onToggleLegend={() => setLegendOpen((v) => !v)}
        legendOpen={legendOpen}
        onToggleMinimap={() => setMinimapOpen((v) => !v)}
        minimapOpen={minimapOpen}
        onToggleConflicts={() => setConflictsOpen((v) => !v)}
        conflictsOpen={conflictsOpen}
        conflictCount={summary?.stats.conflict_count ?? conflictsData?.conflicts.length ?? 0}
        onFocusNode={handleFocusNode}
      />

      {/* Active-filter chips */}
      <div className="border-b px-3 py-1">
        <GraphActiveFilters filters={filters} onChange={handlePatchFilters} />
      </div>

      {/* Workspace: collapsible filters | canvas | collapsible details */}
      <div className="relative flex min-h-0 flex-1 overflow-hidden">
        {anyPanelOpen && (
          <button
            type="button"
            className="absolute inset-0 z-20 bg-black/40 lg:hidden"
            onClick={closePanels}
            aria-label="Close panels"
          />
        )}

        {filtersOpen && (
          <aside className="absolute inset-y-0 left-0 z-30 w-64 shrink-0 overflow-y-auto border-r bg-card/40 lg:static lg:z-auto">
            <div className="flex items-center justify-between border-b px-3 py-2 lg:hidden">
              <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Filters</span>
              <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => setFiltersOpen(false)} aria-label="Close filters">
                <X className="h-3.5 w-3.5" />
              </Button>
            </div>
            <div className="p-3">
              <GraphFilters filters={filters} onChange={handlePatchFilters} summary={summary} />
            </div>
          </aside>
        )}

        <div
          className="relative min-w-0 flex-1"
          role="application"
          aria-label="Attack graph canvas. Pan and zoom with mouse or touch; drag nodes to rearrange; click a node to inspect it."
        >
          {legendOpen && <GraphLegend onClose={() => setLegendOpen(false)} className="absolute left-3 top-3" />}

          {conflictsOpen && (
            <ConflictsPanel
              conflicts={conflictsData?.conflicts ?? []}
              onClose={() => setConflictsOpen(false)}
              className="absolute right-3 top-3 z-20 w-80 max-h-[70%]"
            />
          )}

          {pathMode && (
            <div className="absolute bottom-3 right-3 z-20 max-h-[62%] w-80 overflow-y-auto rounded-lg border bg-background/95 p-3 shadow-lg backdrop-blur">
              <GraphPathFinder
                runId={runId}
                nodes={viewNodes}
                selectedNodeId={selectedNodeId}
                onShowPath={handleShowPath}
                onClose={() => setPathMode(false)}
                active={pathActive}
                onClearPath={handleClearPath}
              />
            </div>
          )}

          {graphLoading && (
            <div className="absolute inset-0 z-10 flex items-center justify-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Building graph…
            </div>
          )}
          {graphError && (
            <div className="absolute inset-0 z-10 flex flex-col items-center justify-center gap-2 p-6 text-center">
              <p className="text-sm text-destructive">{graphErrorMessage(graphError)}</p>
              {graphError instanceof ApiError && graphError.isNotFound && (
                <p className="text-xs text-muted-foreground">
                  Enable <code className="font-mono">api.graph_route: true</code> in config.yaml to use the graph.
                </p>
              )}
            </div>
          )}
          {!runId && (
            <div className="absolute inset-0 z-10 flex items-center justify-center p-6 text-center text-sm text-muted-foreground">
              Select a run to load its attack graph.
            </div>
          )}
          {runId && !graphLoading && !graphError && viewNodes.length === 0 && (
            <div className="absolute inset-0 z-10 flex items-center justify-center p-6 text-center text-sm text-muted-foreground">
              No graph nodes for this run yet — it may still be running, or the filters exclude everything.
            </div>
          )}
          {runId && !graphLoading && !graphError && viewNodes.length > 0 && (
            <AttackGraphCanvas
              nodes={viewNodes}
              edges={viewEdges}
              selectedNodeId={selectedNodeId}
              onSelectNode={handleSelectNode}
              pathNodeIds={pathNodeIds}
              pathEdgeIds={pathEdgeIds}
              pathStartNodeId={pathNodeIds.size ? selectedStartOf(pathNodeIds) : undefined}
              pathEndNodeId={pathNodeIds.size ? selectedEndOf(pathNodeIds) : undefined}
              focusRequest={focusRequest}
              fitRequest={fitRequest}
              resetRequest={resetRequest}
              showMinimap={minimapOpen}
              onNodeDoubleClick={(id) => handleExpandNode(id, 1)}
              className="h-full w-full"
            />
          )}
        </div>

        {detailsOpen && (
          <aside className="absolute inset-y-0 right-0 z-30 w-80 shrink-0 overflow-y-auto border-l bg-card/95 lg:static lg:z-auto">
            <GraphDetailsPanel
              runId={runId}
              nodeId={selectedNode ? selectedNode.node_id : null}
              onSelect={handleSelectNode}
              onClose={() => setSelectedNodeId(null)}
              onFocus={handleFocusNode}
              onExpand={handleExpandNode}
            />
          </aside>
        )}
      </div>
    </div>
  );
}

// The backend path omits the start node — the overlay needs its real id. We
// track start/dest as the first/last ids in the path node set, which
// handleShowPath builds as [start, ...steps]. This is display-only.
function selectedStartOf(ids: Set<string>): string | undefined {
  const arr = [...ids];
  return arr.length ? arr[0] : undefined;
}
function selectedEndOf(ids: Set<string>): string | undefined {
  const arr = [...ids];
  return arr.length > 1 ? arr[arr.length - 1] : undefined;
}

function RunSelect({
  id,
  value,
  onChange,
}: {
  id: string;
  value: string;
  onChange: (runId: string) => void;
}) {
  const runs = useRuns(50, 0);
  const rows = runs.data?.runs ?? [];
  // Active runs first, then newest.
  const sorted = useMemo(
    () => [...rows].sort((a, b) => (isActiveState(a.state) ? -1 : isActiveState(b.state) ? 1 : 0)),
    [rows],
  );
  return (
    <select
      id={id}
      className="h-8 max-w-52 rounded-md border border-input bg-background px-2 text-xs focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      <option value="">Select a run…</option>
      {sorted.map((r) => (
        <option key={r.id} value={r.id}>
          {runLabel(r)} — {r.id.slice(0, 8)}
        </option>
      ))}
    </select>
  );
}

function runLabel(r: RunListRow): string {
  const target = r.target || r.target_ip || "";
  const title = r.title || target || "";
  return title ? `${title} (${target})` : (r.target_ip || r.id.slice(0, 8));
}

function graphErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.code === "graph_disabled" ? "Graph route is disabled." : error.message || "Failed to load graph.";
  }
  return "Failed to load graph.";
}

function ConflictsPanel({
  conflicts,
  onClose,
  className,
}: {
  conflicts: GraphConflict[];
  onClose: () => void;
  className?: string;
}) {
  return (
    <div className={`overflow-hidden rounded-lg border bg-background/95 shadow-lg backdrop-blur ${className ?? ""}`}>
      <div className="flex items-center justify-between border-b px-3 py-1.5">
        <h3 className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          <AlertTriangle className="h-3.5 w-3.5 text-yellow-500" />
          Merge conflicts ({conflicts.length})
        </h3>
        <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={onClose} aria-label="Close conflicts">
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>
      {conflicts.length === 0 ? (
        <p className="p-3 text-xs text-muted-foreground">
          No merge conflicts were detected during ingestion for this run.
        </p>
      ) : (
        <ul className="max-h-full space-y-1.5 overflow-y-auto p-2">
          {conflicts.map((c, i) => (
            <li key={i} className="rounded border border-border/60 bg-card/40 px-2 py-1.5 text-xs">
              <div className="flex flex-wrap items-center gap-1.5">
                <Badge variant="outline" className="font-mono text-[10px]">{c.node_value}</Badge>
                <span className="ml-auto font-mono text-[10px] tabular-nums text-muted-foreground">
                  {c.existing_confidence.toFixed(2)} → {c.proposed_confidence.toFixed(2)}
                </span>
              </div>
              <p className="mt-0.5 text-muted-foreground">{c.reason}</p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function mergeNodes(a: GraphExplorerNode[], b: GraphExplorerNode[]): GraphExplorerNode[] {
  const byId = new Map<string, GraphExplorerNode>();
  for (const n of a) byId.set(n.node_id, n);
  for (const n of b) byId.set(n.node_id, n);
  return [...byId.values()];
}

function mergeEdges(a: GraphExplorerEdge[], b: GraphExplorerEdge[]): GraphExplorerEdge[] {
  const byId = new Map<string, GraphExplorerEdge>();
  for (const e of a) byId.set(e.edge_id, e);
  for (const e of b) byId.set(e.edge_id, e);
  return [...byId.values()];
}
