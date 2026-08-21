import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, GitBranch, Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { ApiError } from "@/api/client";
import {
  useGraphConflicts,
  useGraphNeighbors,
  useGraphPolling,
  useGraphRun,
  useGraphSummary,
} from "@/features/graph/graphApi";
import { GraphFilters, type GraphFilterState } from "@/features/graph/GraphFilters";
import { GraphToolbar } from "@/features/graph/GraphToolbar";
import { GraphStats } from "@/features/graph/GraphStats";
import { GraphDetailsPanel } from "@/features/graph/GraphDetailsPanel";
import { GraphPathFinder } from "@/features/graph/GraphPathFinder";
import { AttackGraphCanvas } from "@/features/graph/AttackGraphCanvas";
import type { GraphConflict, GraphExplorerEdge, GraphExplorerNode } from "@/features/graph/graphTypes";

interface ExpansionRequest {
  nodeId: string;
  hops: number;
  ts: number;
}

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
  const { data: summary } = useGraphSummary(runId || null, !!runId);
  const { data: conflictsData } = useGraphConflicts(runId || null, !!runId && conflictsOpen);
  useGraphPolling(runId || null, !!runId);

  const neighbors = useGraphNeighbors(
    runId || null,
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
  const handleShowPath = useCallback((nodeIds: Set<string>, edgeIds: Set<string>) => {
    setPathNodeIds(nodeIds);
    setPathEdgeIds(edgeIds);
    setPathMode(false);
    const first = nodeIds.values().next().value as string | undefined;
    if (first) setFocusRequest({ nodeId: first, ts: Date.now() });
  }, []);
  const handleFocusNode = useCallback((nodeId: string) => {
    setSelectedNodeId(nodeId);
    setFocusRequest({ nodeId, ts: Date.now() });
  }, []);

  const truncated = graph?.truncated === true || (graph?.total_nodes ?? 0) > 500;
  const selectedNode = useMemo(
    () => viewNodes.find((n) => n.node_id === selectedNodeId) ?? null,
    [viewNodes, selectedNodeId],
  );

  return (
    <div className="space-y-4 p-4 md:p-6">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold">
            <GitBranch className="h-5 w-5 text-primary" />
            Attack Graph
          </h1>
          <p className="text-xs text-muted-foreground">
            Interactive investigation of a run's attack graph (scope-isolated per run). Select a run to begin.
          </p>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[260px_minmax(0,1fr)_340px]">
        {/* Left: filters */}
        <Card className="border-border/60 xl:max-h-[calc(100dvh-8rem)] xl:overflow-y-auto">
          <CardContent className="p-3">
            <GraphFilters filters={filters} onChange={handlePatchFilters} />
          </CardContent>
        </Card>

        {/* Center: canvas + toolbar + stats */}
        <div className="min-w-0 space-y-3">
          <GraphToolbar
            nodes={viewNodes}
            selectedNodeId={selectedNodeId}
            onFit={() => setFitRequest((n) => n + 1)}
            onReset={() => setResetRequest((n) => n + 1)}
            onExpand={handleExpand}
            canExpand={!!selectedNodeId && !!runId}
            expanding={!!expansion && neighbors.isLoading}
            onTogglePath={() => setPathMode((v) => !v)}
            pathMode={pathMode}
            onToggleConflicts={() => setConflictsOpen((v) => !v)}
            conflictsOpen={conflictsOpen}
            conflictCount={summary?.stats.conflict_count ?? conflictsData?.conflicts.length ?? 0}
            onFocusNode={handleFocusNode}
          />

          <GraphStats stats={summary?.stats} />

          {truncated && (
            <div className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-1.5 text-xs text-yellow-300" role="status">
              <AlertTriangle className="h-3.5 w-3.5" />
              <span>Graph is large — refine filters to narrow the view.</span>
            </div>
          )}

          <Card className="border-border/80">
            <CardContent className="p-0">
              <div
                className="relative h-[60dvh] min-h-[420px] rounded-md"
                role="application"
                aria-label="Attack graph canvas. Pan and zoom with mouse or touch; drag nodes to rearrange; click a node to inspect it."
              >
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
                    focusRequest={focusRequest}
                    fitRequest={fitRequest}
                    resetRequest={resetRequest}
                    className="h-full w-full"
                  />
                )}
              </div>
            </CardContent>
          </Card>

          {pathMode && (
            <GraphPathFinder
              runId={runId}
              nodes={viewNodes}
              onShowPath={handleShowPath}
              onClose={() => setPathMode(false)}
            />
          )}

          {conflictsOpen && <ConflictsPanel conflicts={conflictsData?.conflicts ?? []} />}
        </div>

        {/* Right: details */}
        <Card className="border-border/80 xl:max-h-[calc(100dvh-8rem)] xl:overflow-y-auto">
          <CardContent className="p-0 xl:h-full">
            <GraphDetailsPanel
              runId={runId}
              nodeId={selectedNode ? selectedNode.node_id : null}
              onSelect={handleSelectNode}
              onClose={() => setSelectedNodeId(null)}
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function graphErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return error.code === "graph_disabled" ? "Graph route is disabled." : error.message || "Failed to load graph.";
  }
  return "Failed to load graph.";
}

function ConflictsPanel({ conflicts }: { conflicts: GraphConflict[] }) {
  if (conflicts.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">
        No merge conflicts were detected during ingestion for this run.
      </div>
    );
  }
  return (
    <Card className="border-border/80">
      <CardContent className="p-3">
        <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          <AlertTriangle className="h-3.5 w-3.5 text-yellow-500" />
          Merge conflicts ({conflicts.length})
        </h3>
        <ul className="space-y-1.5">
          {conflicts.map((c, i) => (
            <li key={i} className="rounded border border-border/60 bg-card/40 px-2 py-1.5 text-xs">
              <div className="flex flex-wrap items-center gap-1.5">
                <Badge variant="outline" className="font-mono text-[10px]">{c.node_value}</Badge>
                <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                  {c.existing_confidence.toFixed(2)} → {c.proposed_confidence.toFixed(2)}
                </span>
              </div>
              <p className="mt-0.5 text-muted-foreground">{c.reason}</p>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
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
