// React-query hooks for the AttackGraph explorer API.
// All query keys are prefixed `graphExplorer` so they are distinct from the
// legacy runGraph key. Live runs invalidate via the WS event broker's
// artifact event (see api/ws.ts patchCaches) — the graph is rebuilt lazily by
// the backend when artifact fingerprints change, so a light invalidation is
// all the UI needs.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect } from "react";
import { apiFetch, ApiError } from "@/api/client";
import { queryKeys } from "@/api/hooks";
import { isActiveState } from "@/api/types";
import type { RunDetail } from "@/api/types";
import type {
  GraphConflictsResponse,
  GraphNodeDetail,
  GraphNeighborsResponse,
  GraphPathsResponse,
  GraphRunResponse,
  GraphSummaryResponse,
} from "@/features/graph/graphTypes";

export const graphKeys = {
  all: (runId: string) => ["graphExplorer", runId] as const,
  graph: (runId: string, filters: string) => ["graphExplorer", runId, "graph", filters] as const,
  summary: (runId: string) => ["graphExplorer", runId, "summary"] as const,
  node: (runId: string, nodeId: string) => ["graphExplorer", runId, "nodes", nodeId] as const,
  neighbors: (runId: string, nodeId: string, hops: number, maxNodes: number) =>
    ["graphExplorer", runId, "neighbors", nodeId, hops, maxNodes] as const,
  paths: (runId: string, start: string, end: string, len: number, count: number) =>
    ["graphExplorer", runId, "paths", start, end, len, count] as const,
  conflicts: (runId: string) => ["graphExplorer", runId, "conflicts"] as const,
};

const GRAPH_OPTS = {
  retry: (count: number, error: unknown) => {
    // 404 = route disabled (api.graph_route=false) or run has no graph yet.
    if (error instanceof ApiError && error.isNotFound) return false;
    return count < 2;
  },
  staleTime: 5_000,
  gcTime: 5 * 60_000,
};

interface GraphFilters {
  nodeTypes?: string[];
  statuses?: string[];
  q?: string;
  limit?: number;
}

export function useGraphRun(runId: string | null | undefined, filters: GraphFilters = {}, enabled = true) {
  const { nodeTypes = [], statuses = [], q = "", limit = 300 } = filters;
  const params = new URLSearchParams();
  nodeTypes.forEach((t) => params.append("node_type", t));
  statuses.forEach((s) => params.append("status", s));
  if (q) params.set("q", q);
  if (limit !== 300) params.set("limit", String(limit));
  const qs = params.toString();

  return useQuery<GraphRunResponse>({
    queryKey: graphKeys.graph(runId ?? "", qs),
    queryFn: () => apiFetch<GraphRunResponse>(`/graph/runs/${encodeURIComponent(runId as string)}${qs ? `?${qs}` : ""}`),
    ...GRAPH_OPTS,
    enabled: !!runId && enabled,
  });
}

export function useGraphSummary(runId: string | null | undefined, enabled = true) {
  return useQuery<GraphSummaryResponse>({
    queryKey: graphKeys.summary(runId ?? ""),
    queryFn: () => apiFetch<GraphSummaryResponse>(`/graph/runs/${encodeURIComponent(runId as string)}/summary`),
    ...GRAPH_OPTS,
    enabled: !!runId && enabled,
  });
}

export function useGraphConflicts(runId: string | null | undefined, enabled = true) {
  return useQuery<GraphConflictsResponse>({
    queryKey: graphKeys.conflicts(runId ?? ""),
    queryFn: () => apiFetch<GraphConflictsResponse>(`/graph/runs/${encodeURIComponent(runId as string)}/conflicts`),
    ...GRAPH_OPTS,
    enabled: !!runId && enabled,
  });
}

export function useGraphNode(runId: string | null | undefined, nodeId: string | null, enabled = true) {
  return useQuery<GraphNodeDetail>({
    queryKey: graphKeys.node(runId ?? "", nodeId ?? ""),
    queryFn: () =>
      apiFetch<GraphNodeDetail>(
        `/graph/runs/${encodeURIComponent(runId as string)}/nodes/${encodeURIComponent(nodeId as string)}`,
      ),
    ...GRAPH_OPTS,
    enabled: !!runId && !!nodeId && enabled,
  });
}

export function useGraphNeighbors(
  runId: string | null | undefined,
  nodeId: string | null,
  maxHops = 1,
  maxNodes = 50,
  enabled = true,
) {
  return useQuery<GraphNeighborsResponse>({
    queryKey: graphKeys.neighbors(runId ?? "", nodeId ?? "", maxHops, maxNodes),
    queryFn: () =>
      apiFetch<GraphNeighborsResponse>(
        `/graph/runs/${encodeURIComponent(runId as string)}/nodes/${encodeURIComponent(nodeId as string)}/neighbors` +
          `?max_hops=${maxHops}&max_nodes=${maxNodes}`,
      ),
    ...GRAPH_OPTS,
    enabled: !!runId && !!nodeId && enabled,
  });
}

export function useGraphPaths(
  runId: string | null | undefined,
  start: string | null,
  end: string | null,
  maxLength = 4,
  maxPaths = 5,
  enabled = true,
) {
  return useQuery<GraphPathsResponse>({
    queryKey: graphKeys.paths(runId ?? "", start ?? "", end ?? "", maxLength, maxPaths),
    queryFn: () => {
      const params = new URLSearchParams({ start: start as string, end: end as string });
      if (maxLength !== 4) params.set("max_length", String(maxLength));
      if (maxPaths !== 5) params.set("max_paths", String(maxPaths));
      return apiFetch<GraphPathsResponse>(
        `/graph/runs/${encodeURIComponent(runId as string)}/paths?${params.toString()}`,
      );
    },
    ...GRAPH_OPTS,
    enabled: !!runId && !!start && !!end && enabled,
  });
}

/** Invalidate every graph-explorer query for a run (called after WS events). */
export function useInvalidateGraph(runId: string) {
  const qc = useQueryClient();
  return useCallback(() => {
    void qc.invalidateQueries({ queryKey: graphKeys.all(runId) });
  }, [qc, runId]);
}

/** Poll the explorer graph only while the run is in an active state. */
export function useGraphPolling(runId: string | null | undefined, enabled = true) {
  const qc = useQueryClient();
  const { data: run } = useQuery<RunDetail>({
    queryKey: queryKeys.run(runId ?? ""),
    enabled: !!runId,
    staleTime: 15_000,
  });
  const active = !!run && isActiveState(run.state);

  // Lightweight: while active, refetch the graph queries every 10s so new
  // audit/report artifacts show up without streaming the whole graph.
  useEffect(() => {
    if (!enabled || !active || !runId) return;
    const timer = setInterval(() => {
      void qc.invalidateQueries({ queryKey: graphKeys.all(runId) });
    }, 10_000);
    return () => clearInterval(timer);
  }, [qc, runId, active, enabled]);
  return active;
}
