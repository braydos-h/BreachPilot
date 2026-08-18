import ReactFlow, {
  Background,
  Controls,
  type Edge,
  type Node,
  Position,
} from "reactflow";
import "reactflow/dist/style.css";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, Network } from "lucide-react";
import { cn } from "@/lib/utils";
import { useRunGraph } from "@/api/hooks";
import { ApiError } from "@/api/client";
import type { GraphEdge, GraphNode } from "@/api/types";

// Interactive attack-path DAG. Renders the /api/v1/runs/{id}/graph response
// with reactflow (nodes = findings/creds/access/tools, edges = "enables").
// Replaces the hand-rolled linear SVG in AttackGraph.tsx when the graph
// route is enabled (api.graph_route=true). Falls back to a plain list when
// reactflow is unavailable or the route is disabled (404).

interface AttackGraphDagProps {
  runId: string;
  className?: string;
  height?: number;
}

const NODE_STYLE: Record<GraphNode["type"], { bg: string; border: string; label: string }> = {
  tool: { bg: "rgba(59,130,246,0.12)", border: "rgb(96,165,250)", label: "tool" },
  target: { bg: "rgba(168,85,247,0.12)", border: "rgb(192,132,252)", label: "target" },
  step: { bg: "rgba(16,185,129,0.12)", border: "rgb(52,211,153)", label: "step" },
};

function toFlowNodes(nodes: GraphNode[]): Node[] {
  // ponytail: simple column layout by type (tool left, target right, step
  // middle). A real auto-layout (dagre) is overkill for the small graphs a
  // single run produces; reactflow's built-in drag handles the rest.
  const byType: Record<string, number> = { tool: 0, step: 0, target: 0 };
  const xFor: Record<string, number> = { tool: 0, step: 280, target: 560 };
  return nodes.map((n) => {
    const y = byType[n.type] * 90;
    byType[n.type] += 1;
    const style = NODE_STYLE[n.type] ?? NODE_STYLE.tool;
    return {
      id: n.id,
      data: { label: n.label },
      position: { x: xFor[n.type] ?? 0, y },
      style: {
        background: style.bg,
        border: `1.5px solid ${style.border}`,
        borderRadius: 6,
        padding: 8,
        fontSize: 11,
        width: 160,
        fontFamily: "monospace",
      },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    };
  });
}

function toFlowEdges(edges: GraphEdge[]): Edge[] {
  return edges.map((e, i) => ({
    id: `e${i}-${e.source}-${e.target}`,
    source: e.source,
    target: e.target,
    label: e.relation,
    type: "smoothstep",
    animated: e.relation === "enables",
    style: { stroke: e.relation === "enables" ? "rgb(52,211,153)" : "rgb(148,163,184)" },
  }));
}

export function AttackGraphDag({ runId, className, height = 360 }: AttackGraphDagProps) {
  const { data, isLoading, error } = useRunGraph(runId);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading attack graph...
      </div>
    );
  }
  // 404 = route disabled (api.graph_route=false) or no graph yet. Render the
  // empty state rather than an error so the UI stays calm.
  if (error instanceof ApiError && error.isNotFound) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        Attack-path graph unavailable (enable <code>api.graph_route</code> in config.yaml).
      </div>
    );
  }
  if (error) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        Failed to load attack graph.
      </div>
    );
  }
  const nodes = data?.nodes ?? [];
  const edges = data?.edges ?? [];
  if (nodes.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        No attack-path nodes for this run yet.
      </div>
    );
  }

  const flowNodes = toFlowNodes(nodes);
  const flowEdges = toFlowEdges(edges);

  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex flex-wrap items-center gap-3">
        <Badge variant="outline" className="tabular-nums">{nodes.length} nodes</Badge>
        <Badge variant="outline" className="tabular-nums">{edges.length} edges</Badge>
        <span className="text-xs text-muted-foreground">drag to rearrange; scroll to zoom</span>
      </div>
      <Card className="border-border/60">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Network className="h-4 w-4" />
            Attack-Path DAG
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div style={{ height }} className="rounded-md border bg-background">
            <ReactFlow
              nodes={flowNodes}
              edges={flowEdges}
              fitView
              nodesDraggable
              zoomOnScroll
              panOnDrag
            >
              <Background gap={16} size={1} />
              <Controls showInteractive={false} />
            </ReactFlow>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}