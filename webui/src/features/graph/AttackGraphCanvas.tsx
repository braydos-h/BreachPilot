import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  ReactFlowProvider,
  useReactFlow,
  applyEdgeChanges,
  applyNodeChanges,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeChange,
} from "reactflow";
import "reactflow/dist/style.css";
import { cn } from "@/lib/utils";
import { GraphFlowNode, type GraphFlowNodeData } from "@/features/graph/GraphNodeTypes";
import { toFlowEdges, toFlowNodes } from "@/features/graph/graphTransforms";
import type { GraphExplorerEdge, GraphExplorerNode } from "@/features/graph/graphTypes";

const nodeTypes = { graph: GraphFlowNode };

export interface AttackGraphCanvasProps {
  nodes: GraphExplorerNode[];
  edges: GraphExplorerEdge[];
  selectedNodeId: string | null;
  onSelectNode: (id: string | null) => void;
  /** ids of nodes/edges to emphasize (attack path, search result) */
  pathNodeIds?: Set<string>;
  pathEdgeIds?: Set<string>;
  /** non-null triggers a fit-to-node request (ts breaks ties for same id) */
  focusRequest?: { nodeId: string; ts: number } | null;
  /** increments to re-fit the whole graph (fit-to-screen button) */
  fitRequest?: number;
  /** increments to reset drag positions back to the deterministic layout */
  resetRequest?: number;
  className?: string;
}

function CanvasInner(props: AttackGraphCanvasProps) {
  const { fitView } = useReactFlow();
  const [flowNodes, setFlowNodes] = useState<Node[]>([]);
  const [flowEdges, setFlowEdges] = useState<Edge[]>([]);
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const focusNodeRef = useRef<string | null>(null);

  const baseNodes = useMemo(
    () => toFlowNodes(props.nodes).map((n) => ({ ...n, position: positions[n.id] ?? n.position })),
    [props.nodes, positions],
  );
  const baseEdges = useMemo(() => toFlowEdges(props.edges), [props.edges]);

  // Merge base + expanded edges into reactflow state. Only include an edge
  // when both endpoints are present (scope + graph consistency guaranteed by
  // the backend; this guard keeps a stray node-id from rendering a dangling edge).
  useEffect(() => {
    const nextNodes = new Map<string, Node>();
    baseNodes.forEach((n) => {
      const prev = flowNodes.find((p) => p.id === n.id);
      nextNodes.set(n.id, prev ?? n);
    });
    const nextEdges = new Map<string, Edge>();
    baseEdges.forEach((e) => {
      if (nextNodes.has(e.source) && nextNodes.has(e.target)) nextEdges.set(e.id, e);
    });
    setFlowNodes([...nextNodes.values()]);
    setFlowEdges([...nextEdges.values()]);
  }, [baseNodes, baseEdges]); // eslint-disable-line react-hooks/exhaustive-deps

  // Path / focus emphasis. Dims non-path nodes when a path is shown; focused
  // (search-result) node gets a pulsing highlight via a data flag.
  useEffect(() => {
    setFlowNodes((prev) =>
      prev.map((n) => {
        const isPath = props.pathNodeIds?.has(n.id) ?? false;
        const isFocus = focusNodeRef.current === n.id;
        const data = n.data as GraphFlowNodeData;
        const dimmed = props.pathNodeIds && props.pathNodeIds.size > 0 && !isPath;
        return {
          ...n,
          data: { ...data, node: data.node, path: isPath, focus: isFocus },
          className: cn("transition-opacity", dimmed ? "opacity-40" : "opacity-100"),
        };
      }),
    );
  }, [props.pathNodeIds, props.selectedNodeId]);

  // Emphasis edges: path edges get a brighter stroke.
  useEffect(() => {
    setFlowEdges((prev) =>
      prev.map((e) => {
        const isPath = props.pathEdgeIds?.has(e.id) ?? false;
        return {
          ...e,
          style: isPath
            ? { stroke: "rgb(52,211,153)", strokeWidth: 2.25 }
            : { stroke: "rgb(148,163,184)", strokeWidth: 1.25 },
        };
      }),
    );
  }, [props.pathEdgeIds, props.pathNodeIds]);

  const onNodesChange = useCallback((changes: NodeChange[]) => {
    setFlowNodes((nds) => applyNodeChanges(changes, nds));
    const moved = changes.filter((c) => c.type === "position" && c.position);
    if (moved.length) {
      setPositions((prev) => {
        const next = { ...prev };
        for (const c of moved as Array<{ id: string; position?: { x: number; y: number } }>) {
          if (c.position) next[c.id] = c.position;
        }
        return next;
      });
    }
  }, []);
  const onEdgesChange = useCallback((changes: EdgeChange[]) => {
    setFlowEdges((eds) => applyEdgeChanges(changes, eds));
  }, []);

  // Fit-to-screen request from the toolbar.
  useEffect(() => {
    if (props.fitRequest) void fitView({ padding: 0.15, duration: 300 });
  }, [props.fitRequest, fitView]);

  // Reset drag positions back to the deterministic layout.
  useEffect(() => {
    if (!props.resetRequest) return;
    setPositions({});
    setFlowNodes((nds) => nds.map((n) => ({ ...n, position: (baseNodes.find((b) => b.id === n.id) ?? n).position })));
  }, [props.resetRequest]); // eslint-disable-line react-hooks/exhaustive-deps

  // Focus a specific node (search result / path endpoint).
  useEffect(() => {
    if (!props.focusRequest) return;
    focusNodeRef.current = props.focusRequest.nodeId;
    const node = flowNodes.find((n) => n.id === props.focusRequest?.nodeId);
    if (node) {
      void fitView({ nodes: [node], duration: 350, padding: 0.4 });
      setTimeout(() => { focusNodeRef.current = null; }, 800);
    } else {
      void fitView({ padding: 0.15 });
    }
  }, [props.focusRequest?.ts]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <ReactFlow
      nodes={flowNodes}
      edges={flowEdges}
      nodeTypes={nodeTypes}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={(_, node) => props.onSelectNode(node.id)}
      onPaneClick={() => props.onSelectNode(null)}
      onKeyDown={(e) => {
        // Keyboard selection: nodes render as focusable [data-id] elements.
        if (e.key === "Enter" || e.key === " ") {
          const id = (e.target as HTMLElement).getAttribute?.("data-id");
          if (id) {
            e.preventDefault();
            props.onSelectNode(id);
          }
        }
      }}
      fitView
      fitViewOptions={{ padding: 0.15 }}
      nodesDraggable
      nodesConnectable={false}
      elementsSelectable
      panOnDrag
      zoomOnScroll
      minZoom={0.1}
      maxZoom={2.5}
      className={props.className}
      deleteKeyCode={null}
    >
      <Background variant={BackgroundVariant.Dots} gap={18} size={1} />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}

export function AttackGraphCanvas(props: AttackGraphCanvasProps) {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} />
    </ReactFlowProvider>
  );
}
