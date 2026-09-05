import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlowProvider,
  useReactFlow,
  applyEdgeChanges,
  applyNodeChanges,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeChange,
  type Viewport,
} from "reactflow";
import "reactflow/dist/style.css";
import { cn } from "@/lib/utils";
import { GraphFlowNode, type GraphFlowNodeData } from "@/features/graph/GraphNodeTypes";
import { MAX_FLOW_EDGES, MAX_FLOW_NODES, edgeMeta, nodeTypeMeta, toFlowEdges, toFlowNodes } from "@/features/graph/graphTransforms";
import type { GraphExplorerEdge, GraphExplorerNode } from "@/features/graph/graphTypes";

const nodeTypes = { graph: GraphFlowNode };

/** Zoom at/above which non-essential edge labels become visible. */
const EDGE_LABEL_ZOOM = 0.6;

interface EdgeViewData {
  edgeType?: string;
}

export interface AttackGraphCanvasProps {
  nodes: GraphExplorerNode[];
  edges: GraphExplorerEdge[];
  selectedNodeId: string | null;
  onSelectNode: (id: string | null) => void;
  /** ids of nodes/edges to emphasize (attack path, search result) */
  pathNodeIds?: Set<string>;
  pathEdgeIds?: Set<string>;
  /** path overlay endpoints — visually distinct start/destination */
  pathStartNodeId?: string | null;
  pathEndNodeId?: string | null;
  /** non-null triggers a fit-to-node request (ts breaks ties for same id) */
  focusRequest?: { nodeId: string; ts: number } | null;
  /** increments to re-fit the whole graph (fit-to-screen button) */
  fitRequest?: number;
  /** increments to reset drag positions back to the deterministic layout */
  resetRequest?: number;
  /** toggle the reactflow minimap */
  showMinimap?: boolean;
  /** double-click a node to expand its neighborhood by one hop */
  onNodeDoubleClick?: (id: string) => void;
  className?: string;
}

function CanvasInner(props: AttackGraphCanvasProps) {
  const { fitView } = useReactFlow();
  const [flowNodes, setFlowNodes] = useState<Node[]>([]);
  const [flowEdges, setFlowEdges] = useState<Edge[]>([]);
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [hoverEdgeId, setHoverEdgeId] = useState<string | null>(null);
  const [edgeLabelsVisible, setEdgeLabelsVisible] = useState(true);
  const focusNodeRef = useRef<string | null>(null);
  const edgeLabelsVisibleRef = useRef(true);
  const lastFlowCount = useRef(0);
  const prevPathKey = useRef("");

  const baseNodes = useMemo(
    () => toFlowNodes(props.nodes).map((n) => ({ ...n, position: positions[n.id] ?? n.position })),
    [props.nodes, positions],
  );
  const baseEdges = useMemo(() => toFlowEdges(props.edges), [props.edges]);

  // Nodes/edges directly connected to the current selection (for emphasis).
  const connected = useMemo(() => {
    const nodes = new Set<string>();
    const edges = new Set<string>();
    const selectedId = props.selectedNodeId;
    if (selectedId) {
      for (const e of props.edges) {
        if (e.source_node_id === selectedId || e.target_node_id === selectedId) {
          edges.add(e.edge_id);
          nodes.add(e.source_node_id === selectedId ? e.target_node_id : e.source_node_id);
        }
      }
    }
    return { nodes, edges };
  }, [props.edges, props.selectedNodeId]);

  // Merge base + expanded nodes/edges into reactflow state. Only include an
  // edge when both endpoints are present (scope + graph consistency guaranteed
  // by the backend; this guard keeps a stray node-id from rendering a dangling
  // edge). Existing entries (drag positions, emphasis) are preserved.
  useEffect(() => {
    const prevNodes = new Map(flowNodes.map((n) => [n.id, n]));
    const nextNodes = new Map<string, Node>();
    for (const n of baseNodes) {
      nextNodes.set(n.id, prevNodes.get(n.id) ?? n);
    }
    const prevEdges = new Map(flowEdges.map((e) => [e.id, e]));
    const nextEdges = new Map<string, Edge>();
    for (const e of baseEdges) {
      if (nextNodes.has(e.source) && nextNodes.has(e.target)) {
        nextEdges.set(e.id, prevEdges.get(e.id) ?? e);
      }
    }
    setFlowNodes([...nextNodes.values()]);
    setFlowEdges([...nextEdges.values()]);
  }, [baseNodes, baseEdges]); // eslint-disable-line react-hooks/exhaustive-deps

  // Node emphasis: path / selection / focus context → data flags + dimming.
  useEffect(() => {
    const pathNodes = props.pathNodeIds;
    setFlowNodes((prev) =>
      prev.map((n) => {
        const id = n.id;
        const isPath = pathNodes?.has(id) ?? false;
        const isStart = isPath && props.pathStartNodeId === id;
        const isEnd = isPath && props.pathEndNodeId === id;
        const isFocus = focusNodeRef.current === id;
        const isSelected = props.selectedNodeId === id;
        let dimmed = false;
        if (pathNodes && pathNodes.size > 0) {
          dimmed = !isPath;
        } else if (props.selectedNodeId) {
          dimmed = !isSelected && !connected.nodes.has(id);
        }
        const data = n.data as GraphFlowNodeData;
        return {
          ...n,
          data: {
            ...data,
            node: data.node,
            path: isPath,
            focus: isFocus,
            start: isStart,
            end: isEnd,
            dimmed,
            selected: isSelected,
          },
          className: cn("transition-opacity", dimmed ? "opacity-40" : "opacity-100"),
        };
      }),
    );
  }, [props.pathNodeIds, props.pathStartNodeId, props.pathEndNodeId, props.selectedNodeId, connected.nodes]);

  // Edge emphasis: attack-path edges are prominent; selection-connected edges
  // are easier to trace; the rest dim to keep the selected path readable.
  useEffect(() => {
    const pathEdges = props.pathEdgeIds;
    setFlowEdges((prev) =>
      prev.map((e) => {
        const id = e.id;
        const isPath = pathEdges?.has(id) ?? false;
        const isConnected = connected.edges.has(id);
        const isHover = hoverEdgeId === id;
        const type = (e.data as EdgeViewData | undefined)?.edgeType ?? (e.label as string) ?? "related_to";
        const base = edgeMeta(type as GraphExplorerEdge["edge_type"]);
        const showLabel = isPath || isConnected || isHover || edgeLabelsVisible;

        let stroke = base.color;
        let width = 1.25;
        let dash: string | undefined = base.dashed ? "5 4" : undefined;
        let opacity = 0.85;
        if (isPath) {
          stroke = "rgb(52,211,153)";
          width = 2.75;
          opacity = 1;
          dash = undefined;
        } else if (pathEdges && pathEdges.size > 0) {
          opacity = 0.15;
        } else if (props.selectedNodeId) {
          if (isConnected) {
            width = 2;
            opacity = 1;
          } else {
            opacity = 0.3;
          }
        }

        return {
          ...e,
          label: showLabel ? type : "",
          style: { stroke, strokeWidth: width, opacity, ...(dash ? { strokeDasharray: dash } : {}) },
          markerEnd: { type: MarkerType.ArrowClosed, color: stroke } as unknown as Edge["markerEnd"],
        };
      }),
    );
  }, [props.pathEdgeIds, props.selectedNodeId, connected.edges, hoverEdgeId, edgeLabelsVisible]);

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

  // Zoom-level-dependent edge labels: show at a sufficient zoom, hide at a
  // distance so the graph doesn't become noise (labels still appear on hover
  // and for selected/path edges — see the emphasis effect).
  const updateLabelVisibility = useCallback((zoom: number) => {
    const on = zoom >= EDGE_LABEL_ZOOM;
    if (on !== edgeLabelsVisibleRef.current) {
      edgeLabelsVisibleRef.current = on;
      setEdgeLabelsVisible(on);
    }
  }, []);
  const onMove = useCallback(
    (_event: unknown, viewport: Viewport) => updateLabelVisibility(viewport.zoom),
    [updateLabelVisibility],
  );
  const onMoveEnd = useCallback(
    (_event: unknown, viewport: Viewport) => updateLabelVisibility(viewport.zoom),
    [updateLabelVisibility],
  );

  // Fit-to-screen request from the toolbar.
  useEffect(() => {
    if (props.fitRequest) void fitView({ padding: 0.15, duration: 300 });
  }, [props.fitRequest, fitView]);

  // Reset drag positions back to the deterministic layout.
  useEffect(() => {
    if (!props.resetRequest) return;
    setPositions({});
    setFlowNodes((nds) => {
      const baseById = new Map(baseNodes.map((b) => [b.id, b]));
      return nds.map((n) => ({ ...n, position: baseById.get(n.id)?.position ?? n.position }));
    });
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

  // Auto-fit the first time nodes arrive (graph load / run switch).
  useEffect(() => {
    if (lastFlowCount.current === 0 && flowNodes.length > 0) {
      void fitView({ padding: 0.15, duration: 300 });
    }
    lastFlowCount.current = flowNodes.length;
  }, [flowNodes.length, fitView]);

  // When a path overlay appears, frame the path.
  useEffect(() => {
    if (!props.pathNodeIds || props.pathNodeIds.size === 0) return;
    const key = [...props.pathNodeIds].sort().join("|");
    if (key === prevPathKey.current) return;
    prevPathKey.current = key;
    const pathNodes = flowNodes.filter((n) => props.pathNodeIds?.has(n.id));
    if (pathNodes.length) void fitView({ nodes: pathNodes, padding: 0.3, duration: 500 });
  }, [props.pathNodeIds, flowNodes, fitView]);

  const onPaneClick = useCallback(() => {
    props.onSelectNode(null);
  }, [props.onSelectNode]);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      if (e.key === "Escape") {
        props.onSelectNode(null);
        return;
      }
      if (e.key === "Enter" || e.key === " ") {
        const id = target?.closest?.("[data-id]")?.getAttribute("data-id");
        if (id) {
          e.preventDefault();
          props.onSelectNode(id);
        }
      }
    },
    [props.onSelectNode],
  );

  const minimapNodeColor = useCallback((node: Node) => {
    const data = node.data as GraphFlowNodeData | undefined;
    if (!data?.node) return "rgb(148,163,184)";
    return nodeTypeMeta(data.node.node_type).color;
  }, []);

  // ponytail: virtualization cap — memoized slices so reactflow never mounts
  // more DOM nodes than the transform ceiling (drag state stays in flowNodes).
  const displayNodes = useMemo(() => flowNodes.slice(0, MAX_FLOW_NODES), [flowNodes]);
  const displayEdges = useMemo(() => flowEdges.slice(0, MAX_FLOW_EDGES), [flowEdges]);

  return (
    <ReactFlow
      nodes={displayNodes}
      edges={displayEdges}
      nodeTypes={nodeTypes}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={(_, node) => props.onSelectNode(node.id)}
      onNodeDoubleClick={(_, node) => props.onNodeDoubleClick?.(node.id)}
      onPaneClick={onPaneClick}
      onEdgeMouseEnter={(_, edge) => setHoverEdgeId(edge.id)}
      onEdgeMouseLeave={() => setHoverEdgeId(null)}
      onMove={onMove}
      onMoveEnd={onMoveEnd}
      onKeyDown={onKeyDown}
      fitView={false}
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
      <Background
        variant={BackgroundVariant.Dots}
        gap={18}
        size={1}
        color="rgba(148,163,184,0.4)"
      />
      <Controls showInteractive={false} />
      {props.showMinimap !== false && (
        <MiniMap
          nodeColor={minimapNodeColor}
          nodeStrokeColor={minimapNodeColor}
          nodeBorderRadius={4}
          maskColor="rgba(2,6,23,0.6)"
          pannable
          zoomable
          ariaLabel="Graph minimap"
          className="!bottom-2 !right-2"
        />
      )}
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
