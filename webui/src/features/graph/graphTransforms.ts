// Pure transforms between the explorer API DTOs and reactflow / UI shapes.
// Nothing here mutates graph facts — it only maps them for display.

import type { Edge, Node, Position } from "reactflow";
import type {
  GraphExplorerEdge,
  GraphExplorerNode,
  GraphNodeStatus,
  GraphNodeType,
  GraphSummaryStats,
} from "@/features/graph/graphTypes";

// ── node/status presentation metadata ───────────────────────────────────────

const NODE_TYPE_META: Partial<Record<GraphNodeType, { label: string; color: string; bg: string }>> = {
  ip: { label: "IP", color: "rgb(96,165,250)", bg: "rgba(59,130,246,0.14)" },
  host: { label: "Host", color: "rgb(94,234,212)", bg: "rgba(45,212,191,0.14)" },
  domain: { label: "Domain", color: "rgb(94,234,212)", bg: "rgba(45,212,191,0.14)" },
  service: { label: "Service", color: "rgb(74,222,128)", bg: "rgba(34,197,94,0.14)" },
  port: { label: "Port", color: "rgb(74,222,128)", bg: "rgba(34,197,94,0.14)" },
  finding: { label: "Finding", color: "rgb(248,113,113)", bg: "rgba(239,68,68,0.14)" },
  vulnerability_candidate: { label: "Vuln", color: "rgb(251,146,60)", bg: "rgba(249,115,22,0.14)" },
  hypothesis: { label: "Hypothesis", color: "rgb(192,132,252)", bg: "rgba(168,85,247,0.14)" },
  evidence: { label: "Evidence", color: "rgb(251,191,36)", bg: "rgba(245,158,11,0.14)" },
  observation: { label: "Obs", color: "rgb(148,163,184)", bg: "rgba(100,116,139,0.14)" },
};

export function nodeTypeMeta(nodeType: GraphNodeType): { label: string; color: string; bg: string } {
  return (
    NODE_TYPE_META[nodeType] ?? {
      label: nodeType,
      color: "rgb(148,163,184)",
      bg: "rgba(100,116,139,0.14)",
    }
  );
}

const STATUS_META: Record<GraphNodeStatus, { label: string; color: string }> = {
  confirmed: { label: "Confirmed", color: "rgb(52,211,153)" },
  likely: { label: "Likely", color: "rgb(96,165,250)" },
  suspected: { label: "Suspected", color: "rgb(251,191,36)" },
  unknown: { label: "Unknown", color: "rgb(148,163,184)" },
  refuted: { label: "Refuted", color: "rgb(248,113,113)" },
  exhausted: { label: "Exhausted", color: "rgb(234,179,8)" },
};

export function statusMeta(status: GraphNodeStatus): { label: string; color: string } {
  return STATUS_META[status] ?? STATUS_META.unknown;
}

export const NODE_TYPE_ORDER: GraphNodeType[] = [
  "domain", "host", "ip", "service", "port", "endpoint",
  "application", "technology", "version", "identity", "role",
  "vulnerability_candidate", "finding", "hypothesis", "evidence",
  "observation", "capability", "security_control", "asset",
];

export const NODE_STATUS_ORDER: GraphNodeStatus[] = [
  "confirmed", "likely", "suspected", "unknown", "refuted", "exhausted",
];

// ── reactflow mapping ───────────────────────────────────────────────────────

interface FlowNodeData {
  label: string;
  node: GraphExplorerNode;
}

export function toFlowNodes(nodes: GraphExplorerNode[]): Node<FlowNodeData>[] {
  // Deterministic column-per-type grid. Fine up to the backend's 500-node
  // ceiling; reactflow handles pan/zoom/drag on top.
  const counts: Record<string, number> = {};
  const colOf = NODE_TYPES_ORDER.reduce((acc, t, i) => ({ ...acc, [t]: i }), {} as Record<string, number>);
  const xOf = (t: string) => (colOf[t] ?? NODE_TYPES_ORDER.length) * 250;
  return nodes.map((n) => {
    const meta = nodeTypeMeta(n.node_type);
    const y = (counts[n.node_type] ?? 0) * 86;
    counts[n.node_type] = (counts[n.node_type] ?? 0) + 1;
    return {
      id: n.node_id,
      data: { label: n.value, node: n },
      position: { x: xOf(n.node_type), y },
      style: {
        background: meta.bg,
        border: `1.5px solid ${meta.color}`,
        borderRadius: 8,
        padding: 6,
        fontSize: 11,
        fontFamily: "monospace",
        minWidth: 140,
        maxWidth: 240,
      },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    };
  });
}

export function toFlowEdges(edges: GraphExplorerEdge[]): Edge[] {
  return edges.map((e) => ({
    id: e.edge_id,
    source: e.source_node_id,
    target: e.target_node_id,
    label: e.edge_type,
    type: "smoothstep",
    style: { stroke: "rgb(148,163,184)", strokeWidth: 1.25 },
    labelStyle: { fontSize: 9, fill: "rgb(148,163,184)" },
    labelBgStyle: { fill: "rgba(15,23,42,0.7)", fillOpacity: 1 },
    labelBgPadding: [3, 2] as [number, number],
    labelBgBorderRadius: 3,
  }));
}

// ── search + evidence helpers ───────────────────────────────────────────────

/** Case-insensitive substring search across the fields operators search for. */
export function nodeMatchesQuery(node: GraphExplorerNode, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  const props = node.properties;
  const haystack = [
    node.value,
    node.node_type,
    node.status,
    node.source,
    node.node_id,
    ...node.evidence_refs,
    typeof props.cvss_score === "number" ? String(props.cvss_score) : "",
    typeof props.severity === "string" ? (props.severity as string) : "",
    typeof props.vuln_class === "string" ? (props.vuln_class as string) : "",
    ...(Array.isArray(props.tags) ? (props.tags as unknown[]).map(String) : []),
  ]
    .join("\n")
    .toLowerCase();
  return haystack.includes(needle);
}

/** Parse an evidence ref `ev:<tool>:<target>:<hash12>:<timestamp>` (lenient). */
export interface ParsedEvidenceRef {
  raw: string;
  tool: string;
  target: string;
  hash: string;
  timestamp: string;
}

export function parseEvidenceRef(ref: string): ParsedEvidenceRef {
  const parts = ref.split(":");
  return {
    raw: ref,
    tool: parts[0] === "ev" ? (parts[1] ?? "") : "",
    target: parts[0] === "ev" ? (parts[2] ?? "") : "",
    hash: parts[0] === "ev" ? (parts[3] ?? "") : "",
    timestamp: parts[0] === "ev" ? (parts[4] ?? "") : "",
  };
}

/** Rich summary chips for the stats bar. */
export function summaryChips(stats: GraphSummaryStats | undefined): Array<{ label: string; value: number; key: string }> {
  if (!stats) return [];
  return [
    { label: "Nodes", value: stats.hosts + stats.domains + stats.ips + stats.services + stats.findings + stats.hypotheses + stats.evidence + stats.observations + stats.vulnerability_candidates, key: "nodes" },
    { label: "Hosts", value: stats.hosts, key: "hosts" },
    { label: "Services", value: stats.services, key: "services" },
    { label: "Findings", value: stats.findings, key: "findings" },
    { label: "Confirmed", value: stats.confirmed, key: "confirmed" },
    { label: "Hypotheses", value: stats.hypotheses, key: "hypotheses" },
  ];
}
