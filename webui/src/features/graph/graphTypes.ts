// Types for the AttackGraph explorer API (/api/v1/graph/runs/...).
//
// These mirror the backend's GraphNode/GraphEdge to_dict() shape exactly
// (tools/intelligence/graph/types.py). Node types/statuses are the real
// repository enums — never invent a node_type here. Properties may carry
// severity/CVSS/CVE only when the backend actually produced them.

export type GraphNodeType =
  | "asset" | "host" | "domain" | "ip" | "service" | "port"
  | "endpoint" | "application" | "technology" | "version" | "identity"
  | "role" | "credential_reference" | "trust_boundary" | "network_segment"
  | "vulnerability_candidate" | "finding" | "hypothesis" | "evidence"
  | "capability" | "security_control" | "observation";

export type GraphEdgeType =
  | "resolves_to" | "hosts" | "exposes" | "runs" | "depends_on"
  | "reachable_from" | "authenticates_to" | "has_role" | "trusts"
  | "related_to" | "supported_by" | "contradicted_by" | "derived_from"
  | "affected_by" | "protected_by" | "connected_to" | "same_as"
  | "observed_on";

export type GraphNodeStatus =
  | "unknown" | "suspected" | "likely" | "confirmed" | "refuted" | "exhausted";

export interface GraphExplorerNode {
  node_id: string;
  node_type: GraphNodeType;
  value: string;
  scope: string;
  properties: Record<string, unknown>;
  confidence: number;
  first_seen: string;
  last_seen: string;
  evidence_refs: string[];
  observation_count: number;
  contradiction_count: number;
  status: GraphNodeStatus;
  source: string;
}

export interface GraphExplorerEdge {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: GraphEdgeType;
  scope: string;
  properties: Record<string, unknown>;
  confidence: number;
  source: string;
  first_seen: string;
  last_seen: string;
  evidence_refs: string[];
  observation_count: number;
  contradiction_count: number;
}

export interface GraphRunResponse {
  run_id: string;
  scope: string;
  nodes: GraphExplorerNode[];
  edges: GraphExplorerEdge[];
  total_nodes: number;
  truncated: boolean;
}

export interface GraphSummaryStats {
  hosts: number;
  domains: number;
  ips: number;
  services: number;
  findings: number;
  hypotheses: number;
  evidence: number;
  observations: number;
  vulnerability_candidates: number;
  confirmed: number;
  likely: number;
  refuted: number;
  highest_degree_node: { node_id: string; value: string; node_type: GraphNodeType; degree: number } | null;
  conflict_count: number;
}

export interface GraphSummaryResponse {
  run_id: string;
  summary: {
    nodes: Record<string, number>;
    edges: Record<string, number>;
    total_nodes: number;
    total_edges: number;
  };
  stats: GraphSummaryStats;
}

export interface GraphConflict {
  node_value: string;
  reason: string;
  existing_confidence: number;
  proposed_confidence: number;
  node_id: string;
  scope: string;
  built_at: string;
}

export interface GraphConflictsResponse {
  run_id: string;
  conflicts: GraphConflict[];
}

export interface GraphNodeDetail {
  node: GraphExplorerNode;
  edges: GraphExplorerEdge[];
  neighbors: GraphExplorerNode[];
}

export interface GraphNeighborsResponse {
  run_id: string;
  start_node: GraphExplorerNode | null;
  nodes: GraphExplorerNode[];
  edges: GraphExplorerEdge[];
}

export interface GraphPathStep {
  distance: number;
  node: GraphExplorerNode;
  edge: GraphExplorerEdge;
}

export interface GraphPathsResponse {
  run_id: string;
  paths: GraphPathStep[][];
}
