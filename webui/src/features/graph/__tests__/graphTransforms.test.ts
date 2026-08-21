import { describe, expect, it } from "vitest";
import {
  NODE_STATUS_ORDER,
  NODE_TYPE_ORDER,
  nodeMatchesQuery,
  nodeTypeMeta,
  parseEvidenceRef,
  statusMeta,
  summaryChips,
  toFlowEdges,
  toFlowNodes,
} from "@/features/graph/graphTransforms";
import type { GraphExplorerEdge, GraphExplorerNode, GraphNodeStatus, GraphSummaryStats } from "@/features/graph/graphTypes";

function node(overrides: Partial<GraphExplorerNode> = {}): GraphExplorerNode {
  return {
    node_id: "run:r1|ip|10-0-0-5",
    node_type: "ip",
    value: "10.0.0.5",
    scope: "run:r1",
    properties: {},
    confidence: 0.5,
    first_seen: "2026-08-01T10:00:00Z",
    last_seen: "2026-08-01T10:00:00Z",
    evidence_refs: [],
    observation_count: 0,
    contradiction_count: 0,
    status: "unknown",
    source: "run",
    ...overrides,
  };
}

function edge(overrides: Partial<GraphExplorerEdge> = {}): GraphExplorerEdge {
  return {
    edge_id: "a->b|observed_on",
    source_node_id: "run:r1|observation|nmap",
    target_node_id: "run:r1|ip|10-0-0-5",
    edge_type: "observed_on",
    scope: "run:r1",
    properties: {},
    confidence: 0.5,
    source: "nmap",
    first_seen: "t",
    last_seen: "t",
    evidence_refs: [],
    observation_count: 0,
    contradiction_count: 0,
    ...overrides,
  };
}

describe("toFlowNodes", () => {
  it("maps node type/status/confidence onto typed reactflow nodes", () => {
    const nodes = [
      node({ node_id: "ip1", node_type: "ip", value: "10.0.0.5" }),
      node({ node_id: "f1", node_type: "finding", value: "F-1 · SQLi", status: "confirmed", confidence: 0.9 }),
    ];
    const flow = toFlowNodes(nodes);
    expect(flow).toHaveLength(2);
    expect(flow[0].id).toBe("ip1");
    expect(flow[0].data.node.value).toBe("10.0.0.5");
    // different node types land in different columns
    expect(flow[0].position.x).not.toBe(flow[1].position.x);
  });

  it("assigns unique stacking offsets within a type", () => {
    const nodes = [node({ node_id: "a", node_type: "finding" }), node({ node_id: "b", node_type: "finding" })];
    const flow = toFlowNodes(nodes);
    expect(flow[0].position.y).not.toBe(flow[1].position.y);
  });

  it("caps node width so the deterministic layout stays dense", () => {
    const flow = toFlowNodes([node({ node_type: "bogus" as GraphExplorerNode["node_type"] })]);
    expect(flow[0].style?.minWidth).toBe(150);
    expect(flow[0].style?.maxWidth).toBe(240);
  });
});

describe("toFlowEdges", () => {
  it("maps source/target/edge_type onto a labeled reactflow edge", () => {
    const e = toFlowEdges([edge()])[0];
    expect(e.source).toBe(edge().source_node_id);
    expect(e.target).toBe(edge().target_node_id);
    expect(e.label).toBe("observed_on");
    expect(e.type).toBe("smoothstep");
  });
});

describe("nodeMatchesQuery", () => {
  const n = node({
    value: "10.0.0.5",
    node_type: "finding",
    status: "confirmed",
    properties: { cvss_score: 9.8, severity: "critical", vuln_class: "SQL Injection" },
    evidence_refs: ["ev:nmap:10.0.0.5:abc:2026-01-01"],
  });

  it("matches value, type, status, properties and evidence refs", () => {
    expect(nodeMatchesQuery(n, "10.0.0.5")).toBe(true);
    expect(nodeMatchesQuery(n, "SQL Injection")).toBe(true);
    expect(nodeMatchesQuery(n, "9.8")).toBe(true);
    expect(nodeMatchesQuery(n, "confirmed")).toBe(true);
    expect(nodeMatchesQuery(n, "nmap")).toBe(true);
    expect(nodeMatchesQuery(n, "log4j")).toBe(false);
  });

  it("is case-insensitive and treats empty query as match-all", () => {
    expect(nodeMatchesQuery(n, "SQl iNjeCTion")).toBe(true);
    expect(nodeMatchesQuery(n, "")).toBe(true);
    expect(nodeMatchesQuery(n, "   ")).toBe(true);
  });
});

describe("parseEvidenceRef", () => {
  it("parses the ev:<tool>:<target>:<hash>:<timestamp> format", () => {
    const p = parseEvidenceRef("ev:nmap:10.0.0.5:abc123:2026-08-01");
    expect(p.tool).toBe("nmap");
    expect(p.target).toBe("10.0.0.5");
    expect(p.hash).toBe("abc123");
    expect(p.timestamp).toBe("2026-08-01");
  });

  it("is lenient with non-evidence strings (never crashes the UI)", () => {
    const p = parseEvidenceRef("plain-string");
    expect(p.tool).toBe("");
    expect(p.raw).toBe("plain-string");
  });
});

describe("metadata maps", () => {
  it("every real NodeType/status has a presentation entry", () => {
    for (const t of NODE_TYPE_ORDER) {
      const m = nodeTypeMeta(t);
      expect(m.label).toBeTruthy();
      expect(m.color).toMatch(/^rgb\(/);
    }
    for (const s of NODE_STATUS_ORDER) {
      expect(statusMeta(s).label).toBeTruthy();
    }
  });

  it("unknown status falls back to unknown label", () => {
    expect(statusMeta("definitely_fake" as GraphNodeStatus).label).toBe("Unknown");
  });
});

describe("summaryChips", () => {
  const stats: GraphSummaryStats = {
    hosts: 1,
    domains: 0,
    ips: 1,
    services: 2,
    findings: 3,
    hypotheses: 0,
    evidence: 2,
    observations: 4,
    vulnerability_candidates: 1,
    confirmed: 1,
    likely: 2,
    refuted: 0,
    highest_degree_node: null,
    conflict_count: 0,
  };
  it("summarizes the stat keys used by the UI", () => {
    const chips = summaryChips(stats);
    expect(chips.map((c) => c.label)).toEqual(["Nodes", "Hosts", "Services", "Findings", "Confirmed", "Hypotheses"]);
    expect(chips.find((c) => c.label === "Nodes")?.value).toBe(14); // 1+0+1+2+3+0+2+4+1
  });

  it("returns an empty list when stats are undefined", () => {
    expect(summaryChips(undefined)).toEqual([]);
  });
});
