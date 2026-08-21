// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { GraphDetailsPanel } from "@/features/graph/GraphDetailsPanel";
import { useGraphNode } from "@/features/graph/graphApi";
import type { GraphNodeDetail } from "@/features/graph/graphTypes";

vi.mock("@/features/graph/graphApi", async () => {
  const actual = await vi.importActual<typeof import("@/features/graph/graphApi")>("@/features/graph/graphApi");
  return { ...actual, useGraphNode: vi.fn() };
});

const mockedUseGraphNode = vi.mocked(useGraphNode);

function detail(overrides: Partial<GraphNodeDetail> = {}): GraphNodeDetail {
  return {
    node: {
      node_id: "run:r1|finding|f-1-sqli",
      node_type: "finding",
      value: "F-0001 · SQL injection in login",
      scope: "run:r1",
      properties: { cvss_score: 9.8, severity: "critical", vuln_class: "SQL Injection", exploitation_result: "verified" },
      confidence: 0.9,
      first_seen: "2026-08-01T10:00:00Z",
      last_seen: "2026-08-01T10:01:00Z",
      evidence_refs: ["ev:nmap:10.0.0.5:abc123:2026-08-01"],
      observation_count: 2,
      contradiction_count: 0,
      status: "confirmed",
      source: "enhanced_report",
    },
    edges: [
      {
        edge_id: "e1",
        source_node_id: "run:r1|node|f-1-sqli",
        target_node_id: "run:r1|evidence|ev-nmap-10-0-0-5",
        edge_type: "supported_by",
        scope: "run:r1",
        properties: {},
        confidence: 0.9,
        source: "enhanced_report",
        first_seen: "t",
        last_seen: "t",
        evidence_refs: [],
        observation_count: 0,
        contradiction_count: 0,
      },
    ],
    neighbors: [
      {
        node_id: "run:r1|evidence|ev-nmap-10-0-0-5",
        node_type: "evidence",
        value: "ev:nmap:10.0.0.5:abc123:2026-08-01",
        scope: "run:r1",
        properties: { evidence_id: "ev:nmap:10.0.0.5:abc123:2026-08-01" },
        confidence: 0.5,
        first_seen: "t",
        last_seen: "t",
        evidence_refs: [],
        observation_count: 0,
        contradiction_count: 0,
        status: "unknown",
        source: "evidence_refs",
      },
    ],
    ...overrides,
  };
}

function renderPanel(nodeId: string | null) {
  const onSelect = vi.fn();
  const onClose = vi.fn();
  render(
    <GraphDetailsPanel runId="r1" nodeId={nodeId} onSelect={onSelect} onClose={onClose} />,
  );
  return { onSelect, onClose };
}

beforeEach(() => {
  mockedUseGraphNode.mockReturnValue({ data: undefined, isLoading: false, error: null } as never);
});

describe("GraphDetailsPanel", () => {
  it("shows the empty state when no node is selected", () => {
    renderPanel(null);
    expect(screen.getByText(/select a node/i)).toBeInTheDocument();
  });

  it("renders only real metadata for a selected node", () => {
    mockedUseGraphNode.mockReturnValue({ data: detail(), isLoading: false, error: null } as never);
    renderPanel("run:r1|node|f-1-sqli");

    expect(screen.getByText("F-0001 · SQL injection in login")).toBeInTheDocument();
    expect(screen.getByText("Confirmed")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText("CVSS 9.8")).toBeInTheDocument();
    expect(screen.getByText("9.80")).toBeInTheDocument(); // confidence
    expect(screen.getByText("run:r1|node|f-1-sqli")).toBeInTheDocument();
    expect(screen.getByText("r1")).toBeInTheDocument(); // run id
    expect(screen.getByText("verified")).toBeInTheDocument(); // exploitation_result
    expect(screen.getByText("SQL Injection")).toBeInTheDocument(); // vuln_class
  });

  it("never fabricates missing severity/CVSS — absent props render no badge", () => {
    const d = detail();
    d.node.properties = {};
    mockedUseGraphNode.mockReturnValue({ data: d, isLoading: false, error: null } as never);
    renderPanel(d.node.node_id);
    expect(screen.queryByText(/cvss/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/critical/i)).not.toBeInTheDocument();
  });

  it("elaborates evidence refs into tool/target provenance", () => {
    mockedUseGraphNode.mockReturnValue({ data: detail(), isLoading: false, error: null } as never);
    renderPanel("run:r1|node|f-1-sqli");
    expect(screen.getByText("nmap")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.5")).toBeInTheDocument();
    expect(screen.getByText("2026-08-01")).toBeInTheDocument();
  });

  it("lists connected nodes grouped by edge type and jumps on click", async () => {
    const user = userEvent.setup();
    mockedUseGraphNode.mockReturnValue({ data: detail(), isLoading: false, error: null } as never);
    const { onSelect } = renderPanel("run:r1|node|f-1-sqli");
    expect(screen.getByText("supported_by")).toBeInTheDocument();
    // the ref also appears verbatim in the evidence/provenance list, so target
    // the connected-node button by role, not by text
    await user.click(screen.getByRole("button", { name: /ev:nmap:10\.0\.0\.5:abc123:2026-08-01/ }));
    expect(onSelect).toHaveBeenCalledWith("run:r1|evidence|ev-nmap-10-0-0-5");
  });

  it("shows a loading skeleton while fetching", () => {
    mockedUseGraphNode.mockReturnValue({ data: undefined, isLoading: true, error: null } as never);
    renderPanel("run:r1|node|f-1-sqli");
    expect(document.querySelector(".skeleton")).toBeTruthy();
  });

  it("surfaces load failures instead of crashing", () => {
    mockedUseGraphNode.mockReturnValue({ data: undefined, isLoading: false, error: new Error("boom") } as never);
    renderPanel("run:r1|node|f-1-sqli");
    expect(screen.getByText(/failed to load node/i)).toBeInTheDocument();
  });
});
