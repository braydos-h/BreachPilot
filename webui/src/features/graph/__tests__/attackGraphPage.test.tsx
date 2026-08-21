// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AttackGraphPage } from "@/features/graph/AttackGraphPage";
import { ApiError } from "@/api/client";
import type { GraphExplorerNode } from "@/features/graph/graphTypes";

// ── module mocks ────────────────────────────────────────────────────────────

vi.mock("@/features/graph/graphApi", () => ({
  useGraphRun: vi.fn(),
  useGraphSummary: vi.fn(),
  useGraphConflicts: vi.fn(),
  useGraphNeighbors: vi.fn(),
  useGraphPolling: vi.fn(),
  useGraphNode: vi.fn(),
}));
vi.mock("@/features/graph/AttackGraphCanvas", () => ({
  AttackGraphCanvas: (props: { nodes: GraphExplorerNode[]; focusRequest?: { nodeId: string } | null }) => (
    <div
      data-testid="canvas"
      data-nodes={String(props.nodes.length)}
      data-focus={props.focusRequest?.nodeId ?? ""}
    />
  ),
}));
vi.mock("@/api/hooks", () => ({
  useRuns: vi.fn(),
}));

import {
  useGraphRun,
  useGraphSummary,
  useGraphConflicts,
  useGraphNeighbors,
  useGraphPolling,
  useGraphNode,
} from "@/features/graph/graphApi";
import { useRuns } from "@/api/hooks";

const graphRunMock = vi.mocked(useGraphRun);
const graphSummaryMock = vi.mocked(useGraphSummary);
const graphConflictsMock = vi.mocked(useGraphConflicts);
const graphNeighborsMock = vi.mocked(useGraphNeighbors);
const graphPollingMock = vi.mocked(useGraphPolling);
const graphNodeMock = vi.mocked(useGraphNode);
const useRunsMock = vi.mocked(useRuns);

// ── fixtures ────────────────────────────────────────────────────────────────

const ipNode: GraphExplorerNode = {
  node_id: "run:r1|ip|10-0-0-5",
  node_type: "ip",
  value: "10.0.0.5",
  scope: "run:r1",
  properties: {},
  confidence: 0.9,
  first_seen: "t",
  last_seen: "t",
  evidence_refs: [],
  observation_count: 0,
  contradiction_count: 0,
  status: "unknown",
  source: "run",
};

const findingNode: GraphExplorerNode = {
  ...ipNode,
  node_id: "run:r1|finding|f-1-sqli",
  node_type: "finding",
  value: "F-0001 · SQL injection in login",
  properties: { cvss_score: 9.8, severity: "critical" },
  status: "confirmed",
  confidence: 0.9,
  source: "enhanced_report",
};

const observationNode: GraphExplorerNode = {
  ...ipNode,
  node_id: "run:r1|observation|sqlmap-on-10-0-0-5",
  node_type: "observation",
  value: "sqlmap on 10.0.0.5",
  properties: { tool: "sqlmap" },
  status: "unknown",
  source: "exploit_audit",
};

const graphResponse = {
  run_id: "r1",
  scope: "run:r1",
  nodes: [ipNode, findingNode],
  edges: [{
    edge_id: "run:r1|edge|e1",
    source_node_id: ipNode.node_id,
    target_node_id: findingNode.node_id,
    edge_type: "affected_by",
    scope: "run:r1",
    properties: {},
    confidence: 0.5,
    source: "enhanced_report",
    first_seen: "t",
    last_seen: "t",
    evidence_refs: [],
    observation_count: 0,
    contradiction_count: 0,
  }],
  total_nodes: 2,
  truncated: false,
};

const summaryResponse = {
  run_id: "r1",
  summary: { nodes: {}, edges: {}, total_nodes: 2, total_edges: 1 },
  stats: {
    hosts: 0, domains: 0, ips: 1, services: 0, findings: 1, hypotheses: 0, evidence: 0,
    observations: 1, vulnerability_candidates: 0, confirmed: 1, likely: 0, refuted: 0,
    highest_degree_node: null, conflict_count: 0,
  },
};

const runRow = {
  id: "r1", state: "completed" as const, created_at: "t", target: "10.0.0.5",
  mode: "attack" as const, goal_name: "backdoor", target_ip: "10.0.0.5", model_alias: "glm",
};

beforeEach(() => {
  vi.clearAllMocks();
  graphPollingMock.mockReturnValue(false as never);
  graphRunMock.mockImplementation(((runId: string | null) =>
    runId
      ? { data: graphResponse, isLoading: false, error: null }
      : { data: undefined, isLoading: false, error: null }) as never);
  graphSummaryMock.mockReturnValue({ data: summaryResponse, isLoading: false, error: null } as never);
  graphConflictsMock.mockReturnValue({ data: { run_id: "r1", conflicts: [] }, isLoading: false, error: null } as never);
  graphNeighborsMock.mockReturnValue({ data: undefined, isLoading: false, isError: false, error: null } as never);
  graphNodeMock.mockReturnValue({ data: undefined, isLoading: false, error: null } as never);
  useRunsMock.mockReturnValue({ data: { runs: [runRow] }, isLoading: false, error: null } as never);
});

async function renderPage() {
  const user = userEvent.setup();
  render(<AttackGraphPage />);
  return { user };
}

async function selectRun(user: ReturnType<typeof userEvent.setup>) {
  await user.selectOptions(screen.getByLabelText(/run \(scope\)/i), "r1");
}

describe("AttackGraphPage", () => {
  it("prompts for a run before loading any graph", () => {
    renderPage();
    expect(screen.getByText(/select a run to load its attack graph/i)).toBeInTheDocument();
    expect(screen.queryByTestId("canvas")).not.toBeInTheDocument();
  });

  it("loads the graph + stats once a run is selected", async () => {
    const { user } = renderPage();
    await selectRun(user);
    const canvas = screen.getByTestId("canvas");
    await waitFor(() => expect(canvas.getAttribute("data-nodes")).toBe("2"));
    expect(screen.getByRole("list", { name: /graph statistics/i })).toBeInTheDocument();
  });

  it("renders an empty state when the run has no nodes", async () => {
    graphRunMock.mockReturnValue({
      data: { ...graphResponse, nodes: [], edges: [], total_nodes: 0, truncated: false },
      isLoading: false,
      error: null,
    } as never);
    const { user } = renderPage();
    await selectRun(user);
    expect(screen.getByText(/no graph nodes for this run yet/i)).toBeInTheDocument();
  });

  it("surfaces the disabled-route error instead of a blank canvas", async () => {
    graphRunMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError({ status: 404, code: "graph_disabled", message: "Graph route disabled (api.graph_route=false)", details: {}, requestId: "", raw: null }),
    } as never);
    const { user } = renderPage();
    await selectRun(user);
    expect(screen.getByText(/graph route is disabled/i)).toBeInTheDocument();
  });

  it("warns when the graph is large (truncated flag)", async () => {
    graphRunMock.mockReturnValue({
      data: { ...graphResponse, truncated: true, total_nodes: 1200 },
      isLoading: false,
      error: null,
    } as never);
    const { user } = renderPage();
    await selectRun(user);
    expect(screen.getByText(/graph is large/i)).toBeInTheDocument();
  });

  it("shows node details after selecting a node via focus search", async () => {
    const { user } = renderPage();
    await selectRun(user);
    const input = screen.getByLabelText(/find node in graph/i);
    await user.type(input, "SQL injection");
    const jump = await screen.findByRole("button", { name: /focus f-0001/i });
    await user.click(jump);
    // focus request reaches the canvas
    const canvas = screen.getByTestId("canvas");
    expect(canvas.getAttribute("data-focus")).toBe(findingNode.node_id);
  });

  it("merges a neighborhood expansion into the view when +1 hop is clicked", async () => {
    const extra: GraphExplorerNode = { ...ipNode, node_id: "run:r1|service|ssh", node_type: "service", value: "ssh" };
    graphNeighborsMock.mockImplementation(() =>
      ({
        data: { run_id: "r1", start_node: ipNode, nodes: [ipNode, extra], edges: [] },
        isLoading: false,
        isError: false,
        error: null,
      }) as never);
    const { user } = renderPage();
    await selectRun(user);
    // select a node first (focus search sets selection)
    await user.type(screen.getByLabelText(/find node in graph/i), "10.0.0.5");
    await user.click(await screen.findByRole("button", { name: /focus 10\.0\.0\.5/i }));
    const before = screen.getByTestId("canvas").getAttribute("data-nodes");
    await user.click(screen.getByRole("button", { name: /expand neighborhood of selected node by one hop/i }));
    await waitFor(() => expect(screen.getByTestId("canvas").getAttribute("data-nodes")).not.toBe(before));
    expect(screen.getByTestId("canvas").getAttribute("data-nodes")).toBe(String(Number(before) + 1));
  });

  it("shows merge-conflict visibility when the conflicts panel is opened", async () => {
    graphConflictsMock.mockReturnValue({
      data: { run_id: "r1", conflicts: [{ node_value: "10.0.0.5", reason: "type conflict: proposed as host, existing as ip", existing_confidence: 0.5, proposed_confidence: 0.6, node_id: "", scope: "run:r1", built_at: "t" }] },
      isLoading: false,
      error: null,
    } as never);
    const { user } = renderPage();
    await selectRun(user);
    await user.click(screen.getByRole("button", { name: /merge conflicts/i }));
    expect(screen.getByText(/type conflict/i)).toBeInTheDocument();
  });
});
