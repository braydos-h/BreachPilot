// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider, useMutation, useQuery } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { EvidenceTab } from "./EvidenceTab";
import { ApiError } from "@/api/client";
import type { DecideFindingResponse, ProposedResponse, ProposedFinding } from "@/api/types";
import { useDecideFinding, useProposed } from "@/api/hooks";

vi.mock("@/api/hooks", () => ({ useDecideFinding: vi.fn(), useProposed: vi.fn() }));

function finding(title: string, approval: string, verification: string, retest = ""): ProposedFinding {
  return {
    finding_id: title, title, affected_asset: "10.0.0.50", severity: "Medium",
    vuln_class: "test", summary: "", confidence: 0.5, hitl_status: approval, hitl_history: [],
    proof: {
      finding_id: title, probe_exec: "", output_excerpt: "", proof_sha256: "", proof_runs: 3,
      verify_status: verification, verify_detail: "", retest_status: retest, retest_detail: "",
    },
  };
}

const findings = [
  finding("Awaiting candidate", "PROPOSED", "HOLDING"),
  finding("Approved unverified", "APPROVED", "HOLDING"),
  finding("Machine verified", "PROPOSED", "verified"),
  finding("Ambiguous probe", "APPROVED", "inconclusive"),
  finding("Ambiguous retest", "APPROVED", "HOLDING", "inconclusive"),
  finding("Rejected candidate", "REJECTED", "HOLDING"),
  finding("Fixed candidate", "APPROVED", "HOLDING", "fixed"),
];

function setup(path = "/runs/run-1") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><EvidenceTab runId="run-1" /></MemoryRouter></QueryClientProvider>);
}

describe("EvidenceTab lifecycle", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useProposed).mockImplementation(() => useQuery<ProposedResponse>({
      queryKey: ["proposed-test"],
      queryFn: async () => ({ run_id: "run-1", proposed: findings }),
      initialData: { run_id: "run-1", proposed: findings },
      enabled: false,
    }));
    vi.mocked(useDecideFinding).mockImplementation(() => useMutation<DecideFindingResponse, ApiError, { findingId: string; decision: string; note?: string }>({
      mutationFn: async () => { throw new Error("Unexpected finding decision in a read-only test"); },
    }));
  });

  it.each([
    ["Awaiting review", ["Awaiting candidate", "Machine verified"]],
    ["Approved", ["Approved unverified", "Ambiguous probe", "Ambiguous retest", "Fixed candidate"]],
    ["Verified", ["Machine verified"]],
    ["Inconclusive", ["Ambiguous probe", "Ambiguous retest"]],
    ["Rejected", ["Rejected candidate"]],
    ["Fixed", ["Fixed candidate"]],
  ])("filters %s by its actual lifecycle evidence", async (label, expected) => {
    const user = userEvent.setup();
    setup();
    const filters = screen.getByRole("group", { name: "Finding lifecycle filter" });
    const button = within(filters).getByRole("button", { name: label });
    await user.click(button);
    expect(button).toHaveAttribute("aria-pressed", "true");
    for (const candidate of findings) {
      if (expected.includes(candidate.title)) expect(screen.getByText(candidate.title)).toBeInTheDocument();
      else expect(screen.queryByText(candidate.title)).not.toBeInTheDocument();
    }
    await user.click(within(filters).getByRole("button", { name: "All" }));
    for (const candidate of findings) expect(screen.getByText(candidate.title)).toBeInTheDocument();
  });

  it("applies deep-linked lifecycle and text filters together", () => {
    setup("/runs/run-1?lifecycle=inconclusive&q=retest");
    expect(screen.getByText("Ambiguous retest")).toBeInTheDocument();
    expect(screen.queryByText("Ambiguous probe")).not.toBeInTheDocument();
    expect(screen.queryByText("Approved unverified")).not.toBeInTheDocument();
  });

  it("treats unknown URL filters as All", () => {
    setup("/runs/run-1?lifecycle=unsupported");
    expect(screen.getByRole("button", { name: "All" })).toHaveAttribute("aria-pressed", "true");
    for (const candidate of findings) expect(screen.getByText(candidate.title)).toBeInTheDocument();
  });

  it("does not represent requested proof trials as passed trials", async () => {
    const user = userEvent.setup();
    setup();
    await user.click(screen.getByRole("button", { name: /Approved unverified/ }));
    expect(screen.getByText("Requested proof trials: 3")).toBeInTheDocument();
    expect(screen.getByText("Verification: HOLDING")).toBeInTheDocument();
    expect(screen.queryByText(/Proof passed/)).not.toBeInTheDocument();
    expect(screen.queryByText("Proof passed 3/3")).not.toBeInTheDocument();
  });
});
