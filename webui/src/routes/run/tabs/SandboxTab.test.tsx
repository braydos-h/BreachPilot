// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { SandboxTab } from "@/routes/run/tabs/SandboxTab";
import type { RunSandboxResponse } from "@/api/types";

function sandboxData(overrides: Partial<RunSandboxResponse> = {}): RunSandboxResponse {
  return {
    run_id: "run1",
    found: true,
    config: { enabled: true, backend: "docker", image: "breachpilot-sandbox:latest", user: "sandbox" },
    container: { id: "abc123def4567890", sandbox_run_id: "sandboxrun1" },
    network: {
      enforced: true,
      fingerprint: "fp-abc",
      authorized_destinations: ["10.0.0.50/32"],
      explicitly_blocked: ["169.254.169.254/32"],
      resolved_domains: { "github.com": "140.82.121.4" },
      unresolved_targets: [],
      allow_dns: "controlled",
    },
    executions: { attempts: 3, completed: 2, failed: 1, timed_out: 0, total: 3 },
    blocked: {
      total: 2,
      recent: [
        {
          timestamp: "2026-08-29T10:02:00+00:00",
          tool: "run_exploit_terminal",
          code: "SANDBOX_SCOPE_DENIED",
          message: "192.0.2.9 is outside the target allowlist",
        },
        {
          timestamp: "2026-08-29T10:05:00+00:00",
          tool: "run_as_root",
          code: "SANDBOX_UNAVAILABLE",
          message: "docker daemon unreachable",
        },
      ],
    },
    last_activity: "2026-08-29T10:05:00+00:00",
    ...overrides,
  };
}

function renderTab(props: Parameters<typeof SandboxTab>[0]) {
  return render(<SandboxTab {...props} />);
}

describe("SandboxTab", () => {
  it("shows a loading skeleton", () => {
    renderTab({ loading: true, error: null, data: undefined });
    expect(screen.queryByText("Network policy")).not.toBeInTheDocument();
  });

  it("shows an error state", () => {
    renderTab({ loading: false, error: new Error("boom"), data: undefined });
    expect(screen.getByText("Failed to load sandbox info.")).toBeInTheDocument();
  });

  it("shows an empty state when the run had no sandbox activity", () => {
    renderTab({ loading: false, error: null, data: { ...sandboxData(), found: false } });
    expect(screen.getByText(/No sandbox activity recorded/)).toBeInTheDocument();
  });

  it("renders the container identity, execution stats, and network policy", () => {
    renderTab({ loading: false, error: null, data: sandboxData() });
    expect(screen.getByText("Contained (docker)")).toBeInTheDocument();
    expect(screen.getByText("abc123def456")).toBeInTheDocument(); // short container id
    expect(screen.getByText("breachpilot-sandbox:latest")).toBeInTheDocument();
    expect(screen.getByText("locked (default drop)")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.50/32")).toBeInTheDocument();
    expect(screen.getByText("github.com -> 140.82.121.4")).toBeInTheDocument();
    expect(screen.getByText("169.254.169.254/32")).toBeInTheDocument();
    expect(screen.getByText("policy fingerprint fp-abc")).toBeInTheDocument();
  });

  it("lists recent blocked commands with reason codes", () => {
    renderTab({ loading: false, error: null, data: sandboxData() });
    const table = screen.getByRole("table", { name: "Recent sandbox-blocked commands" });
    expect(within(table).getByText("SANDBOX_SCOPE_DENIED")).toBeInTheDocument();
    expect(within(table).getByText("192.0.2.9 is outside the target allowlist")).toBeInTheDocument();
    expect(within(table).getByText("SANDBOX_UNAVAILABLE")).toBeInTheDocument();
    expect(within(table).getByText("run_as_root")).toBeInTheDocument();
  });

  it("shows a blocked-count badge when blocks exist", () => {
    renderTab({ loading: false, error: null, data: sandboxData() });
    expect(screen.getByText("2 blocked")).toBeInTheDocument();
  });
});
