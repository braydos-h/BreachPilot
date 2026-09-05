// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { BrowserTab, groupBrowserActivity, groupBrowserScreenshots } from "@/routes/run/tabs/BrowserTab";

vi.mock("@/api/hooks", () => ({
  useWorkspace: vi.fn(),
}));
vi.mock("@/components/WorkspaceViewer", () => ({
  WorkspaceViewer: ({ path }: { path: string }) => <div data-testid="shot">{path}</div>,
}));

import { useWorkspace } from "@/api/hooks";

const workspaceMock = vi.mocked(useWorkspace);

function wsFiles(paths: string[]) {
  return { data: { files: paths.map((path) => ({ path, bytes: 10 })) }, isLoading: false, error: null, refetch: vi.fn() };
}

function setup(records: Array<Record<string, unknown>>, files: string[] = []) {
  workspaceMock.mockReturnValue(wsFiles(files) as never);
  render(
    <MemoryRouter>
      <BrowserTab runId="run-1" records={records} loading={false} error={null} />
    </MemoryRouter>,
  );
}

const STARTED = {
  timestamp: "2026-09-04T01:00:00+00:00",
  target_ip: "10.0.0.50",
  tool_name: "browser_start",
  approved: true,
  status: "completed",
  args: { target: "10.0.0.50", run_id: "run-1" },
};
const NAV_STARTED = {
  timestamp: "2026-09-04T01:01:00+00:00",
  target_ip: "10.0.0.50",
  tool_name: "browser_navigate",
  approved: true,
  status: "started",
  args: { target: "10.0.0.50", session_id: "bs-0001-abc", url: "http://10.0.0.50/login" },
};
const NAV_DONE = { ...NAV_STARTED, timestamp: "2026-09-04T01:01:05+00:00", status: "completed" };
const BLOCKED = {
  timestamp: "2026-09-04T01:02:00+00:00",
  target_ip: "10.0.0.50",
  tool_name: "browser_navigate",
  approved: false,
  status: "blocked",
  args: { target: "10.0.0.50", session_id: "bs-0001-abc", url: "http://evil.example.com/" },
};

describe("groupBrowserActivity", () => {
  it("ignores non-browser tools", () => {
    expect(groupBrowserActivity([{ tool_name: "run_exploit_terminal", status: "completed", args: {} }])).toEqual([]);
  });

  it("collapses started/completed pairs and groups by session", () => {
    const sessions = groupBrowserActivity([STARTED, NAV_STARTED, NAV_DONE, BLOCKED]);
    expect(sessions).toHaveLength(2);
    const adhoc = sessions.find((s) => s.sessionId === "(ad hoc)");
    const live = sessions.find((s) => s.sessionId === "bs-0001-abc");
    expect(adhoc?.actions).toHaveLength(1);
    expect(live?.actions).toHaveLength(2); // pair collapsed, blocked kept
    expect(live?.actions[0]!.detail).toBe("http://10.0.0.50/login");
    expect(live?.actions[1]!.status).toBe("blocked");
    expect(live?.target).toBe("10.0.0.50");
  });
});

describe("groupBrowserScreenshots", () => {
  it("keeps browser images grouped by session and ignores the rest", () => {
    const grouped = groupBrowserScreenshots([
      { path: "browser/bs-1/a.png" },
      { path: "browser/bs-1/b.jpg" },
      { path: "browser/bs-2/a.png" },
      { path: "plans/x.json" },
      { path: "browser/bs-1/notes.txt" },
    ]);
    expect([...grouped.keys()].sort()).toEqual(["bs-1", "bs-2"]);
    expect(grouped.get("bs-1")).toEqual(["browser/bs-1/a.png", "browser/bs-1/b.jpg"]);
  });
});

describe("BrowserTab", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the empty state when the run never touched a browser", () => {
    setup([{ tool_name: "run_exploit_terminal", status: "completed", args: {} }]);
    expect(screen.getByText("No browser activity in this run yet")).toBeInTheDocument();
  });

  it("renders the session timeline with deduped actions and blocked rows", () => {
    setup([STARTED, NAV_STARTED, NAV_DONE, BLOCKED]);
    expect(screen.getByText("2 sessions")).toBeInTheDocument();
    expect(screen.getByText("3 actions")).toBeInTheDocument();
    expect(screen.getByText("1 blocked")).toBeInTheDocument();
    const section = screen.getByLabelText("Browser session bs-0001-abc");
    expect(within(section).getAllByText("Navigate")).toHaveLength(2);
    expect(within(section).getByText("http://10.0.0.50/login")).toBeInTheDocument();
    expect(within(section).getByText("blocked")).toBeInTheDocument();
  });

  it("renders screenshot thumbnails grouped under their session", () => {
    setup([NAV_DONE], ["browser/bs-0001-abc/shot-1.png", "plans/notes.md"]);
    expect(screen.getByText("1 screenshot")).toBeInTheDocument();
    expect(screen.getByTestId("shot")).toHaveTextContent("browser/bs-0001-abc/shot-1.png");
  });

  it("renders loading and error states", () => {
    workspaceMock.mockReturnValue(wsFiles([]) as never);
    const { unmount } = render(
      <MemoryRouter>
        <BrowserTab runId="run-1" records={[]} loading error={null} />
      </MemoryRouter>,
    );
    expect(document.body.textContent ?? "").not.toContain("No browser activity");
    unmount();
    render(
      <MemoryRouter>
        <BrowserTab runId="run-1" records={[]} loading={false} error={new Error("boom")} />
      </MemoryRouter>,
    );
    expect(screen.getByText("Failed to load browser activity.")).toBeInTheDocument();
  });
});
