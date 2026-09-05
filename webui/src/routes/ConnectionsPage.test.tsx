// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConnectionsPage } from "@/routes/ConnectionsPage";
import { ApiError } from "@/api/client";

vi.mock("@/api/hooks", () => ({
  useConnections: vi.fn(),
  useConnection: vi.fn(),
  useConnectionListener: vi.fn(),
  useCheckConnection: vi.fn(),
  useRemoveConnection: vi.fn(),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

import { useConnections, useConnection, useConnectionListener, useCheckConnection, useRemoveConnection } from "@/api/hooks";

const useConnectionsMock = vi.mocked(useConnections);
const useConnectionMock = vi.mocked(useConnection);
const useConnectionListenerMock = vi.mocked(useConnectionListener);
const useCheckConnectionMock = vi.mocked(useCheckConnection);
const useRemoveConnectionMock = vi.mocked(useRemoveConnection);

function makeConn(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    connection_id: "conn-abc12345",
    target_ip: "10.0.0.15",
    method: "linux_cron",
    callback_host: "192.168.1.5",
    callback_port: 4444,
    listener_name: "persist-10-0-0-15-linux-cron",
    status: "active",
    created_at: Date.now() / 1000 - 3600,
    created_at_iso: new Date(Date.now() - 3600 * 1000).toISOString(),
    last_beacon: Date.now() / 1000 - 12,
    last_beacon_iso: new Date(Date.now() - 12 * 1000).toISOString(),
    last_check: Date.now() / 1000 - 30,
    last_check_iso: new Date(Date.now() - 30 * 1000).toISOString(),
    check_output: "ok",
    implant_path: "/tmp/implant.py",
    mitre_technique: "T1053.003",
    os_family: "linux",
    notes: "test notes",
    ...overrides,
  };
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ConnectionsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  useConnectionMock.mockReturnValue({ data: undefined, isLoading: false, error: null, refetch: vi.fn() } as unknown as ReturnType<typeof useConnection>);
  useConnectionListenerMock.mockReturnValue({ data: undefined, isLoading: false, error: null, isFetching: false, refetch: vi.fn() } as unknown as ReturnType<typeof useConnectionListener>);
  useCheckConnectionMock.mockReturnValue({ mutate: vi.fn(), isPending: false, isError: false, error: null } as unknown as ReturnType<typeof useCheckConnection>);
  useRemoveConnectionMock.mockReturnValue({ mutate: vi.fn(), isPending: false } as unknown as ReturnType<typeof useRemoveConnection>);
});

describe("ConnectionsPage", () => {
  it("renders loaded connections and KPI cards", async () => {
    const c1 = makeConn({ connection_id: "conn-aaa", target_ip: "10.0.0.15", status: "active" });
    const c2 = makeConn({ connection_id: "conn-bbb", target_ip: "10.0.0.21", method: "windows_schtask", status: "stale", os_family: "windows", mitre_technique: "T1053.005", listener_name: "persist-10-0-0-21-win" });
    useConnectionsMock.mockReturnValue({
      data: { connections: [c1, c2], total: 2, active: 1, stale: 1, removed: 0, error: 0 },
      isLoading: false,
      isFetching: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnections>);
    renderPage();
    expect(screen.getByText("Connections")).toBeInTheDocument();
    expect(screen.getAllByText("10.0.0.15").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("10.0.0.21").length).toBeGreaterThanOrEqual(1);
    // status badges - there will be at least 2 (desktop + mobile) but check count
    expect(screen.getAllByText("ACTIVE").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("STALE").length).toBeGreaterThanOrEqual(1);
    // KPI + filter both contain Active
    expect(screen.getAllByText("Active").length).toBeGreaterThanOrEqual(1);
    // humanized method - appears twice (desktop + mobile maybe) but check at least one
    expect(screen.getAllByText("Linux Cron").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Windows Schtask").length).toBeGreaterThanOrEqual(1);
  });

  it("filters by status", async () => {
    const c1 = makeConn({ connection_id: "conn-aaa", status: "active", target_ip: "10.0.0.1" });
    const c2 = makeConn({ connection_id: "conn-bbb", status: "stale", target_ip: "10.0.0.2" });
    const c3 = makeConn({ connection_id: "conn-ccc", status: "removed", target_ip: "10.0.0.3" });
    useConnectionsMock.mockReturnValue({
      data: { connections: [c1, c2, c3], total: 3, active: 1, stale: 1, removed: 1, error: 0 },
      isLoading: false,
      isFetching: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnections>);
    renderPage();
    const user = userEvent.setup();
    // Click Stale filter
    await user.click(screen.getByRole("tab", { name: /Stale/ }));
    expect(screen.getAllByText("10.0.0.2").length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText("10.0.0.1")).not.toBeInTheDocument();
    // All
    await user.click(screen.getByRole("tab", { name: /^All/ }));
    expect(screen.getAllByText("10.0.0.1").length).toBeGreaterThanOrEqual(1);
  });

  it("search filters locally", async () => {
    const c1 = makeConn({ connection_id: "conn-aaa", target_ip: "10.0.0.15", method: "linux_cron" });
    const c2 = makeConn({ connection_id: "conn-bbb", target_ip: "10.0.0.99", method: "web_php_shell" });
    useConnectionsMock.mockReturnValue({
      data: { connections: [c1, c2], total: 2, active: 2, stale: 0, removed: 0, error: 0 },
      isLoading: false,
      isFetching: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnections>);
    renderPage();
    const user = userEvent.setup();
    const input = screen.getByPlaceholderText(/Search target/);
    await user.type(input, "10.0.0.99");
    // debounced - wait a bit
    await new Promise((r) => setTimeout(r, 350));
    expect(screen.getAllByText("10.0.0.99").length).toBeGreaterThanOrEqual(1);
    // c1 should be filtered out
    expect(screen.queryByText("10.0.0.15")).not.toBeInTheDocument();
  });

  it("status badge displays correctly via variant", async () => {
    const c = makeConn({ status: "error" });
    useConnectionsMock.mockReturnValue({
      data: { connections: [c], total: 1, active: 0, stale: 0, removed: 0, error: 1 },
      isLoading: false,
      isFetching: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnections>);
    renderPage();
    expect(screen.getAllByText("ERROR").length).toBeGreaterThanOrEqual(1);
  });

  it("empty state", async () => {
    useConnectionsMock.mockReturnValue({
      data: { connections: [], total: 0, active: 0, stale: 0, removed: 0, error: 0 },
      isLoading: false,
      isFetching: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnections>);
    renderPage();
    expect(screen.getByText(/No persisted connections/)).toBeInTheDocument();
    expect(screen.getByText(/View sessions/)).toBeInTheDocument();
  });

  it("API error + retry", async () => {
    const refetch = vi.fn();
    useConnectionsMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      isFetching: false,
      error: new ApiError({ status: 500, code: "internal_error", message: "boom", details: {}, requestId: "", raw: null }),
      refetch,
    } as unknown as ReturnType<typeof useConnections>);
    renderPage();
    expect(screen.getByText(/boom/)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByText("Retry"));
    expect(refetch).toHaveBeenCalled();
  });

  it("drawer opens from row click", async () => {
    const c = makeConn();
    useConnectionsMock.mockReturnValue({
      data: { connections: [c], total: 1, active: 1, stale: 0, removed: 0, error: 0 },
      isLoading: false,
      isFetching: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnections>);
    useConnectionMock.mockReturnValue({
      data: c,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnection>);
    useConnectionListenerMock.mockReturnValue({
      data: { connection_id: c.connection_id, listener_name: c.listener_name, output: "hello", updated_at: new Date().toISOString(), running: true, status: "running" },
      isLoading: false,
      error: null,
      isFetching: false,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnectionListener>);
    renderPage();
    const user = userEvent.setup();
    // Mobile and desktop rows both rendered; pick first
    const rows = screen.getAllByRole("button", { name: /Open details for 10.0.0.15/ });
    await user.click(rows[0]!);
    expect(await screen.findByText("Connection Details")).toBeInTheDocument();
    expect(screen.getAllByText(c.connection_id).length).toBeGreaterThanOrEqual(1);
  });

  it("removal confirmation dialog appears", async () => {
    const c = makeConn();
    useConnectionsMock.mockReturnValue({
      data: { connections: [c], total: 1, active: 1, stale: 0, removed: 0, error: 0 },
      isLoading: false,
      isFetching: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnections>);
    useConnectionMock.mockReturnValue({
      data: c,
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnection>);
    useConnectionListenerMock.mockReturnValue({
      data: { connection_id: c.connection_id, listener_name: c.listener_name, output: "", updated_at: new Date().toISOString(), running: false, status: "stopped" },
      isLoading: false,
      error: null,
      isFetching: false,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useConnectionListener>);
    renderPage();
    const user = userEvent.setup();
    const rows = screen.getAllByRole("button", { name: /Open details for 10.0.0.15/ });
    await user.click(rows[0]!);
    await screen.findByText("Connection Details");
    // There may be multiple Remove buttons (drawer + dialog trigger) - pick first drawer one
    const removeBtns = screen.getAllByRole("button", { name: /Remove connection/ });
    await user.click(removeBtns[0]!);
    expect(await screen.findByText("Remove connection?")).toBeInTheDocument();
    expect(screen.getByText(/Target:/)).toBeInTheDocument();
  });
});
