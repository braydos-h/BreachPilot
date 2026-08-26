// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import React from "react";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return { ...actual, apiFetch: vi.fn() };
});

import { apiFetch } from "@/api/client";
import { queryKeys, useConnections, useConnection, useCheckConnection, useRemoveConnection, useConnectionListener } from "@/api/hooks";

const apiFetchMock = vi.mocked(apiFetch);

function wrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => React.createElement(QueryClientProvider, { client: qc }, children);
}

describe("connections hooks", () => {
  beforeEach(() => vi.clearAllMocks());

  it("queryKeys are stable", () => {
    expect(queryKeys.connections).toEqual(["connections"]);
    expect(queryKeys.connection("conn-abc")).toEqual(["connections", "conn-abc"]);
    expect(queryKeys.connectionListener("conn-abc")).toEqual(["connections", "conn-abc", "listener"]);
  });

  it("useConnections calls GET /connections", async () => {
    apiFetchMock.mockResolvedValue({ connections: [], total: 0, active: 0, stale: 0, removed: 0, error: 0 });
    const { result } = renderHook(() => useConnections(), { wrapper: wrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(apiFetchMock).toHaveBeenCalledWith("/connections");
  });

  it("useConnections with status filter builds query string", async () => {
    apiFetchMock.mockResolvedValue({ connections: [], total: 0, active: 0, stale: 0, removed: 0, error: 0 });
    const { result } = renderHook(() => useConnections({ status: "active" }), { wrapper: wrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(apiFetchMock).toHaveBeenCalledWith("/connections?status=active");
  });

  it("useConnection calls GET /connections/{id}", async () => {
    const fake = {
      connection_id: "conn-abc",
      target_ip: "10.0.0.5",
      method: "linux_cron",
      callback_host: "127.0.0.1",
      callback_port: 4444,
      listener_name: "persist-10-0-0-5-linux-cron",
      status: "active",
      created_at: 0,
      last_beacon: null,
      last_check: null,
      check_output: "",
      implant_path: "",
      mitre_technique: "T1053.003",
      os_family: "linux",
      notes: "",
    };
    apiFetchMock.mockResolvedValue(fake);
    const { result } = renderHook(() => useConnection("conn-abc"), { wrapper: wrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(apiFetchMock).toHaveBeenCalledWith("/connections/conn-abc");
  });

  it("useConnectionListener calls GET /connections/{id}/listener", async () => {
    const fake = { connection_id: "conn-abc", listener_name: "persist-10-0-0-5-linux-cron", output: "hello", updated_at: new Date().toISOString(), running: true, status: "running" };
    apiFetchMock.mockResolvedValue(fake);
    const { result } = renderHook(() => useConnectionListener("conn-abc", true), { wrapper: wrapper() });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(apiFetchMock).toHaveBeenCalledWith("/connections/conn-abc/listener");
  });

  it("useCheckConnection posts to /check and invalidates", async () => {
    const updated = {
      connection_id: "conn-abc",
      target_ip: "10.0.0.5",
      method: "linux_cron",
      callback_host: "127.0.0.1",
      callback_port: 4444,
      listener_name: "persist-10-0-0-5-linux-cron",
      status: "active",
      created_at: 0,
      last_beacon: null,
      last_check: Date.now() / 1000,
      check_output: "ok",
      implant_path: "",
      mitre_technique: "T1053.003",
      os_family: "linux",
      notes: "",
    };
    apiFetchMock.mockResolvedValue(updated);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidateSpy = vi.spyOn(qc, "invalidateQueries");
    const w = ({ children }: { children: React.ReactNode }) => React.createElement(QueryClientProvider, { client: qc }, children);
    const { result } = renderHook(() => useCheckConnection(), { wrapper: w });
    await result.current.mutateAsync("conn-abc");
    expect(apiFetchMock).toHaveBeenCalledWith("/connections/conn-abc/check", { method: "POST", body: {} });
    // after success, invalidation should have been called
    expect(invalidateSpy).toHaveBeenCalled();
  });

  it("useRemoveConnection posts to /remove", async () => {
    const resp = { connection: { connection_id: "conn-abc", status: "removed" }, removed: true, listener_stopped: false };
    apiFetchMock.mockResolvedValue(resp as unknown as Record<string, unknown>);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidateSpy = vi.spyOn(qc, "invalidateQueries");
    const w = ({ children }: { children: React.ReactNode }) => React.createElement(QueryClientProvider, { client: qc }, children);
    const { result } = renderHook(() => useRemoveConnection(), { wrapper: w });
    await result.current.mutateAsync("conn-abc");
    expect(apiFetchMock).toHaveBeenCalledWith("/connections/conn-abc/remove", { method: "POST", body: {} });
    expect(invalidateSpy).toHaveBeenCalled();
  });
});
