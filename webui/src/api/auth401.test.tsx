// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { renderHook, waitFor, render, screen, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import React from "react";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return { ...actual, apiFetch: vi.fn() };
});

import {
  apiFetch,
  clearStoredToken,
  expireSession,
  getStoredToken,
  setStoredToken,
  AUTH_EXPIRED_EVENT,
  ApiError,
} from "@/api/client";
import { queryClient } from "@/api/queryClient";
import { usePatchConfig } from "@/api/hooks";
import { TokenGate } from "@/components/TokenGate";

const apiFetchMock = vi.mocked(apiFetch);

function apiError(status: number): ApiError {
  return new ApiError({
    status,
    code: status === 401 ? "unauthorized" : "internal",
    message: status === 401 ? "Invalid or expired token" : "boom",
    details: {},
    requestId: "req-1",
    raw: null,
  });
}

function wrapper() {
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

/** AUTH_EXPIRED_EVENT dispatch counter with an explicit detach. */
function makeExpiredCounter(): { count: () => number; detach: () => void } {
  let n = 0;
  const listener = () => {
    n += 1;
  };
  window.addEventListener(AUTH_EXPIRED_EVENT, listener);
  return {
    count: () => n,
    detach: () => window.removeEventListener(AUTH_EXPIRED_EVENT, listener),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  sessionStorage.clear();
  clearStoredToken();
  queryClient.clear();
  setStoredToken("test-token");
});

describe("global 401 funnel", () => {
  it("expireSession clears the token, fires one event, and is first-caller-wins", () => {
    const counter = makeExpiredCounter();
    try {
      expireSession("token rejected");
      expect(getStoredToken()).toBe("");
      // A second expiry in the same tick is a no-op (no token left).
      expireSession("again");
      expect(counter.count()).toBe(1);
    } finally {
      counter.detach();
    }
  });

  it("expireSession is a no-op without a stored token", () => {
    clearStoredToken();
    const counter = makeExpiredCounter();
    try {
      expireSession("nobody is logged in");
      expect(counter.count()).toBe(0);
    } finally {
      counter.detach();
    }
  });

  it("a 401 mutation error clears the token and fires the event once", async () => {
    const counter = makeExpiredCounter();
    try {
      apiFetchMock.mockRejectedValue(apiError(401));
      const { result } = renderHook(() => usePatchConfig(), { wrapper: wrapper() });
      result.current.mutate({ models: { default_alias: "glm" } });
      await waitFor(() => expect(result.current.isError).toBe(true));
      expect(getStoredToken()).toBe("");
      // Retry refuses 4xx, so the cache handler fires exactly once.
      await waitFor(() => expect(counter.count()).toBe(1));
    } finally {
      counter.detach();
    }
  });

  it("a non-auth mutation error leaves the token alone", async () => {
    const counter = makeExpiredCounter();
    try {
      apiFetchMock.mockRejectedValue(apiError(500));
      const { result } = renderHook(() => usePatchConfig(), { wrapper: wrapper() });
      result.current.mutate({ models: { default_alias: "glm" } });
      await waitFor(() => expect(result.current.isError).toBe(true));
      expect(getStoredToken()).toBe("test-token");
      expect(counter.count()).toBe(0);
    } finally {
      counter.detach();
    }
  });

  it("an auth-rejected query drops cached data (removeQueries, not clear)", async () => {
    const counter = makeExpiredCounter();
    try {
      // Seed cache state so we can watch it vanish.
      queryClient.setQueryData(["probe-seed"], { keep: false });
      expect(queryClient.getQueryData(["probe-seed"])).toBeDefined();

      await expect(
        queryClient.fetchQuery({
          queryKey: ["probe-401"],
          queryFn: async () => {
            throw apiError(401);
          },
        }),
      ).rejects.toBeInstanceOf(ApiError);

      expect(getStoredToken()).toBe("");
      expect(counter.count()).toBe(1);
      expect(queryClient.getQueryData(["probe-seed"])).toBeUndefined();
    } finally {
      counter.detach();
    }
  });

  it("meta.onErrorAuthClear === false opts a query out of the funnel", async () => {
    const counter = makeExpiredCounter();
    try {
      await expect(
        queryClient.fetchQuery({
          queryKey: ["probe-opt-out"],
          queryFn: async () => {
            throw apiError(401);
          },
          meta: { onErrorAuthClear: false },
        }),
      ).rejects.toBeInstanceOf(ApiError);
      expect(getStoredToken()).toBe("test-token");
      expect(counter.count()).toBe(0);
    } finally {
      counter.detach();
    }
  });
});

describe("TokenGate auth-expiry subscription", () => {
  function renderGate(children: React.ReactNode): void {
    render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <TokenGate>{children}</TokenGate>
        </QueryClientProvider>
      </MemoryRouter>,
    );
  }

  it("re-renders the token gate when expireSession fires mid-session", async () => {
    apiFetchMock.mockResolvedValue({ capabilities: {}, constraints: { max_concurrent_runs: 1 } });
    renderGate(<div data-testid="app">console body</div>);
    // Token present + capabilities resolved → children rendered.
    await waitFor(() => expect(screen.getByTestId("app")).toBeInTheDocument());

    // Simulate the API rejecting the token mid-session (act flushes the
    // re-render the AUTH_EXPIRED_EVENT listener schedules).
    await act(async () => {
      expireSession("Your session token was rejected by the API.");
    });
    expect(getStoredToken()).toBe("");
    await waitFor(() => expect(screen.getByText("NetAttackAI console")).toBeInTheDocument());
    expect(screen.queryByTestId("app")).not.toBeInTheDocument();
  });

  it("a token submitted after expiry restores the console", async () => {
    const user = userEvent.setup();
    clearStoredToken();
    apiFetchMock.mockResolvedValue({ capabilities: {}, constraints: { max_concurrent_runs: 1 } });
    renderGate(<div data-testid="app">console body</div>);
    // No token → gate.
    expect(screen.getByText("NetAttackAI console")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Bearer token"), "fresh-token");
    await user.click(screen.getByRole("button", { name: /connect/i }));
    await waitFor(() => expect(screen.getByTestId("app")).toBeInTheDocument());
  });
});