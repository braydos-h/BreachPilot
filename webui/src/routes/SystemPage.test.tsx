// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/hooks")>();
  return {
    ...actual,
    useSandboxStatus: vi.fn(),
    useSandboxFixPlan: vi.fn(),
    useSandboxFix: vi.fn(),
    useSandboxFixStatus: vi.fn(),
  };
});

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return { ...actual, apiFetch: vi.fn().mockRejectedValue(new Error("no backend")) };
});

import { useSandboxStatus, useSandboxFixPlan, useSandboxFix, useSandboxFixStatus } from "@/api/hooks";
import type { SandboxStatusResponse } from "@/api/hooks";
import { SystemPage } from "@/routes/SystemPage";
import { SandboxFirewallCard } from "@/routes/SandboxFirewallCard";

const useSandboxStatusMock = vi.mocked(useSandboxStatus);
const useSandboxFixPlanMock = vi.mocked(useSandboxFixPlan);
const useSandboxFixMock = vi.mocked(useSandboxFix);
const useSandboxFixStatusMock = vi.mocked(useSandboxFixStatus);

function makeStatus(overrides: Partial<SandboxStatusResponse> = {}): SandboxStatusResponse {
  return {
    enabled: true,
    backend: "docker",
    image: "breachpilot-sandbox:latest",
    user: "sandbox",
    read_only_rootfs: true,
    mode: "contained",
    fallback_native: false,
    fallback_reason: "",
    docker_available: true,
    docker_error: "",
    image_present: true,
    network: { enforce: true, fail_closed: true, allow_dns: "controlled", map_host_loopback: false, extra_allow_cidrs: [] },
    resources: { memory_mb: 4096, cpus: 2, pids: 512, timeout_seconds: 300, output_max_bytes: 2_000_000 },
    cleanup: { remove_on_exit: true, remove_stale_on_startup: true },
    ...overrides,
  };
}

function renderNode(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  useSandboxFixPlanMock.mockReturnValue({
    data: undefined,
    isLoading: false,
    error: null,
  } as unknown as ReturnType<typeof useSandboxFixPlan>);
  const mockMutate = vi.fn();
  useSandboxFixMock.mockReturnValue({
    mutate: mockMutate,
    mutateAsync: mockMutate,
    isPending: false,
    error: null,
    reset: vi.fn(),
  } as unknown as ReturnType<typeof useSandboxFix>);
  useSandboxFixStatusMock.mockReturnValue({
    data: undefined,
    isLoading: false,
    error: null,
  } as unknown as ReturnType<typeof useSandboxFixStatus>);
});

function mockStatus(data: SandboxStatusResponse | undefined, opts?: { isLoading?: boolean; error?: unknown }) {
  useSandboxStatusMock.mockReturnValue({
    data,
    isLoading: !!opts?.isLoading,
    error: (opts?.error ?? null) as null,
    refetch: vi.fn(),
    isFetching: false,
  } as unknown as ReturnType<typeof useSandboxStatus>);
}

describe("SandboxFirewallCard", () => {
  it("renders contained posture with enforced firewall and containment facts", () => {
    mockStatus(makeStatus({ mode: "contained" }));
    renderNode(<SandboxFirewallCard />);
    expect(screen.getByTestId("sandbox-firewall-card")).toBeTruthy();
    expect(screen.getByTestId("sandbox-mode-badge").textContent).toMatch(/Contained/);
    expect(screen.getByTestId("sandbox-firewall-enforcement").textContent).toMatch(/default-DROP enforced/);
    // Containment facts
    expect(screen.getByText("breachpilot-sandbox:latest")).toBeTruthy();
    expect(screen.getByText("read-only")).toBeTruthy();
    // No fallback reason when contained
    expect(screen.queryByTestId("sandbox-fallback-reason")).toBeNull();
  });

  it("renders native_fallback badge plus the degradation reason", () => {
    mockStatus(makeStatus({ mode: "native_fallback", fallback_native: true, fallback_reason: "daemon unreachable", docker_available: false }));
    renderNode(<SandboxFirewallCard />);
    expect(screen.getByTestId("sandbox-mode-badge").textContent).toMatch(/Native fallback/);
    const reason = screen.getByTestId("sandbox-fallback-reason");
    expect(reason.textContent).toMatch(/daemon unreachable/);
  });

  it("renders disabled mode without a reason line", () => {
    mockStatus(makeStatus({ mode: "disabled", enabled: false, image_present: null, note: "sandbox disabled" }));
    renderNode(<SandboxFirewallCard />);
    expect(screen.getByTestId("sandbox-mode-badge").textContent).toMatch(/Disabled/);
    expect(screen.queryByTestId("sandbox-fallback-reason")).toBeNull();
  });

  it("renders blocked mode with fail-closed facts", () => {
    mockStatus(makeStatus({ mode: "blocked", fallback_reason: "sandbox image 'breachpilot-sandbox:latest' not built", image_present: false }));
    renderNode(<SandboxFirewallCard />);
    expect(screen.getByTestId("sandbox-mode-badge").textContent).toMatch(/Blocked/);
    expect(screen.getByTestId("sandbox-fallback-reason").textContent).toMatch(/not built/);
    // Missing image offers the fix-plan flow
    expect(screen.getByRole("button", { name: /Fix sandbox/i })).toBeTruthy();
  });

  it("renders an inline error without blocking the page", () => {
    mockStatus(undefined, { error: new Error("boom") });
    renderNode(<SandboxFirewallCard />);
    expect(screen.getByTestId("sandbox-firewall-error").textContent).toMatch(/Failed to load sandbox status/);
  });

  it("labels an unenforced firewall as not enforced", () => {
    mockStatus(makeStatus({ network: { enforce: false, fail_closed: true, allow_dns: "controlled", map_host_loopback: false, extra_allow_cidrs: [] } }));
    renderNode(<SandboxFirewallCard />);
    expect(screen.getByTestId("sandbox-firewall-enforcement").textContent).toMatch(/NOT enforced/);
  });
});

describe("SystemPage", () => {
  it("shows the Sandbox/Firewall card above settings", () => {
    mockStatus(makeStatus({ mode: "contained" }));
    renderNode(<SystemPage />);
    expect(screen.getByTestId("sandbox-firewall-card")).toBeTruthy();
    expect(screen.getByTestId("sandbox-mode-badge").textContent).toMatch(/Contained/);
  });
});
