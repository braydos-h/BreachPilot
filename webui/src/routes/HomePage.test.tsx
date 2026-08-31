// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HomePage, SandboxBanner } from "@/routes/HomePage";
import type { SandboxStatusResponse } from "@/api/hooks";

vi.mock("@/api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/hooks")>();
  return {
    ...actual,
    useRuns: vi.fn(),
    useSandboxStatus: vi.fn(),
  };
});

import { useRuns, useSandboxStatus } from "@/api/hooks";

const useRunsMock = vi.mocked(useRuns);
const useSandboxStatusMock = vi.mocked(useSandboxStatus);

function makeStatus(overrides: Partial<SandboxStatusResponse> = {}): SandboxStatusResponse {
  return {
    enabled: true,
    backend: "docker",
    image: "breachpilot-sandbox:latest",
    user: "sandbox",
    read_only_rootfs: true,
    mode: "contained",
    fallback_native: true,
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
  useRunsMock.mockReturnValue({
    data: { runs: [], total: 0 },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  } as unknown as ReturnType<typeof useRuns>);
});

describe("SandboxBanner", () => {
  it("renders quiet green copy when contained", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "contained" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    renderNode(<SandboxBanner />);
    expect(screen.getByTestId("sandbox-banner-contained")).toHaveTextContent("Sandbox active");
  });

  it("renders muted info line when disabled", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "disabled", enabled: false, docker_available: false }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    renderNode(<SandboxBanner />);
    expect(screen.getByTestId("sandbox-banner-disabled")).toHaveTextContent("Sandbox disabled");
  });

  it("warns loudly on native fallback with the failure reason", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({
        mode: "native_fallback",
        docker_available: false,
        fallback_reason: "docker daemon unreachable",
      }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    renderNode(<SandboxBanner />);
    expect(screen.getByTestId("sandbox-banner-fallback")).toBeInTheDocument();
    expect(screen.getByText(/docker daemon unreachable/)).toBeInTheDocument();
    expect(screen.getByText(/Running natively/i)).toBeInTheDocument();
    expect(screen.getByText(/breachpilot-sandbox:latest/)).toBeInTheDocument();
  });

  it("renders red fail-closed card when blocked", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({
        mode: "blocked",
        fallback_native: false,
        docker_available: false,
        docker_error: "docker daemon unreachable",
      }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    renderNode(<SandboxBanner />);
    expect(screen.getByTestId("sandbox-banner-blocked")).toBeInTheDocument();
    expect(screen.getByText(/Execution is blocked/i)).toBeInTheDocument();
    expect(screen.getByText(/fallback is disabled/i)).toBeInTheDocument();
  });

  it("renders nothing while loading", () => {
    useSandboxStatusMock.mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    const { container } = renderNode(<SandboxBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing on fetch error", () => {
    useSandboxStatusMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new Error("503"),
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    const { container } = renderNode(<SandboxBanner />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("HomePage sandbox banner placement", () => {
  it("surfaced on the home screen", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "daemon down" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    renderNode(<HomePage />);
    expect(screen.getByTestId("sandbox-banner-fallback")).toBeInTheDocument();
  });
});