// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HomePage, SandboxBanner } from "@/routes/HomePage";
import type { SandboxStatusResponse, SandboxFixPlanResponse, SandboxFixJobResponse } from "@/api/hooks";

vi.mock("@/api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/hooks")>();
  return {
    ...actual,
    useRuns: vi.fn(),
    useSandboxStatus: vi.fn(),
    useSandboxFixPlan: vi.fn(),
    useSandboxFix: vi.fn(),
    useSandboxFixStatus: vi.fn(),
  };
});

import { useRuns, useSandboxStatus, useSandboxFixPlan, useSandboxFix, useSandboxFixStatus } from "@/api/hooks";

const useRunsMock = vi.mocked(useRuns);
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

function makePlan(overrides: Partial<SandboxFixPlanResponse> = {}): SandboxFixPlanResponse {
  return {
    platform: "linux",
    reason: "Docker CLI not found on PATH",
    docker_cli_present: false,
    docker_daemon_running: false,
    image_present: false,
    requires_admin: true,
    steps: [
      { id: "detect_os", title: "Detect operating system", description: "Detected platform: linux", command_preview: null },
      { id: "check_docker_cli", title: "Check whether the Docker CLI is installed", description: "The Docker CLI was not found", command_preview: "docker --version" },
      { id: "install_docker", title: "Install Docker", description: "Install Docker using apt", command_preview: "sudo apt-get update && sudo apt-get install -y docker.io", requires_admin: true },
      { id: "check_daemon", title: "Check whether the Docker daemon / Docker Desktop is running", description: "Probe daemon", command_preview: "docker version" },
      { id: "start_docker", title: "Start Docker", description: "Start Docker using systemctl", command_preview: "sudo systemctl start docker", requires_admin: true },
      { id: "verify_docker", title: "Verify Docker can actually run containers", description: "Verify daemon", command_preview: "docker version" },
      { id: "check_image", title: "Check whether breachpilot-sandbox:latest exists", description: "Check image", command_preview: "docker image inspect breachpilot-sandbox:latest" },
      { id: "build_image", title: "Build BreachPilot sandbox image", description: "Build image", command_preview: "docker build -t breachpilot-sandbox:latest docker/sandbox" },
      { id: "verify_sandbox", title: "Verify the sandbox image exists and Docker is usable", description: "Final verification", command_preview: "docker version && docker image inspect breachpilot-sandbox:latest" },
    ],
    ...overrides,
  };
}

function makeJob(overrides: Partial<SandboxFixJobResponse> = {}): SandboxFixJobResponse {
  return {
    job_id: "abc123def456",
    status: "pending",
    platform: "linux",
    reason: "Docker CLI not found on PATH",
    steps: makePlan().steps.map((s) => ({ ...s, status: "pending" as const, output: "", error: "" })),
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  useRunsMock.mockReturnValue({
    data: { runs: [], total: 0 },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  } as unknown as ReturnType<typeof useRuns>);
  // Default fix hooks: no dialog open yet, plan not loaded, no job
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

  it("renders nothing for an unknown/missing mode (old backend payload)", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: undefined as unknown as string, docker_available: true, image_present: true }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    const { container } = renderNode(<SandboxBanner />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing on an unrecognized future mode", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "quantum_isolated" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    const { container } = renderNode(<SandboxBanner />);
    expect(container).toBeEmptyDOMElement();
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

describe("SandboxBanner Fix sandbox action", () => {
  it("native_fallback displays Fix sandbox", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "docker daemon unreachable" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    renderNode(<SandboxBanner />);
    expect(screen.getByRole("button", { name: /Fix sandbox/i })).toBeInTheDocument();
  });

  it("blocked displays the remediation action", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "blocked", fallback_native: false, docker_error: "daemon down" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    renderNode(<SandboxBanner />);
    expect(screen.getByRole("button", { name: /Fix sandbox/i })).toBeInTheDocument();
  });

  it("contained does not display Fix sandbox", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "contained" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    renderNode(<SandboxBanner />);
    expect(screen.queryByRole("button", { name: /Fix sandbox/i })).not.toBeInTheDocument();
  });

  it("intentionally disabled mode does not misleadingly display the Docker fix", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "disabled", enabled: false }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    renderNode(<SandboxBanner />);
    expect(screen.queryByRole("button", { name: /Fix sandbox/i })).not.toBeInTheDocument();
  });

  it("clicking Fix sandbox opens the explanation dialog with reason and plan", async () => {
    const user = userEvent.setup();
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "Docker CLI not found on PATH" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    useSandboxFixPlanMock.mockReturnValue({
      data: makePlan(),
      isLoading: false,
      error: null,
    } as unknown as ReturnType<typeof useSandboxFixPlan>);
    renderNode(<SandboxBanner />);
    await user.click(screen.getByRole("button", { name: /Fix sandbox/i }));
    expect(await screen.findByText(/Fix Docker sandbox/i)).toBeInTheDocument();
    expect(screen.getByText(/BreachPilot is currently executing commands directly on this machine because the Docker sandbox could not start\./)).toBeInTheDocument();
    expect(screen.getByText(/Docker CLI not found on PATH/)).toBeInTheDocument();
    expect(screen.getByText(/What BreachPilot will do/i)).toBeInTheDocument();
    expect(screen.getByText(/Install Docker/)).toBeInTheDocument();
    expect(screen.getByText(/sudo apt-get update/)).toBeInTheDocument();
  });

  it("the current failure reason appears in the dialog", async () => {
    const user = userEvent.setup();
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "custom reason 123" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    useSandboxFixPlanMock.mockReturnValue({
      data: makePlan({ reason: "custom reason 123" }),
      isLoading: false,
      error: null,
    } as unknown as ReturnType<typeof useSandboxFixPlan>);
    renderNode(<SandboxBanner />);
    await user.click(screen.getByRole("button", { name: /Fix sandbox/i }));
    expect(await screen.findByText(/custom reason 123/)).toBeInTheDocument();
  });

  it("the planned host changes are visible before confirmation", async () => {
    const user = userEvent.setup();
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "Docker CLI not found" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    useSandboxFixPlanMock.mockReturnValue({
      data: makePlan(),
      isLoading: false,
      error: null,
    } as unknown as ReturnType<typeof useSandboxFixPlan>);
    renderNode(<SandboxBanner />);
    await user.click(screen.getByRole("button", { name: /Fix sandbox/i }));
    expect(await screen.findByText(/This may install software, start a system service, build a Docker image, and request administrator privileges\./)).toBeInTheDocument();
    expect(screen.getByText(/What BreachPilot will do/i)).toBeInTheDocument();
  });

  it("no fix mutation executes just from opening the dialog", async () => {
    const user = userEvent.setup();
    const mutateMock = vi.fn().mockResolvedValue(makeJob());
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "x" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    useSandboxFixPlanMock.mockReturnValue({
      data: makePlan(),
      isLoading: false,
      error: null,
    } as unknown as ReturnType<typeof useSandboxFixPlan>);
    useSandboxFixMock.mockReturnValue({
      mutate: mutateMock,
      mutateAsync: mutateMock,
      isPending: false,
      error: null,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxFix>);
    renderNode(<SandboxBanner />);
    await user.click(screen.getByRole("button", { name: /Fix sandbox/i }));
    await screen.findByText(/Fix Docker sandbox/i);
    expect(mutateMock).not.toHaveBeenCalled();
  });

  it("clicking Cancel executes nothing", async () => {
    const user = userEvent.setup();
    const mutateMock = vi.fn().mockResolvedValue(makeJob());
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "x" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    useSandboxFixPlanMock.mockReturnValue({
      data: makePlan(),
      isLoading: false,
      error: null,
    } as unknown as ReturnType<typeof useSandboxFixPlan>);
    useSandboxFixMock.mockReturnValue({
      mutate: mutateMock,
      mutateAsync: mutateMock,
      isPending: false,
      error: null,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxFix>);
    renderNode(<SandboxBanner />);
    await user.click(screen.getByRole("button", { name: /Fix sandbox/i }));
    await screen.findByText(/Fix Docker sandbox/i);
    await user.click(screen.getByRole("button", { name: /Cancel/i }));
    expect(mutateMock).not.toHaveBeenCalled();
  });

  it("clicking Start fix triggers the remediation", async () => {
    const user = userEvent.setup();
    const mutateMock = vi.fn().mockResolvedValue(makeJob({ status: "running" }));
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "x" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    useSandboxFixPlanMock.mockReturnValue({
      data: makePlan(),
      isLoading: false,
      error: null,
    } as unknown as ReturnType<typeof useSandboxFixPlan>);
    useSandboxFixMock.mockReturnValue({
      mutate: mutateMock,
      mutateAsync: mutateMock,
      isPending: false,
      error: null,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxFix>);
    renderNode(<SandboxBanner />);
    await user.click(screen.getByRole("button", { name: /Fix sandbox/i }));
    await screen.findByText(/Fix Docker sandbox/i);
    await user.click(screen.getByRole("button", { name: /^Start fix$/i }));
    expect(mutateMock).toHaveBeenCalledTimes(1);
  });

  it("progress state renders", async () => {
    const user = userEvent.setup();
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "x" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    useSandboxFixPlanMock.mockReturnValue({
      data: makePlan(),
      isLoading: false,
      error: null,
    } as unknown as ReturnType<typeof useSandboxFixPlan>);
    const runningJob = makeJob({
      status: "running",
      steps: makePlan().steps.map((s, idx) =>
        idx === 0 ? { ...s, status: "succeeded" as const, output: "done" } :
        idx === 1 ? { ...s, status: "running" as const, output: "checking..." } :
        { ...s, status: "pending" as const, output: "" }
      ),
    });
    useSandboxFixStatusMock.mockReturnValue({
      data: runningJob,
    } as unknown as ReturnType<typeof useSandboxFixStatus>);
    const mutateMock = vi.fn().mockResolvedValue(runningJob);
    useSandboxFixMock.mockReturnValue({
      mutate: mutateMock,
      mutateAsync: mutateMock,
      isPending: false,
      error: null,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxFix>);
    renderNode(<SandboxBanner />);
    await user.click(screen.getByRole("button", { name: /Fix sandbox/i }));
    await screen.findByText(/Fix Docker sandbox/i);
    await user.click(screen.getByRole("button", { name: /^Start fix$/i }));
    await waitFor(() => expect(screen.getByText(/Fixing sandbox\.\.\./)).toBeInTheDocument());
  });

  it("successful remediation tells the user a BreachPilot restart is required", async () => {
    const user = userEvent.setup();
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "x" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    useSandboxFixPlanMock.mockReturnValue({
      data: makePlan(),
      isLoading: false,
      error: null,
    } as unknown as ReturnType<typeof useSandboxFixPlan>);
    const successJob = makeJob({
      status: "succeeded",
      steps: makePlan().steps.map((s) => ({ ...s, status: "succeeded" as const, output: "ok", error: "" })),
    });
    useSandboxFixStatusMock.mockReturnValue({
      data: successJob,
    } as unknown as ReturnType<typeof useSandboxFixStatus>);
    const mutateMock = vi.fn().mockResolvedValue(successJob);
    useSandboxFixMock.mockReturnValue({
      mutate: mutateMock,
      mutateAsync: mutateMock,
      isPending: false,
      error: null,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxFix>);
    renderNode(<SandboxBanner />);
    await user.click(screen.getByRole("button", { name: /Fix sandbox/i }));
    await screen.findByText(/Fix Docker sandbox/i);
    await user.click(screen.getByRole("button", { name: /^Start fix$/i }));
    expect(await screen.findByText(/Docker is ready/i)).toBeInTheDocument();
    expect(screen.getByText(/Restart BreachPilot to activate containment\./)).toBeInTheDocument();
  });

  it("a failed remediation displays the failed step/error and Retry", async () => {
    const user = userEvent.setup();
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "native_fallback", fallback_reason: "x" }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    useSandboxFixPlanMock.mockReturnValue({
      data: makePlan(),
      isLoading: false,
      error: null,
    } as unknown as ReturnType<typeof useSandboxFixPlan>);
    const failedJob = makeJob({
      status: "failed",
      steps: makePlan().steps.map((s, idx) =>
        idx === 2 ? { ...s, status: "failed" as const, error: "apt-get failed: locked", command_preview: "sudo apt-get install -y docker.io", output: "" } :
        idx < 2 ? { ...s, status: "succeeded" as const, output: "ok", error: "" } :
        { ...s, status: "pending" as const, output: "", error: "" }
      ),
    });
    useSandboxFixStatusMock.mockReturnValue({
      data: failedJob,
    } as unknown as ReturnType<typeof useSandboxFixStatus>);
    const mutateMock = vi.fn().mockResolvedValue(failedJob);
    useSandboxFixMock.mockReturnValue({
      mutate: mutateMock,
      mutateAsync: mutateMock,
      isPending: false,
      error: null,
      reset: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxFix>);
    renderNode(<SandboxBanner />);
    await user.click(screen.getByRole("button", { name: /Fix sandbox/i }));
    await screen.findByText(/Fix Docker sandbox/i);
    await user.click(screen.getByRole("button", { name: /^Start fix$/i }));
    expect(await screen.findByText(/Sandbox fix failed/i)).toBeInTheDocument();
    expect(screen.getByText(/apt-get failed: locked/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Retry/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Close/i })).toBeInTheDocument();
  });

  it("unknown sandbox modes retain the existing safe behavior", () => {
    useSandboxStatusMock.mockReturnValue({
      data: makeStatus({ mode: "quantum_isolated" as unknown as string }),
      isLoading: false,
      error: null,
      refetch: vi.fn(),
    } as unknown as ReturnType<typeof useSandboxStatus>);
    const { container } = renderNode(<SandboxBanner />);
    expect(container).toBeEmptyDOMElement();
  });
});