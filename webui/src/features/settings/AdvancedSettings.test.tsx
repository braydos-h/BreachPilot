// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AdvancedSettings } from "@/features/settings/AdvancedSettings";
import type { BrowserSystemStatus, SandboxStatusResponse } from "@/api/hooks";

vi.mock("@/api/hooks", () => ({
  useBrowserStatus: vi.fn(),
  useSandboxStatus: vi.fn(),
  useSystemInfo: vi.fn(),
  useTelemetry: vi.fn(),
  useDiagnostics: vi.fn(),
  useConfig: vi.fn(),
  useConfigSchema: vi.fn(),
  usePatchConfig: vi.fn(),
  useResetSystem: vi.fn(),
}));

// ConfigEditor needs the SettingsDraftProvider from SettingsPage; not under test here.
vi.mock("@/features/settings/ConfigEditor", () => ({ ConfigEditor: () => <div>ConfigEditor</div> }));
vi.mock("@/features/settings/DangerZone", () => ({ DangerZone: () => <div>DangerZone</div> }));

import { useBrowserStatus, useSandboxStatus, useSystemInfo, useTelemetry, useDiagnostics, useConfig, useConfigSchema, usePatchConfig, useResetSystem } from "@/api/hooks";

const browserStatusMock = vi.mocked(useBrowserStatus);
const sandboxStatusMock = vi.mocked(useSandboxStatus);

function sandboxData(overrides: Partial<SandboxStatusResponse> = {}): SandboxStatusResponse {
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
    network: {
      enforce: true,
      fail_closed: true,
      allow_dns: "controlled",
      map_host_loopback: false,
      extra_allow_cidrs: [],
    },
    resources: {
      memory_mb: 4096,
      cpus: 2,
      pids: 512,
      timeout_seconds: 300,
      output_max_bytes: 2_000_000,
    },
    cleanup: { remove_on_exit: true, remove_stale_on_startup: true },
    ...overrides,
  };
}

function setup(data: SandboxStatusResponse | null) {
  browserStatusMock.mockReturnValue({
    data: null,
    isLoading: false,
    error: null,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  sandboxStatusMock.mockReturnValue({
    data,
    isLoading: false,
    error: null,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  vi.mocked(useSystemInfo).mockReturnValue({
    data: { hostname: "test", public_ip: null, os: "win", python: "3.12", platform: "win32", local_ips: [] },
    isLoading: false,
    error: null,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  vi.mocked(useTelemetry).mockReturnValue({
    data: { summary: null, recent: [] },
    isLoading: false,
    error: null,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  vi.mocked(useDiagnostics).mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  vi.mocked(useConfig).mockReturnValue({ data: {}, isLoading: false, error: null } as never);
  vi.mocked(useConfigSchema).mockReturnValue({ data: { schema: {} }, isLoading: false, error: null } as never);
  vi.mocked(usePatchConfig).mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  vi.mocked(useResetSystem).mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  render(
    <MemoryRouter>
      <AdvancedSettings />
    </MemoryRouter>,
  );
}

function sandboxSection(): HTMLElement {
  const heading = screen.getByRole("heading", { name: "Sandbox" });
  const section = heading.closest("section");
  expect(section).not.toBeNull();
  return section as HTMLElement;
}

describe("AdvancedSettings sandbox panel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows a healthy contained status with config detail", () => {
    setup(sandboxData());
    const section = sandboxSection();
    expect(within(section).getByText("Contained (docker)")).toBeInTheDocument();
    expect(within(section).getByText("breachpilot-sandbox:latest")).toBeInTheDocument();
    expect(within(section).getByText("read-only")).toBeInTheDocument();
    expect(within(section).getByText("iptables lock")).toBeInTheDocument();
    expect(within(section).getByText("4096 MB")).toBeInTheDocument();
  });

  it("warns with the build command when the worker image is missing", () => {
    setup(sandboxData({ mode: "blocked", image_present: false }));
    const section = sandboxSection();
    expect(within(section).getByText("Execution blocked")).toBeInTheDocument();
    expect(within(section).getByText("The worker image is not built — every attack command will be blocked (fail closed).")).toBeInTheDocument();
    expect(
      within(section).getByText("docker build -t breachpilot-sandbox:latest docker/sandbox"),
    ).toBeInTheDocument();
  });

  it("warns on an unknown sandbox mode instead of guessing the posture", () => {
    setup(sandboxData({ mode: "native_fallback" as unknown as "contained" | "blocked" }));
    const section = sandboxSection();
    expect(within(section).getByText("Unknown sandbox status")).toBeInTheDocument();
    expect(within(section).getByRole("status")).toHaveTextContent(/unknown sandbox mode/i);
    expect(within(section).queryByText("Contained (docker)")).not.toBeInTheDocument();
    expect(within(section).queryByText("Execution blocked")).not.toBeInTheDocument();
  });

  it("reports an unreachable Docker daemon as a hard failure", () => {
    setup(sandboxData({ mode: "blocked", docker_available: false, docker_error: "cannot connect to the Docker daemon" }));
    const section = sandboxSection();
    expect(within(section).getByText("Execution blocked")).toBeInTheDocument();
    expect(within(section).getByText("cannot connect to the Docker daemon")).toBeInTheDocument();
  });

  it("reports blocked status if Docker is unreachable", () => {
    setup(
      sandboxData({
        mode: "blocked",
        docker_available: false,
        docker_error: "cannot connect to Docker",
      }),
    );
    const section = sandboxSection();
    expect(within(section).getByText("Execution blocked")).toBeInTheDocument();
    expect(within(section).getByText(/Docker is unavailable — attack execution is blocked/)).toBeInTheDocument();
  });
});

function browserData(overrides: Partial<BrowserSystemStatus> = {}): BrowserSystemStatus {
  return {
    enabled: true,
    backend: "playwright",
    available: true,
    health: {
      name: "browser_backend_playwright",
      ok: true,
      detail: "playwright 1.60.0 + chromium runtime present",
      playwright_present: true,
      playwright_version: "1.60.0",
      chromium_present: true,
    },
    capabilities: [
      { name: "browser.navigate", description: "Open URLs", read_only: false, available: true },
      { name: "browser.dom.inspect", description: "DOM snapshots", read_only: true, available: true },
    ],
    config: {
      headless: true,
      max_sessions: 2,
      allow_mutating_actions: false,
      capture_screenshots: true,
      capture_network: true,
      capture_console: false,
    },
    ...overrides,
  };
}

function setupBrowser(data: BrowserSystemStatus | null) {
  browserStatusMock.mockReturnValue({
    data,
    isLoading: false,
    error: null,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  sandboxStatusMock.mockReturnValue({
    data: null,
    isLoading: false,
    error: null,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  vi.mocked(useSystemInfo).mockReturnValue({
    data: { hostname: "test", public_ip: null, os: "win", python: "3.12", platform: "win32", local_ips: [] },
    isLoading: false,
    error: null,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  vi.mocked(useTelemetry).mockReturnValue({
    data: { summary: null, recent: [] },
    isLoading: false,
    error: null,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  vi.mocked(useDiagnostics).mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  vi.mocked(useConfig).mockReturnValue({ data: {}, isLoading: false, error: null } as never);
  vi.mocked(useConfigSchema).mockReturnValue({ data: { schema: {} }, isLoading: false, error: null } as never);
  vi.mocked(usePatchConfig).mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  vi.mocked(useResetSystem).mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  render(
    <MemoryRouter>
      <AdvancedSettings />
    </MemoryRouter>,
  );
}

function browserSection(): HTMLElement {
  const heading = screen.getByRole("heading", { name: "Browser agent" });
  const section = heading.closest("section");
  expect(section).not.toBeNull();
  return section as HTMLElement;
}

describe("AdvancedSettings browser panel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows contained worker readiness and capabilities", () => {
    setupBrowser(browserData());
    const section = browserSection();
    expect(within(section).getByText("Ready (playwright)")).toBeInTheDocument();
    expect(within(section).getByText("Chromium runs only inside the required sandbox worker.")).toBeInTheDocument();
    expect(within(section).getByText("sandbox worker only")).toBeInTheDocument();
    expect(within(section).getByText("browser.navigate")).toBeInTheDocument();
    expect(within(section).getByText("browser.dom.inspect")).toBeInTheDocument();
  });

  it("marks the disabled state", () => {
    setupBrowser(browserData({ enabled: false, available: false, capabilities: [] }));
    const section = browserSection();
    expect(within(section).getByText("Disabled")).toBeInTheDocument();
  });

  it("shows the worker build hint when the host SDK is missing", () => {
    setupBrowser(
      browserData({
        available: false,
        capabilities: [],
        health: {
          name: "browser_backend_playwright",
          ok: false,
          detail: "playwright SDK not installed (optional 'browser' extra)",
          playwright_present: false,
          playwright_version: "",
          chromium_present: false,
        },
      }),
    );
    const section = browserSection();
    expect(within(section).getByText("Not ready")).toBeInTheDocument();
    expect(
      within(section).getByText("docker build -t breachpilot-sandbox:browser -f docker/sandbox/Dockerfile.browser docker/sandbox"),
    ).toBeInTheDocument();
    expect(within(section).getByText("sandbox.image: breachpilot-sandbox:browser")).toBeInTheDocument();
    expect(within(section).getByText(/host Playwright does not enable execution/i)).toBeInTheDocument();
  });

  it("does not treat a complete host browser install as a contained worker", () => {
    setupBrowser(
      browserData({
        available: false,
        capabilities: [],
        health: {
          name: "browser_backend_playwright",
          ok: true,
          detail: "host Playwright and Chromium are installed",
          playwright_present: true,
          playwright_version: "1.60.0",
          chromium_present: true,
        },
      }),
    );
    const section = browserSection();
    expect(within(section).getByText("Not ready")).toBeInTheDocument();
    expect(within(section).getByText(/host Playwright does not enable execution/i)).toBeInTheDocument();
    expect(
      within(section).getByText("docker build -t breachpilot-sandbox:browser -f docker/sandbox/Dockerfile.browser docker/sandbox"),
    ).toBeInTheDocument();
  });

  it("keeps the worker build hint when only host Chromium is missing", () => {
    setupBrowser(
      browserData({
        available: false,
        capabilities: [],
        health: {
          name: "browser_backend_playwright",
          ok: false,
          detail: "playwright SDK present but no chromium runtime",
          playwright_present: true,
          playwright_version: "1.60.0",
          chromium_present: false,
        },
      }),
    );
    const section = browserSection();
    expect(
      within(section).getByText("docker build -t breachpilot-sandbox:browser -f docker/sandbox/Dockerfile.browser docker/sandbox"),
    ).toBeInTheDocument();
    expect(within(section).queryByText("python -m playwright install chromium")).not.toBeInTheDocument();
  });
});
