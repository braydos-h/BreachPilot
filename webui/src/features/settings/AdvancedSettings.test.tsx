// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AdvancedSettings } from "@/features/settings/AdvancedSettings";
import type { SandboxStatusResponse } from "@/api/hooks";

vi.mock("@/api/hooks", () => ({
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

import { useSandboxStatus, useSystemInfo, useTelemetry, useDiagnostics, useConfig, useConfigSchema, usePatchConfig, useResetSystem } from "@/api/hooks";

const sandboxStatusMock = vi.mocked(useSandboxStatus);

function sandboxData(overrides: Partial<SandboxStatusResponse> = {}): SandboxStatusResponse {
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
    setup(sandboxData({ image_present: false }));
    const section = sandboxSection();
    expect(within(section).getByText("Image missing")).toBeInTheDocument();
    expect(
      within(section).getByText("docker build -t breachpilot-sandbox:latest docker/sandbox"),
    ).toBeInTheDocument();
  });

  it("reports an unreachable Docker daemon as a hard failure", () => {
    setup(sandboxData({ docker_available: false, docker_error: "cannot connect to the Docker daemon" }));
    const section = sandboxSection();
    expect(within(section).getByText("Docker unreachable")).toBeInTheDocument();
    expect(within(section).getByText("cannot connect to the Docker daemon")).toBeInTheDocument();
  });

  it("marks the disabled legacy host-execution mode", () => {
    setup(
      sandboxData({
        enabled: false,
        note: "sandbox disabled -- documented legacy host-execution mode",
      }),
    );
    const section = sandboxSection();
    expect(within(section).getByText("Disabled (host exec)")).toBeInTheDocument();
    expect(
      within(section).getByText("sandbox disabled -- documented legacy host-execution mode"),
    ).toBeInTheDocument();
  });
});
