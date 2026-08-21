// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { SettingsPage } from "@/features/settings/SettingsPage";

// ── module mocks ────────────────────────────────────────────────────────────

vi.mock("@/api/hooks", () => ({
  useConfig: vi.fn(),
  useConfigSchema: vi.fn(),
  usePatchConfig: vi.fn(),
  useModels: vi.fn(),
  useLiveModels: vi.fn(),
  useSecrets: vi.fn(),
  usePutSecrets: vi.fn(),
  usePlugins: vi.fn(),
  useTelemetry: vi.fn(),
  useSystemInfo: vi.fn(),
  useDiagnostics: vi.fn(),
  useResetSystem: vi.fn(),
  useAddModel: vi.fn(),
  useRemoveModel: vi.fn(),
}));
vi.mock("@/components/ProviderSetup", () => ({
  useProviderStatus: vi.fn(),
  useModelOptions: vi.fn(),
  useDefaultModel: vi.fn(),
  useProviderSwitch: vi.fn(),
  ProviderPicker: () => <div>ProviderPicker</div>,
  ChatGptControls: () => <div>ChatGptControls</div>,
}));

import {
  useAddModel,
  useConfig,
  useConfigSchema,
  useDiagnostics,
  useLiveModels,
  useModels,
  usePatchConfig,
  usePlugins,
  usePutSecrets,
  useRemoveModel,
  useResetSystem,
  useSecrets,
  useSystemInfo,
  useTelemetry,
} from "@/api/hooks";
import { useModelOptions, useProviderStatus } from "@/components/ProviderSetup";

const configMock = vi.mocked(useConfig);
const schemaMock = vi.mocked(useConfigSchema);
const patchMock = vi.mocked(usePatchConfig);
const modelsMock = vi.mocked(useModels);
const liveMock = vi.mocked(useLiveModels);
const secretsMock = vi.mocked(useSecrets);
const putSecretsMock = vi.mocked(usePutSecrets);
const pluginsMock = vi.mocked(usePlugins);
const telemetryMock = vi.mocked(useTelemetry);
const systemInfoMock = vi.mocked(useSystemInfo);
const diagnosticsMock = vi.mocked(useDiagnostics);
const resetMock = vi.mocked(useResetSystem);
const addModelMock = vi.mocked(useAddModel);
const removeModelMock = vi.mocked(useRemoveModel);
const providerStatusMock = vi.mocked(useProviderStatus);
const modelOptionsMock = vi.mocked(useModelOptions);

const CONFIG = {
  nmap: { path: "/usr/bin/nmap" },
  reasoning: { observer_mode: "hybrid", critic_enabled: true },
  mcp: { http_port: 8000, http_host: "127.0.0.1" },
  ollama: { host: "http://127.0.0.1:11434" },
  models: { default_alias: "glm", registry: { glm: "glm-5.2:cloud" } },
  skills: { enabled: ["recon"] },
  memory: { semantic_enabled: true },
  opsec: { enabled: true, unknown_field: "x" },
};

const SCHEMA = {
  nmap: { path: "/usr/bin/nmap" },
  reasoning: { observer_mode: "hybrid", critic_enabled: true },
  mcp: { http_port: 8000, http_host: "127.0.0.1" },
  ollama: { host: "http://127.0.0.1:11434" },
  models: { default_alias: "glm", registry: {} },
  skills: { enabled: ["recon"] },
  memory: { semantic_enabled: true },
  opsec: { enabled: true, unknown_field: "x" },
};

function setup() {
  configMock.mockReturnValue({ data: CONFIG, isLoading: false, error: null } as never);
  schemaMock.mockReturnValue({ data: { schema: SCHEMA }, isLoading: false, error: null } as never);
  patchMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  modelsMock.mockReturnValue({
    data: { provider: "ollama", default_alias: "glm", registry: { glm: "glm-5.2:cloud" }, info: {} },
    isLoading: false,
    error: null,
  } as never);
  liveMock.mockReturnValue({
    data: { models: ["glm-5.2:cloud"], source: "ollama" },
    isLoading: false,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  secretsMock.mockReturnValue({ data: { keys: {} }, isLoading: false, error: null } as never);
  putSecretsMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  pluginsMock.mockReturnValue({ data: { plugins: [] }, isLoading: false, error: null, refetch: vi.fn() } as never);
  telemetryMock.mockReturnValue({
    data: { summary: null, recent: [] },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  } as never);
  systemInfoMock.mockReturnValue({
    data: { hostname: "test", public_ip: null, os: "win", python: "3.12", platform: "win32", local_ips: [] },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  } as never);
  diagnosticsMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  resetMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  addModelMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  removeModelMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  providerStatusMock.mockReturnValue({
    provider: "ollama",
    label: "Ollama",
    online: true,
    source: "ollama",
    liveCount: 1,
    error: undefined,
  } as never);
  modelOptionsMock.mockReturnValue(["glm-5.2:cloud"]);

  const user = userEvent.setup();
  render(
    <MemoryRouter>
      <SettingsPage />
    </MemoryRouter>,
  );
  return { user };
}

async function goTo(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(screen.getByRole("button", { name }));
}

describe("SettingsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the four categories with General active by default", () => {
    setup();
    const nav = screen.getByRole("navigation", { name: "Settings categories" });
    expect(within(nav).getByRole("button", { name: "General" })).toHaveAttribute("aria-current", "page");
    for (const name of ["AI & Providers", "Features", "Advanced"]) {
      expect(within(nav).getByRole("button", { name })).toBeInTheDocument();
    }
  });

  it("shows friendly labels and section titles in General", () => {
    setup();
    expect(screen.getByText("Nmap path")).toBeInTheDocument();
    expect(screen.getByText("Nmap")).toBeInTheDocument(); // section title, not "nmap"
    expect(screen.getByText("Reasoning")).toBeInTheDocument();
  });

  it("hides advanced fields behind the disclosure", async () => {
    const { user } = setup();
    expect(screen.queryByText("MCP HTTP port")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Show advanced settings" }));
    expect(screen.getByText("MCP HTTP port")).toBeInTheDocument();
  });

  it("shows the unsaved bar on edit and patches the diff on save", async () => {
    const { user } = setup();
    const mutate = vi.fn();
    patchMock.mockReturnValue({ mutate, isPending: false, error: null } as never);

    const input = screen.getByLabelText("Nmap path");
    await user.clear(input);
    await user.type(input, "/usr/local/bin/nmap");

    expect(screen.getByText("1 unsaved change")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    expect(mutate).toHaveBeenCalledTimes(1);
    expect(mutate.mock.calls[0][0]).toEqual({ nmap: { path: "/usr/local/bin/nmap" } });
  });

  it("consolidates provider status, default model, and secrets under AI & Providers", async () => {
    const { user } = setup();
    await goTo(user, "AI & Providers");
    expect(screen.getByText("1 live models")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Default model" })).toBeInTheDocument();
    expect(screen.getByText("Provider API keys")).toBeInTheDocument();
    expect(screen.getByText("Model registry")).toBeInTheDocument();
  });

  it("shows the Features highlights rows", async () => {
    const { user } = setup();
    await goTo(user, "Features");
    const highlights = screen.getByRole("heading", { name: "Highlights" }).closest("section");
    expect(highlights).not.toBeNull();
    const section = highlights as HTMLElement;
    expect(within(section).getByText("Memory")).toBeInTheDocument();
    expect(within(section).getByText("Plugins")).toBeInTheDocument();
    expect(within(section).getByText("Telemetry")).toBeInTheDocument();
  });

  it("keeps the Danger Zone in Advanced, not elsewhere", async () => {
    const { user } = setup();
    expect(screen.queryByText("Danger zone")).not.toBeInTheDocument();
    await goTo(user, "Advanced");
    expect(screen.getByText("Danger zone")).toBeInTheDocument();
    expect(screen.getByText("System information")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Diagnostics" })).toBeInTheDocument();
  });

  it("surfaces unknown fields under Advanced with their raw key", async () => {
    const { user } = setup();
    await goTo(user, "Advanced");
    expect(screen.getByText("opsec.unknown_field")).toBeInTheDocument();
  });

  it("search finds a setting by friendly label and jumps to its category", async () => {
    const { user } = setup();
    const search = screen.getByLabelText("Search settings");
    await user.type(search, "ollama host");
    const result = await screen.findByRole("option", { name: /Ollama host/ });
    await user.click(result);
    expect(screen.getByText("AI provider")).toBeInTheDocument();
  });
});
