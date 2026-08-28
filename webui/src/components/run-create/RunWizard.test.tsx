// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { RunWizard } from "@/components/run-create/RunWizard";

// ── module mocks ────────────────────────────────────────────────────────────

vi.mock("@/api/hooks", () => ({
  useCapabilities: vi.fn(),
  useGoals: vi.fn(),
  useSkills: vi.fn(),
  useCreateRun: vi.fn(),
  useAnswerDecision: vi.fn(),
  useLiveModels: vi.fn(),
  useSyncModels: vi.fn(),
  useConfig: vi.fn(),
  usePatchConfig: vi.fn(),
}));
vi.mock("@/components/ProviderSetup", () => ({
  useModelOptions: vi.fn(),
  useDefaultModel: vi.fn(),
  useProviderStatus: vi.fn(),
}));

import {
  useAnswerDecision,
  useCapabilities,
  useConfig,
  useCreateRun,
  useGoals,
  useLiveModels,
  usePatchConfig,
  useSkills,
  useSyncModels,
} from "@/api/hooks";
import { useDefaultModel, useModelOptions, useProviderStatus } from "@/components/ProviderSetup";

const capabilitiesMock = vi.mocked(useCapabilities);
const goalsMock = vi.mocked(useGoals);
const skillsMock = vi.mocked(useSkills);
const createRunMock = vi.mocked(useCreateRun);
const answerDecisionMock = vi.mocked(useAnswerDecision);
const liveModelsMock = vi.mocked(useLiveModels);
const syncModelsMock = vi.mocked(useSyncModels);
const configMock = vi.mocked(useConfig);
const patchConfigMock = vi.mocked(usePatchConfig);
const modelOptionsMock = vi.mocked(useModelOptions);
const defaultModelMock = vi.mocked(useDefaultModel);
const providerStatusMock = vi.mocked(useProviderStatus);

const ALL_FLAGS = [
  "swarm",
  "parallel_swarm",
  "critic",
  "reflection",
  "adaptive_exploits",
  "long_session",
  "multi_model_consult",
  "ultrathink",
];

function setup({
  flags = ALL_FLAGS,
  goals = [],
  path = "",
  goalParam = "",
}: {
  flags?: string[];
  goals?: Array<{ name: string; description: string; risk: "safe" | "gated" | "high"; compatible: boolean }>;
  path?: string;
  goalParam?: string;
} = {}) {
  capabilitiesMock.mockReturnValue({
    data: { api_version: "1", features: [], constraints: {}, run_options: { modes: ["recon", "attack"], kinds: ["agent"], flags } },
    isLoading: false,
    error: null,
  } as never);
  goalsMock.mockReturnValue({ data: { goals }, isLoading: false, error: null } as never);
  skillsMock.mockReturnValue({ data: { skills: [] }, isLoading: false, error: null } as never);
  createRunMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  answerDecisionMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  liveModelsMock.mockReturnValue({
    data: { models: [], source: "ollama" },
    isLoading: false,
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  syncModelsMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  configMock.mockReturnValue({ data: { opsec: {} }, isLoading: false, error: null } as never);
  patchConfigMock.mockReturnValue({ mutate: vi.fn(), isPending: false, error: null } as never);
  modelOptionsMock.mockReturnValue(["glm-5.2:cloud"]);
  defaultModelMock.mockReturnValue("glm-5.2:cloud");
  providerStatusMock.mockReturnValue({
    provider: "ollama",
    label: "Ollama",
    online: true,
    source: "ollama",
    liveCount: 0,
    error: undefined,
  } as never);

  const search = new URLSearchParams();
  if (path) search.set("path", path);
  if (goalParam) search.set("goal", goalParam);
  const qs = search.toString();
  const user = userEvent.setup();
  render(
    <MemoryRouter initialEntries={[qs ? `/runs/new?${qs}` : "/runs/new"]}>
      <RunWizard />
    </MemoryRouter>,
  );
  return { user };
}

async function goToTarget(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Next" }));
  expect(screen.getByLabelText(/^Target$/)).toBeInTheDocument();
}

describe("RunWizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("starts on the Configure step with OPSEC marked done", () => {
    setup();
    expect(screen.getByRole("button", { name: /Configure/ })).toHaveAttribute("aria-current", "step");
    expect(screen.getByRole("button", { name: /OPSEC/ })).toHaveTextContent("completed");
  });

  it("preselects Attack mode from ?path=attack", () => {
    setup({ path: "attack" });
    expect(screen.getByText("New attack run")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Attack/ })).toHaveAttribute("aria-checked", "true");
  });

  it("preselects Recon mode from ?path=recon", () => {
    setup({ path: "recon" });
    expect(screen.getByText("New recon run")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Recon/ })).toHaveAttribute("aria-checked", "true");
  });

  it("preselects a compatible ?goal= and renders it in the trigger", () => {
    setup({
      goalParam: "enumerate-then-report",
      goals: [
        { name: "enumerate-then-report", description: "Map and report.", risk: "safe", compatible: true },
      ],
    });
    // The goal appears in the GoalSelector trigger and the live sidebar summary.
    expect(screen.getAllByText("enumerate-then-report").length).toBeGreaterThan(0);
  });

  it("does not preselect an incompatible ?goal=", () => {
    setup({
      goalParam: "backdoor",
      goals: [{ name: "backdoor", description: "Install a backdoor.", risk: "high", compatible: false }],
    });
    expect(screen.getByText("Select a preset goal")).toBeInTheDocument();
  });

  it("blocks advancing past an invalid target and allows a valid one", async () => {
    const { user } = setup();
    await goToTarget(user);

    const next = screen.getByRole("button", { name: "Next" });
    await user.type(screen.getByLabelText(/^Target$/), "not a target");
    expect(next).toBeDisabled();

    await user.clear(screen.getByLabelText(/^Target$/));
    await user.type(screen.getByLabelText(/^Target$/), "10.0.0.5");
    expect(next).toBeEnabled();
  });

  it("sends the expected request body (critic gated on swarm, yes flag) on launch", async () => {
    const { user } = setup({ path: "attack" });
    const mutate = vi.fn();
    createRunMock.mockReturnValue({ mutate, isPending: false, error: null } as never);

    // Skip-launch-confirmation lives on the Configure step — set it before moving on.
    await user.click(screen.getByRole("checkbox", { name: /Skip launch confirmation/i }));

    await goToTarget(user);
    const target = screen.getByLabelText(/^Target$/);
    await user.type(target, "10.0.0.5");
    await user.click(screen.getByRole("button", { name: "Next" }));

    await user.click(screen.getByRole("button", { name: /Launch Attack/i }));

    expect(mutate).toHaveBeenCalledTimes(1);
    expect(mutate.mock.calls[0][0]).toMatchObject({
      target: "10.0.0.5",
      mode: "attack",
      goal: "",
      custom_goal: "",
      swarm: false,
      critic: false,
      reflection: false,
      parallel_swarm: false,
      multi_model_consult: null,
      observer_mode: "hybrid",
      ultrathink: false,
      skills: null,
      skills_include: [],
      skills_exclude: [],
      kind: "agent",
      yes: true,
    });
  });

  it("toggling a power-up manually flips the profile to Custom; swarm gates its dependents", async () => {
    const { user } = setup({ path: "attack" });

    // Scoped to the Execution profile radiogroup — the Goal selector also has
    // a "Custom" radio.
    const profileGroup = screen.getByRole("radiogroup", { name: "Execution profile" });
    expect(within(profileGroup).getByRole("radio", { name: /^Standard/ })).toHaveAttribute("aria-checked", "true");

    await user.click(screen.getByRole("button", { name: /Advanced execution settings/ }));

    // Swarm-dependent options are locked until swarm is on.
    const critic = screen.getByRole("switch", { name: "Critic" });
    expect(critic).toBeDisabled();

    await user.click(screen.getByRole("switch", { name: "Swarm" }));

    // The manual edit flipped the profile to Custom.
    expect(within(profileGroup).getByRole("radio", { name: /^Custom/ })).toHaveAttribute("aria-checked", "true");
    // With swarm on, its dependents unlock.
    expect(critic).toBeEnabled();
  });

  it("hides power-ups whose backend flag is absent", async () => {
    const { user } = setup({ path: "attack", flags: ["swarm"] });
    await user.click(screen.getByRole("button", { name: /Advanced execution settings/ }));
    expect(screen.getByRole("switch", { name: "Swarm" })).toBeInTheDocument();
    expect(screen.queryByRole("switch", { name: "Ultrathink" })).not.toBeInTheDocument();
    expect(screen.queryByRole("switch", { name: "Multi-model consult" })).not.toBeInTheDocument();
  });
});
