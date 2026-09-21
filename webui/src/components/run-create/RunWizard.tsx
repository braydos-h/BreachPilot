import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowLeft, ArrowRight, ChevronDown, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { isValidTarget } from "@/lib/targetValidation";
import { Button } from "@/components/ui/button";
import { useCapabilities, useConfig, useCreateRun, useGoals, useRun, useSkills } from "@/api/hooks";
import { useRunEvents } from "@/api/ws";
import { ProviderPrivacyNotice, useDefaultModel, useProviderStatus } from "@/components/ProviderSetup";
import { ApiError } from "@/api/client";
import type { GoalPreset, ObserverMode, RunCreateRequest, RunMode, SkillsMode } from "@/api/types";
import { RunStepper, STEPS, type Step } from "./RunStepper";
import { RunSummary } from "./RunSummary";
import { ModeSelector } from "./ModeSelector";
import { TargetField } from "./TargetField";
import { GoalSelector } from "./GoalSelector";
import { ModelSelector } from "./ModelSelector";
import { ExecutionProfile } from "./ExecutionProfile";
import { AdvancedExecutionSettings } from "./AdvancedExecutionSettings";
import { SkillsSettings } from "./SkillsSettings";
import { RunReview } from "./RunReview";
import { type RunStartupState } from "./RunStartupProgress";
import { profileFieldValues, type ExecutionProfileId } from "./profile";
import { ScopeBadge } from "@/components/ScopeBadge";
import { PreflightCard, type PreflightCheck } from "@/components/PreflightCard";
import { ApprovalPolicyControl, approvalPolicyToBackend } from "@/components/ApprovalPolicyControl";
import { usePermissionMode, type PermissionMode } from "@/lib/permissionMode";

interface RunWizardProps {
  onCreated?: (runId: string, state: string) => void;
}

const DRAFT_KEY = "breachpilot.runDraft.v1";
const DRAFT_TTL_MS = 7 * 24 * 60 * 60 * 1000;

interface RunDraft {
  savedAt: number;
  target: string;
  mode: RunMode;
  goalMode: "preset" | "custom";
  goal: string;
  customGoal: string;
  modelAlias: string;
  profile: ExecutionProfileId;
  powerUps: Record<string, boolean>;
  reconFirst: boolean | null;
  observerMode: ObserverMode;
  skillsMode: SkillsMode;
  skillsInclude: string[];
  skillsExclude: string[];
  approvalPolicy: PermissionMode;
}

function readDraft(): RunDraft | null {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    if (!raw) return null;
    const d = JSON.parse(raw) as RunDraft;
    if (!d.savedAt || Date.now() - d.savedAt > DRAFT_TTL_MS) {
      localStorage.removeItem(DRAFT_KEY);
      return null;
    }
    return d;
  } catch {
    return null;
  }
}

/** Guided run creation: Target -> Intent -> Review & launch.
 *  Expert knobs live behind Advanced; OPSEC edits live in Settings. */
export function RunWizard({ onCreated }: RunWizardProps) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [step, setStep] = useState<Step>("target");
  const [visited, setVisited] = useState<Set<string>>(() => new Set(["target"]));
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [modelOverrideOpen, setModelOverrideOpen] = useState(false);

  // ?path= query param preselects recon vs attack vs fast mode.
  const modeParam: RunMode = (() => {
    const p = searchParams.get("path");
    if (p === "attack" || p === "fast") return p;
    return "recon";
  })();
  const draft = useMemo(() => readDraft(), []);
  const [mode, setMode] = useState<RunMode>(draft?.mode ?? modeParam);

  // Settings state (mirrors the legacy wizard field-for-field).
  const [modelAlias, setModelAlias] = useState<string>(draft?.modelAlias ?? "");
  const [profile, setProfile] = useState<ExecutionProfileId>(draft?.profile ?? "standard");
  const [powerUps, setPowerUps] = useState<Record<string, boolean>>(draft?.powerUps ?? {});
  const [reconFirst, setReconFirst] = useState<boolean | null>(draft?.reconFirst ?? true);
  const [observerMode, setObserverMode] = useState<ObserverMode>(draft?.observerMode ?? "hybrid");
  const [skillsMode, setSkillsMode] = useState<SkillsMode>(draft?.skillsMode ?? "off");
  const [skillsInclude, setSkillsInclude] = useState<string[]>(draft?.skillsInclude ?? []);
  const [skillsExclude, setSkillsExclude] = useState<string[]>(draft?.skillsExclude ?? []);
  const [approvalPolicy, setApprovalPolicy] = useState<PermissionMode>(draft?.approvalPolicy ?? "read_only");

  // Mode + goal. ?goal=<name> preselects only when it exists AND is compatible.
  const [goalMode, setGoalMode] = useState<"preset" | "custom">(draft?.goalMode ?? "preset");
  const [goal, setGoal] = useState<string>(draft?.goal ?? "");
  const [customGoal, setCustomGoal] = useState<string>(draft?.customGoal ?? "");

  // Target state
  const [target, setTarget] = useState(draft?.target ?? "");

  // Launch state
  const [launching, setLaunching] = useState(false);
  const [startedAt, setStartedAt] = useState(() => Date.now());
  const [createdRunId, setCreatedRunId] = useState<string | null>(null);
  const [createError, setCreateError] = useState("");
  const submitLockRef = useRef(false);
  const navigatedRef = useRef(false);

  const capabilities = useCapabilities();
  const goals = useGoals();
  const skills = useSkills();
  const createRun = useCreateRun();
  const defaultModel = useDefaultModel();
  const providerStatus = useProviderStatus();
  const config = useConfig();
  const { setMode: setGlobalPermission } = usePermissionMode();

  const runDetail = useRun(createdRunId);
  const runEvents = useRunEvents(createdRunId, { enabled: !!createdRunId });

  useEffect(() => {
    if (!modelAlias && defaultModel) setModelAlias(defaultModel);
  }, [defaultModel, modelAlias]);

  // Preserve unfinished drafts (todo 28): save non-sensitive state, never secrets.
  useEffect(() => {
    try {
      const payload: RunDraft = {
        savedAt: Date.now(), target, mode, goalMode, goal, customGoal, modelAlias,
        profile, powerUps, reconFirst, observerMode, skillsMode, skillsInclude, skillsExclude, approvalPolicy,
      };
      localStorage.setItem(DRAFT_KEY, JSON.stringify(payload));
    } catch {
      // ignore (private mode etc.)
    }
  }, [target, mode, goalMode, goal, customGoal, modelAlias, profile, powerUps, reconFirst, observerMode, skillsMode, skillsInclude, skillsExclude, approvalPolicy]);

  const discardDraft = () => {
    try {
      localStorage.removeItem(DRAFT_KEY);
    } catch {
      // ignore
    }
    setTarget("");
    setGoal("");
    setCustomGoal("");
    setGoalMode("preset");
    setProfile("standard");
    setPowerUps({});
    setApprovalPolicy("read_only");
    setStep("target");
    setVisited(new Set(["target"]));
  };

  const goalGroups = useMemo(() => {
    const groups: Record<string, GoalPreset[]> = { safe: [], gated: [], high: [] };
    for (const g of goals.data?.goals ?? []) groups[g.risk]?.push(g);
    return groups;
  }, [goals.data]);

  const paramGoal = useMemo(() => searchParams.get("goal")?.trim().toLowerCase() ?? "", [searchParams]);
  const paramGoalValid = useMemo(() => {
    if (!paramGoal) return null;
    const found = (goals.data?.goals ?? []).find((g) => g.name === paramGoal);
    return found?.compatible ? found.name : null;
  }, [paramGoal, goals.data]);

  const paramCustomGoalId = useMemo(
    () => searchParams.get("customGoal")?.trim() ?? searchParams.get("custom_goal")?.trim() ?? "",
    [searchParams],
  );
  const paramCustomGoalResolved = useMemo(() => {
    if (!paramCustomGoalId) return null;
    const found = (goals.data?.custom_goals ?? []).find((g) => g.id === paramCustomGoalId);
    return found ?? null;
  }, [paramCustomGoalId, goals.data]);

  const customInitRef = useRef<string | null>(null);
  useEffect(() => {
    if (!paramCustomGoalResolved) return;
    if (customInitRef.current === paramCustomGoalResolved.id) return;
    customInitRef.current = paramCustomGoalResolved.id;
    setGoalMode("custom");
    setCustomGoal(paramCustomGoalResolved.objective);
    setGoal("");
  }, [paramCustomGoalResolved]);

  useEffect(() => {
    if (paramGoalValid && !paramCustomGoalId && !goal && goalMode !== "custom") {
      setGoalMode("preset");
      setGoal(paramGoalValid);
    }
  }, [paramGoalValid, paramCustomGoalId, goal, goalMode]);

  const flags = capabilities.data?.run_options.flags ?? [];
  const skillsList = (skills.data?.skills ?? []).map((s) => s.name);
  const visiblePowerUps = ["swarm", "parallel_swarm", "critic", "reflection", "adaptive_exploits", "long_session", "multi_model_consult", "ultrathink"].filter((k) => flags.includes(k));

  const applyingRef = useRef(false);
  const touch = () => {
    if (!applyingRef.current) setProfile("custom");
  };
  const applyProfile = (id: ExecutionProfileId) => {
    const values = profileFieldValues(id, flags);
    if (!values) {
      setProfile(id);
      return;
    }
    applyingRef.current = true;
    setProfile(id);
    setPowerUps(values.powerUps);
    setObserverMode(values.observerMode);
    setSkillsMode(values.skillsMode);
    applyingRef.current = false;
  };

  const togglePowerUp = (key: string) => {
    touch();
    setPowerUps((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleModeChange = (next: RunMode) => {
    setMode(next);
    if (next === "fast") {
      applyingRef.current = true;
      setReconFirst(true);
      setObserverMode("hybrid");
      setPowerUps({
        swarm: false, parallel_swarm: false, critic: false, reflection: false,
        adaptive_exploits: false, long_session: false, multi_model_consult: false, ultrathink: false,
      });
      applyingRef.current = false;
    }
  };

  const backend = approvalPolicyToBackend(approvalPolicy);
  const buildRequest = (): RunCreateRequest => ({
    target: target.trim(),
    mode,
    goal: goalMode === "preset" ? goal : "",
    custom_goal: goalMode === "custom" ? customGoal.trim() : "",
    recon_first: reconFirst,
    model: modelAlias || undefined,
    swarm: !!powerUps.swarm,
    parallel_swarm: !!powerUps.parallel_swarm,
    critic: !!powerUps.swarm && !!powerUps.critic,
    reflection: !!powerUps.swarm && !!powerUps.reflection,
    adaptive_exploits: !!powerUps.adaptive_exploits,
    long_session: !!powerUps.long_session,
    multi_model_consult: powerUps.multi_model_consult ?? null,
    observer_mode: observerMode,
    ultrathink: !!powerUps.ultrathink,
    skills: skillsMode === "off" ? null : skillsMode,
    skills_include: skillsInclude,
    skills_exclude: skillsExclude,
    kind: "agent",
    yes: backend.yes,
  });

  const createTheRun = () => {
    if (submitLockRef.current) return;
    submitLockRef.current = true;
    navigatedRef.current = false;
    setCreateError("");
    setStartedAt(Date.now());
    setLaunching(true);
    try {
      setGlobalPermission(backend.mode);
    } catch {
      // ignore
    }
    createRun.mutate(buildRequest(), {
      onSuccess: (data) => {
        setCreatedRunId(data.run_id);
        if (data.state === "queued" || data.state === "running") {
          navigatedRef.current = true;
          onCreated?.(data.run_id, data.state);
        }
      },
      onError: (err) => {
        submitLockRef.current = false;
        setLaunching(false);
        setCreateError(err instanceof ApiError ? err.message : "Failed to create run.");
      },
    });
  };

  const runState = runDetail.data?.state;
  const runError = runDetail.data?.error;
  useEffect(() => {
    if (!createdRunId) return;
    if (runState === "failed") {
      submitLockRef.current = false;
      setLaunching(false);
      setCreatedRunId(null);
      setCreateError(runError || "Run preparation failed. View server logs for details.");
      return;
    }
    if ((runState === "queued" || runState === "running") && !navigatedRef.current) {
      navigatedRef.current = true;
      onCreated?.(createdRunId, runState);
    }
  }, [createdRunId, runState, runError, onCreated]);

  const preparingEvent = useMemo(() => {
    const events = runEvents.events;
    for (let i = events.length - 1; i >= 0; i--) {
      const ev = events[i];
      if (ev?.type === "preparing") return ev;
    }
    return null;
  }, [runEvents.events]);

  const prepared =
    !!runDetail.data && runDetail.data.state !== "preparing" && runDetail.data.state !== "failed";
  const startup: RunStartupState | null =
    launching || (createdRunId && !prepared)
      ? {
          phase: createdRunId ? "preparing" : "sending",
          backendStage:
            preparingEvent != null
              ? String((preparingEvent.payload as Record<string, unknown>).stage ?? "")
              : "",
          message:
            preparingEvent != null
              ? String((preparingEvent.payload as Record<string, unknown>).message ?? "")
              : "",
          startedAt,
        }
      : null;

  const stepIndex = STEPS.indexOf(step);
  const targetValid = isValidTarget(target);
  const canGoNext = step === "target" ? targetValid : step === "intent" ? true : false;

  // Only visited steps show completed (todo 01 regression).
  const visitedStep = (s: Step) => visited.has(s);
  const canVisit = Object.fromEntries(
    STEPS.map((s, i) => [s, i <= stepIndex ? (i === stepIndex ? false : visitedStep(s)) : i === stepIndex + 1 && canGoNext]),
  ) as Record<Step, boolean>;

  const goTo = (s: Step) => {
    setVisited((prev) => new Set(prev).add(s));
    setStep(s);
  };
  const goNext = () => {
    const next = STEPS[stepIndex + 1];
    if (next && (step !== "target" || targetValid)) goTo(next);
  };
  const goBack = () => {
    const prev = STEPS[stepIndex - 1];
    if (prev) goTo(prev);
    else navigate(-1);
  };

  const summaryProps = {
    mode,
    target,
    goalMode,
    goal,
    customGoal,
    model: modelAlias,
    profile,
    powerUpCount: visiblePowerUps.filter((k) => powerUps[k]).length,
    skillsMode,
    observerMode,
    reconFirst,
    yes: backend.yes,
  };

  const resolvedModel = modelAlias || defaultModel || "Default model";
  const opsec = (config.data as unknown as { opsec?: Record<string, unknown> } | undefined)?.opsec;
  const opsecSummary = opsec ? `OPSEC ${opsec.enabled === false ? "relaxed" : "standard"} posture` : "OPSEC standard posture";

  const preflightChecks: PreflightCheck[] = [
    {
      id: "provider",
      label: "Provider",
      ok: providerStatus.status === "online" ? true : providerStatus.status === "checking" ? null : false,
      detail: providerStatus.statusText,
      fixTo: "/system",
      fixLabel: "Open provider settings",
    },
    { id: "model", label: "Model", ok: resolvedModel ? true : false, detail: resolvedModel, fixTo: "/system", fixLabel: "Choose model" },
    {
      id: "scope",
      label: "Target scope",
      ok: targetValid,
      detail: targetValid ? `Authorized and in scope ✓ (${target.trim()})` : "Enter a valid target",
      fixTo: "/runs/new",
      fixLabel: "Edit target",
    },
    { id: "sandbox", label: "Sandbox", ok: true, detail: "Disposable worker ready" },
    { id: "approval", label: "Approval policy", ok: true, detail: approvalPolicy === "read_only" ? "Manual approvals" : approvalPolicy === "approve" ? "Auto-safe approvals" : "Autonomous within scope" },
    { id: "opsec", label: "OPSEC posture", ok: true, detail: opsecSummary, fixTo: "/system", fixLabel: "Edit in Settings" },
  ];
  const blocked = preflightChecks.some((c) => c.ok === false);

  return (
    <div className="mx-auto flex w-full max-w-[1200px] flex-col gap-4 px-4 py-4 md:px-6 md:py-5">
      <header>
        <h1 className="text-lg font-semibold">New {mode === "fast" ? "fast" : mode === "attack" ? "attack" : "recon"} run</h1>
        <p className="text-sm text-muted-foreground">Target → Intent → Review. Expert knobs stay under Advanced.</p>
      </header>

      <RunStepper current={step} canVisit={canVisit} onNavigate={goTo} />

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_19rem]">
        <div className="min-w-0 space-y-4">
          {step === "target" && (
            <div className="space-y-3">
              <TargetField value={target} onChange={setTarget} autoFocus />
              <ScopeBadge target={target} />
            </div>
          )}

          {step === "intent" && (
            <div className="space-y-5">
              <ModeSelector value={mode} onChange={handleModeChange} />
              <GoalSelector
                mode={mode}
                goalMode={goalMode}
                setGoalMode={setGoalMode}
                goal={goal}
                setGoal={setGoal}
                customGoal={customGoal}
                setCustomGoal={setCustomGoal}
                goalGroups={goalGroups}
              />
              <ExecutionProfile value={profile} onSelect={applyProfile} />

              <div className="rounded-lg border bg-card/40 px-4 py-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm">
                    <span className="text-muted-foreground">Using model: </span>
                    <span className="font-medium">{resolvedModel}</span>
                  </span>
                  <Button type="button" variant="ghost" size="sm" onClick={() => setModelOverrideOpen((o) => !o)} aria-expanded={modelOverrideOpen}>
                    Change
                  </Button>
                </div>
                <div className="mt-1.5">
                  <ProviderPrivacyNotice />
                </div>
                {modelOverrideOpen && (
                  <div className="mt-3">
                    <ModelSelector model={modelAlias} onModelChange={setModelAlias} />
                  </div>
                )}
              </div>

              <ApprovalPolicyControl value={approvalPolicy} onChange={setApprovalPolicy} />

              <div className="rounded-lg border bg-card/40">
                <button
                  type="button"
                  onClick={() => setAdvancedOpen((o) => !o)}
                  aria-expanded={advancedOpen}
                  className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <span>
                    <span className="block text-sm font-semibold">Advanced execution settings</span>
                    <span className="block text-xs text-muted-foreground">
                      Power-ups, observer mode, recon-first and skills. Optional.
                    </span>
                  </span>
                  <ChevronDown className={cn("h-4 w-4 shrink-0 text-muted-foreground transition-transform", advancedOpen && "rotate-180")} />
                </button>
                {advancedOpen && (
                  <div className="space-y-5 border-t p-4">
                    <ModelSelector model={modelAlias} onModelChange={(v) => { touch(); setModelAlias(v); }} />
                    <AdvancedExecutionSettings
                      flags={flags}
                      powerUps={powerUps}
                      onTogglePowerUp={togglePowerUp}
                      observerMode={observerMode}
                      setObserverMode={(v) => {
                        touch();
                        setObserverMode(v);
                      }}
                      reconFirst={reconFirst}
                      setReconFirst={setReconFirst}
                    />
                    <SkillsSettings
                      skillsMode={skillsMode}
                      setSkillsMode={(v) => {
                        touch();
                        setSkillsMode(v);
                      }}
                      skillsList={skillsList}
                      skillsInclude={skillsInclude}
                      skillsExclude={skillsExclude}
                      setSkillsInclude={setSkillsInclude}
                      setSkillsExclude={setSkillsExclude}
                    />
                  </div>
                )}
              </div>
            </div>
          )}

          {step === "review" && (
            <div className="space-y-4">
              <PreflightCard checks={preflightChecks} canLaunch={!blocked} />
              <div className="rounded-lg border bg-card/40 px-4 py-3 text-[13px]">
                <span className="font-medium">Effective OPSEC posture: </span>
                <span className="text-muted-foreground">{opsecSummary} (advisory, not a run gate). </span>
                <Link to="/system" className="font-medium text-primary underline-offset-4 hover:underline">
                  Edit in Settings
                </Link>
              </div>
              <RunReview
                mode={mode}
                target={target}
                goalMode={goalMode}
                goal={goal}
                customGoal={customGoal}
                model={resolvedModel}
                profile={profile}
                powerUpCount={visiblePowerUps.filter((k) => powerUps[k]).length}
                skillsMode={skillsMode}
                observerMode={observerMode}
                reconFirst={reconFirst}
                yes={backend.yes}
                isCreating={launching && !createdRunId}
                startup={startup}
                runDetail={prepared ? runDetail.data ?? null : null}
                createError={createError}
                onCreate={createTheRun}
                onEdit={goTo}
                onCreated={onCreated}
                onRetry={createTheRun}
              />
              {blocked && (
                <p role="alert" className="text-[13px] text-destructive">
                  Resolve the blocked checks above to enable Launch.
                </p>
              )}
            </div>
          )}

          {step !== "review" && (
            <div className="flex items-center justify-between border-t pt-3">
              <div className="flex items-center gap-2">
                <Button type="button" variant="ghost" size="sm" onClick={goBack} disabled={launching}>
                  <ArrowLeft className="mr-1.5 h-4 w-4" /> Back
                </Button>
                <Button type="button" variant="ghost" size="sm" onClick={discardDraft} disabled={launching}>
                  Discard draft
                </Button>
              </div>
              <Button type="button" size="sm" onClick={goNext} disabled={!canGoNext || launching}>
                {launching ? (
                  <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
                ) : (
                  <ArrowRight className="mr-1.5 h-4 w-4" />
                )}
                Next
              </Button>
            </div>
          )}
        </div>

        <aside className="hidden lg:sticky lg:top-4 lg:block">
          <RunSummary {...summaryProps} />
        </aside>
      </div>

      <div className="lg:hidden">
        <RunSummary {...summaryProps} />
      </div>
    </div>
  );
}
