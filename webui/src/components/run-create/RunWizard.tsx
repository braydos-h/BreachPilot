import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ArrowLeft, ArrowRight, ChevronDown, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { isValidTarget } from "@/lib/targetValidation";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { useCapabilities, useCreateRun, useGoals, useSkills } from "@/api/hooks";
import { useDefaultModel } from "@/components/ProviderSetup";
import { ApiError } from "@/api/client";
import type { CreateRunResponse, GoalPreset, ObserverMode, RunCreateRequest, RunMode, SkillsMode } from "@/api/types";
import { RunStepper, STEPS, type Step } from "./RunStepper";
import { RunSummary } from "./RunSummary";
import { ModeSelector } from "./ModeSelector";
import { TargetField } from "./TargetField";
import { GoalSelector } from "./GoalSelector";
import { ModelSelector } from "./ModelSelector";
import { ExecutionProfile } from "./ExecutionProfile";
import { AdvancedExecutionSettings } from "./AdvancedExecutionSettings";
import { SkillsSettings } from "./SkillsSettings";
import { OpsecSettings } from "./OpsecSettings";
import { RunReview } from "./RunReview";
import { profileFieldValues, type ExecutionProfileId } from "./profile";

interface RunWizardProps {
  onCreated?: (runId: string, state: string) => void;
}

/** Guided run creation: OPSEC → Configure → Target → Review & launch.
 *  Progressive disclosure — each step answers one question. The sticky sidebar
 *  mirrors the live configuration; nothing here is authoritative for security
 *  decisions (the server remains the authority). */
export function RunWizard({ onCreated }: RunWizardProps) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [step, setStep] = useState<Step>("settings");
  const [advancedOpen, setAdvancedOpen] = useState(false);

  // ?path= query param preselects recon vs attack vs fast mode.
  const modeParam: RunMode = (() => {
    const p = searchParams.get("path");
    if (p === "attack" || p === "fast") return p;
    return "recon";
  })();
  const [mode, setMode] = useState<RunMode>(modeParam);

  // Settings state (mirrors the legacy wizard field-for-field).
  const [modelAlias, setModelAlias] = useState<string>("");
  const [profile, setProfile] = useState<ExecutionProfileId>("standard");
  const [powerUps, setPowerUps] = useState<Record<string, boolean>>({});
  const [reconFirst, setReconFirst] = useState<boolean | null>(true);
  const [observerMode, setObserverMode] = useState<ObserverMode>("hybrid");
  const [skillsMode, setSkillsMode] = useState<SkillsMode>("off");
  const [skillsInclude, setSkillsInclude] = useState<string[]>([]);
  const [skillsExclude, setSkillsExclude] = useState<string[]>([]);
  const [yes, setYes] = useState(false);

  // Mode + goal. ?goal=<name> preselects only when it exists AND is compatible.
  const [goalMode, setGoalMode] = useState<"preset" | "custom">("preset");
  const [goal, setGoal] = useState<string>("");
  const [customGoal, setCustomGoal] = useState<string>("");

  // Target state
  const [target, setTarget] = useState("");

  // Review state
  const [createdRun, setCreatedRun] = useState<CreateRunResponse | null>(null);
  const [createError, setCreateError] = useState("");

  const capabilities = useCapabilities();
  const goals = useGoals();
  const skills = useSkills();
  const createRun = useCreateRun();
  const defaultModel = useDefaultModel();

  useEffect(() => {
    if (!modelAlias && defaultModel) setModelAlias(defaultModel);
  }, [defaultModel, modelAlias]);

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

  useEffect(() => {
    if (paramGoalValid && !goal && goalMode !== "custom") {
      setGoalMode("preset");
      setGoal(paramGoalValid);
    }
  }, [paramGoalValid, goal, goalMode]);

  const flags = capabilities.data?.run_options.flags ?? [];
  const skillsList = (skills.data?.skills ?? []).map((s) => s.name);
  const visiblePowerUps = ["swarm", "parallel_swarm", "critic", "reflection", "adaptive_exploits", "long_session", "multi_model_consult", "ultrathink"].filter((k) => flags.includes(k));

  // Execution profile → field values. Manual edits to any controlled field flip
  // the profile back to Custom (applyingRef suppresses that during a batch apply).
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

  // Fast Mode per-run defaults (performance-oriented, overridable in Advanced).
  // Applied once when user selects fast; manual edits flip profile to custom.
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
      // Don't force profile id; keep standard but per-run fields are fast-optimized.
    }
  };

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
    yes,
  });

  const createTheRun = () => {
    setCreateError("");
    createRun.mutate(buildRequest(), {
      onSuccess: (data) => {
        setCreatedRun(data);
        // Auto-launch only when the server says the run is already queued/running
        // (e.g. yes:true); otherwise surface the ready-to-begin gate.
        if (data.state === "queued" || data.state === "running") {
          onCreated?.(data.run_id, data.state);
        }
      },
      onError: (err) => {
        setCreateError(err instanceof ApiError ? err.message : "Failed to create run.");
      },
    });
  };

  const stepIndex = STEPS.indexOf(step);
  const canGoNext = step === "opsec" || step === "settings" || (step === "target" && isValidTarget(target));

  // Backward steps are always clickable; only the immediate next step is
  // clickable when validation allows it. Review is reached from a valid target.
  const canVisit = Object.fromEntries(
    STEPS.map((s, i) => [s, i <= stepIndex ? i !== stepIndex : i === stepIndex + 1 && canGoNext]),
  ) as Record<Step, boolean>;

  const goNext = () => {
    const next = STEPS[stepIndex + 1];
    if (next) setStep(next);
  };
  const goBack = () => {
    const prev = STEPS[stepIndex - 1];
    if (prev) setStep(prev);
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
    yes,
  };

  return (
    <div className="mx-auto flex w-full max-w-[1200px] flex-col gap-4 px-4 py-4 md:px-6 md:py-5">
      <header>
        <h1 className="text-lg font-semibold">New {mode === "fast" ? "fast" : mode === "attack" ? "attack" : "recon"} run</h1>
        <p className="text-sm text-muted-foreground">Guided setup — mirrors the CLI flow.</p>
      </header>

      <RunStepper current={step} canVisit={canVisit} onNavigate={setStep} />

      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_19rem]">
        <div className="min-w-0 space-y-4">
          {step === "opsec" && <OpsecSettings mode={mode} />}

          {step === "settings" && (
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
              <ModelSelector model={modelAlias} onModelChange={setModelAlias} />
              <ExecutionProfile value={profile} onSelect={applyProfile} />

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
                      Power-ups, observer mode, recon-first and skills.
                    </span>
                  </span>
                  <ChevronDown className={cn("h-4 w-4 shrink-0 text-muted-foreground transition-transform", advancedOpen && "rotate-180")} />
                </button>
                {advancedOpen && (
                  <div className="space-y-5 border-t p-4">
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

              <div className="flex items-start gap-2 rounded-md border bg-background/30 px-3 py-2">
                <Checkbox id="skip-confirm" checked={yes} onCheckedChange={(v) => setYes(v === true)} className="mt-0.5" />
                <Label htmlFor="skip-confirm" className="cursor-pointer text-[13px] font-normal leading-snug">
                  Skip launch confirmation
                  <span className="ml-1.5 text-xs text-muted-foreground">
                    Start immediately without requiring the normal confirmation step.
                  </span>
                </Label>
              </div>
            </div>
          )}

          {step === "target" && (
            <TargetField
              value={target}
              onChange={setTarget}
              autoFocus
            />
          )}

          {step === "review" && (
            <RunReview
              mode={mode}
              target={target}
              goalMode={goalMode}
              goal={goal}
              customGoal={customGoal}
              model={modelAlias}
              profile={profile}
              powerUpCount={visiblePowerUps.filter((k) => powerUps[k]).length}
              skillsMode={skillsMode}
              observerMode={observerMode}
              reconFirst={reconFirst}
              yes={yes}
              isCreating={createRun.isPending}
              createError={createError}
              createdRun={createdRun}
              onCreate={createTheRun}
              onEdit={(s) => setStep(s)}
              onCreated={onCreated}
              onRetry={createTheRun}
            />
          )}

          {step !== "review" && (
            <div className="flex items-center justify-between border-t pt-3">
              <Button type="button" variant="ghost" size="sm" onClick={goBack} disabled={createRun.isPending}>
                <ArrowLeft className="mr-1.5 h-4 w-4" /> Back
              </Button>
              <Button type="button" size="sm" onClick={goNext} disabled={!canGoNext || createRun.isPending}>
                {createRun.isPending ? (
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

      {/* Compact summary card on mobile — below the step content. */}
      <div className="lg:hidden">
        <RunSummary {...summaryProps} />
      </div>
    </div>
  );
}
