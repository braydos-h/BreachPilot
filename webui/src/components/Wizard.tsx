import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  Loader2,
  Play,
  RefreshCw,
  ScanSearch,
  Target,
  Settings as SettingsIcon,
  ClipboardCheck,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  SegmentedControl,
  TriStateToggle,
  SkillMultiSelect,
} from "@/components/RunForm";
import {
  useAnswerDecision,
  useCapabilities,
  useCreateRun,
  useGoals,
  useLiveModels,
  useModels,
  useSkills,
} from "@/api/hooks";
import { ApiError } from "@/api/client";
import type {
  CreateRunResponse,
  GoalPreset,
  RunCreateRequest,
  RunKind,
  RunMode,
  SkillsMode,
} from "@/api/types";

interface WizardProps {
  onCreated?: (runId: string, state: string) => void;
}

const STEPS = ["path", "settings", "target", "review"] as const;
type Step = (typeof STEPS)[number];

const STEP_META: Array<{ key: Step; label: string; icon: typeof ScanSearch }> = [
  { key: "path", label: "Choose path", icon: ScanSearch },
  { key: "settings", label: "Settings", icon: SettingsIcon },
  { key: "target", label: "Target", icon: Target },
  { key: "review", label: "Review & confirm", icon: ClipboardCheck },
];

const OBSERVER_OPTIONS = ["heuristic", "llm", "hybrid"] as const;
const SKILLS_OPTIONS: SkillsMode[] = ["off", "on", "hints", "lookup"];

const POWER_UPS = [
  { key: "swarm", label: "Swarm" },
  { key: "parallel_swarm", label: "Parallel swarm" },
  { key: "critic", label: "Critic" },
  { key: "reflection", label: "Reflection" },
  { key: "adaptive_exploits", label: "Adaptive exploits" },
  { key: "long_session", label: "Long session" },
  { key: "multi_model_consult", label: "Multi-model consult" },
  { key: "ultrathink", label: "Ultrathink" },
] as const;

function isValidTarget(v: string): boolean {
  const s = v.trim();
  if (!s) return false;
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^[0-9a-fA-F:]+$/;
  const fqdn = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return ipv4.test(s) || (ipv6.test(s) && s.includes(":")) || fqdn.test(s);
}

export function Wizard({ onCreated }: WizardProps) {
  const [searchParams] = useSearchParams();
  const [step, setStep] = useState<Step>("path");
  const [path, setPath] = useState<"recon" | "attack">("recon");

  // Settings state
  const [mode, setMode] = useState<RunMode>("recon");
  const [reconFirst, setReconFirst] = useState<boolean | null>(true);
  const [modelAlias, setModelAlias] = useState<string>("");
  const [powerUps, setPowerUps] = useState<Record<string, boolean>>({});
  const [observerMode, setObserverMode] = useState<(typeof OBSERVER_OPTIONS)[number]>("hybrid");
  const [skillsMode, setSkillsMode] = useState<SkillsMode>("off");
  const [skillsInclude, setSkillsInclude] = useState<string[]>([]);
  const [skillsExclude, setSkillsExclude] = useState<string[]>([]);
  const [kind, setKind] = useState<RunKind>("agent");
  const [yes, setYes] = useState(false);

  // Target state
  const [target, setTarget] = useState("");

  // Review state
  const [createdRun, setCreatedRun] = useState<CreateRunResponse | null>(null);
  const [createError, setCreateError] = useState("");

  // Hooks
  const capabilities = useCapabilities();
  const goals = useGoals();
  const models = useModels();
  const liveModels = useLiveModels();
  const skills = useSkills();
  const createRun = useCreateRun();

  useEffect(() => {
    if (!modelAlias && models.data?.default_alias) setModelAlias(models.data.default_alias);
  }, [models.data, modelAlias]);

  // Preselect path from ?path= query
  useEffect(() => {
    const p = searchParams.get("path");
    if (p === "attack") {
      setPath("attack");
      setMode("attack");
      setReconFirst(null);
    } else if (p === "recon") {
      setPath("recon");
      setMode("recon");
      setReconFirst(true);
    }
  }, [searchParams]);

  const flags = capabilities.data?.run_options.flags ?? [];
  const skillsList = skills.data?.skills ?? [];

  const modelOptions = useMemo(() => {
    const set = new Set<string>();
    if (liveModels.data?.source === "ollama") liveModels.data.models.forEach((m) => set.add(m));
    Object.values(models.data?.registry ?? {}).forEach((m) => set.add(String(m)));
    if (models.data?.default_alias) set.add(models.data.default_alias);
    return Array.from(set);
  }, [liveModels.data, models.data]);

  const goalGroups = useMemo(() => {
    const groups: Record<string, GoalPreset[]> = { safe: [], gated: [], high: [] };
    for (const g of goals.data?.goals ?? []) groups[g.risk]?.push(g);
    return groups;
  }, [goals.data]);

  const selectPath = (p: "recon" | "attack") => {
    setPath(p);
    if (p === "recon") {
      setMode("recon");
      setReconFirst(true);
    } else {
      setMode("attack");
      setReconFirst(null);
    }
    setStep("settings");
  };

  const togglePowerUp = (key: string) => {
    setPowerUps((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const buildRequest = (): RunCreateRequest => ({
    target: target.trim(),
    mode,
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
    kind,
    yes,
  });

  const createTheRun = () => {
    setCreateError("");
    createRun.mutate(buildRequest(), {
      onSuccess: (data) => {
        setCreatedRun(data);
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
  const canGoNext = step === "path" || (step === "settings") || (step === "target" && isValidTarget(target));

  const goNext = () => {
    if (step === "target" && !createdRun) {
      createTheRun();
      return;
    }
    const next = STEPS[stepIndex + 1];
    if (next) setStep(next);
  };
  const goBack = () => {
    const prev = STEPS[stepIndex - 1];
    if (prev) setStep(prev);
  };

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4 md:p-6">
      <div>
        <h1 className="text-lg font-semibold">New assessment</h1>
        <p className="text-sm text-muted-foreground">Guided setup — mirrors the CLI questionary flow.</p>
      </div>

      <Stepper current={step} />

      {step === "path" && (
        <div className="grid gap-3 sm:grid-cols-2">
          <PathCard
            icon={<ScanSearch className="h-6 w-6" />}
            title="Recon & Suggest Goals"
            description="Scan the target first, see what's open, then pick a goal from AI-ranked suggestions. Mirrors the CLI 'Recon-first' path."
            onClick={() => selectPath("recon")}
          />
          <PathCard
            icon={<Zap className="h-6 w-6" />}
            title="Start New Session"
            description="Go straight to attack mode. Pick a preset goal or type a custom one. Mirrors the CLI 'Start New Session' path."
            onClick={() => selectPath("attack")}
          />
        </div>
      )}

      {step === "settings" && (
        <Card>
          <CardContent className="space-y-5 pt-6">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Model</Label>
                <Button type="button" size="sm" variant="ghost" className="gap-1.5 text-xs" onClick={() => liveModels.refetch()} disabled={liveModels.isFetching}>
                  <RefreshCw className={cn("h-3 w-3", liveModels.isFetching && "animate-spin")} /> Refresh
                </Button>
              </div>
              <Select value={modelAlias} onValueChange={setModelAlias}>
                <SelectTrigger><SelectValue placeholder="Default model" /></SelectTrigger>
                <SelectContent>
                  {modelOptions.map((m) => <SelectItem key={m} value={m}>{m}</SelectItem>)}
                </SelectContent>
              </Select>
              {liveModels.data && (
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Badge variant="outline" className="text-xs">{liveModels.data.source}</Badge>
                  {liveModels.data.error && <span className="truncate">{liveModels.data.error}</span>}
                </div>
              )}
            </div>

            <div className="space-y-2">
              <Label>Power-ups</Label>
              <p className="text-xs text-muted-foreground">Toggle the execution flags (space to toggle in the CLI).</p>
              <div className="grid gap-2 sm:grid-cols-2">
                {POWER_UPS.filter((p) => flags.includes(p.key)).map((p) => {
                  const disabled = (p.key === "critic" || p.key === "reflection" || p.key === "parallel_swarm") && !powerUps.swarm;
                  return (
                    <button
                      key={p.key}
                      type="button"
                      onClick={() => !disabled && togglePowerUp(p.key)}
                      disabled={disabled}
                      className={cn(
                        "flex items-center gap-2 rounded-md border p-2 text-sm transition-colors",
                        "hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                        disabled && "cursor-not-allowed opacity-50 hover:bg-transparent",
                        powerUps[p.key] && "border-primary bg-accent",
                      )}
                    >
                      <Checkbox checked={!!powerUps[p.key]} />
                      <span>{p.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="space-y-2">
              <Label>Recon first</Label>
              <TriStateToggle value={reconFirst} onChange={setReconFirst} labels={{ true: "On", false: "Off", null: "Auto" }} />
              <p className="text-xs text-muted-foreground">Auto enables recon-first when no goal is selected.</p>
            </div>

            <div className="space-y-2">
              <Label>Observer mode</Label>
              <SegmentedControl value={observerMode} onChange={(v) => setObserverMode(v as (typeof OBSERVER_OPTIONS)[number])}
                options={OBSERVER_OPTIONS.map((o) => ({ value: o, label: o.charAt(0).toUpperCase() + o.slice(1) }))} />
            </div>

            <div className="space-y-2">
              <Label>Skills</Label>
              <SegmentedControl value={skillsMode} onChange={(v) => setSkillsMode(v as SkillsMode)}
                options={SKILLS_OPTIONS.map((o) => ({ value: o, label: o.charAt(0).toUpperCase() + o.slice(1) }))} />
              {skillsMode !== "off" && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <SkillMultiSelect label="Include" skills={skillsList.map((s) => s.name)} selected={skillsInclude} onChange={setSkillsInclude} />
                  <SkillMultiSelect label="Exclude" skills={skillsList.map((s) => s.name)} selected={skillsExclude} onChange={setSkillsExclude} />
                </div>
              )}
            </div>

            {path === "attack" && (
              <div className="space-y-2">
                <Label>Goal (optional — leave blank to choose after recon)</Label>
                <p className="text-xs text-muted-foreground">If you set a goal here, recon-first is skipped.</p>
                <GoalSelector goalGroups={goalGroups} />
              </div>
            )}

            <div className="space-y-2">
              <Label>Run kind</Label>
              <SegmentedControl value={kind} onChange={(v) => setKind(v as RunKind)}
                options={[{ value: "agent", label: "Agent" }, { value: "manual", label: "Manual" }]} />
              {kind === "manual" && (
                <p className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-2 text-xs text-amber-200">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  Manual kind is advertised by the API but currently executes the normal agent path.
                </p>
              )}
            </div>

            <div className="space-y-2">
              <Label className="flex items-center gap-2">
                <Checkbox checked={yes} onCheckedChange={(v) => setYes(v === true)} />
                Skip start confirmation (yes)
              </Label>
              {yes && mode === "attack" && (
                <p className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-red-200">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  Skipping confirmation on attack mode bypasses the destructive-action gate.
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {step === "target" && (
        <Card>
          <CardContent className="space-y-3 pt-6">
            <div className="space-y-2">
              <Label htmlFor="target">Target (IP address or domain)</Label>
              <Input
                id="target"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. 10.0.0.50 or lab.example.com"
                autoFocus
                autoComplete="off"
                spellCheck={false}
              />
              <p className="text-xs text-muted-foreground">Only scan systems you own or are explicitly authorized to test.</p>
              {target && !isValidTarget(target) && (
                <p className="text-xs text-destructive">Invalid target. Enter an IPv4/IPv6 address or a domain name.</p>
              )}
            </div>
            {createError && (
              <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">{createError}</div>
            )}
          </CardContent>
        </Card>
      )}

      {step === "review" && (
        <ReviewStep
          createdRun={createdRun}
          createError={createError}
          isCreating={createRun.isPending}
          onRetry={createTheRun}
          onCreated={onCreated}
        />
      )}

      {step !== "review" && (
        <div className="flex items-center justify-between">
          <Button type="button" variant="ghost" size="sm" onClick={goBack} disabled={stepIndex === 0 || createRun.isPending}>
            <ArrowLeft className="mr-1.5 h-4 w-4" /> Back
          </Button>
          <Button type="button" size="sm" onClick={goNext} disabled={!canGoNext || createRun.isPending}>
            {createRun.isPending ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : step === "target" ? <Play className="mr-1.5 h-4 w-4" /> : <ArrowRight className="mr-1.5 h-4 w-4" />}
            {step === "target" ? "Create run" : "Next"}
          </Button>
        </div>
      )}
    </div>
  );
}

function Stepper({ current }: { current: Step }) {
  const idx = STEPS.indexOf(current);
  return (
    <div className="flex items-center gap-1 overflow-x-auto pb-1">
      {STEP_META.map((s, i) => {
        const Icon = s.icon;
        const active = i === idx;
        const done = i < idx;
        return (
          <div key={s.key} className="flex items-center gap-1">
            <div className={cn(
              "flex items-center gap-1.5 rounded-md px-2 py-1 text-xs transition-colors",
              active ? "bg-secondary text-secondary-foreground" : done ? "text-emerald-400" : "text-muted-foreground",
            )}>
              <Icon className="h-3.5 w-3.5" />
              <span>{s.label}</span>
              {done && <Check className="h-3 w-3" />}
            </div>
            {i < STEP_META.length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground/50" />}
          </div>
        );
      })}
    </div>
  );
}

interface PathCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  onClick: () => void;
}

function PathCard({ icon, title, description, onClick }: PathCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex flex-col items-start gap-3 rounded-lg border bg-card/40 p-5 text-left transition-colors hover:border-primary hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <div className="rounded-md border bg-secondary/40 p-2 text-foreground">{icon}</div>
      <div className="space-y-1">
        <div className="font-medium">{title}</div>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
    </button>
  );
}

function GoalSelector({ goalGroups }: { goalGroups: Record<string, GoalPreset[]> }) {
  const [goalMode, setGoalMode] = useState<"preset" | "custom">("preset");
  const [goal, setGoal] = useState("");
  const [customGoal, setCustomGoal] = useState("");
  return (
    <div className="space-y-2">
      <SegmentedControl value={goalMode} onChange={(v) => setGoalMode(v as "preset" | "custom")}
        options={[{ value: "preset", label: "Preset" }, { value: "custom", label: "Custom" }]} />
      {goalMode === "preset" ? (
        <Select value={goal} onValueChange={setGoal}>
          <SelectTrigger className="min-w-[14rem]"><SelectValue placeholder="Select a goal" /></SelectTrigger>
          <SelectContent>
            {(["safe", "gated", "high"] as const).map((risk) => (
              <SelectGroup key={risk}>
                <SelectLabel className="uppercase">{risk}</SelectLabel>
                {goalGroups[risk].map((g) => (
                  <SelectItem key={g.name} value={g.name}>
                    <div className="flex flex-col">
                      <span>{g.name}</span>
                      <span className="text-xs text-muted-foreground">{g.description}</span>
                    </div>
                  </SelectItem>
                ))}
                {risk !== "high" && <SelectSeparator />}
              </SelectGroup>
            ))}
          </SelectContent>
        </Select>
      ) : (
        <Textarea value={customGoal} onChange={(e) => setCustomGoal(e.target.value)} placeholder="Describe the goal of this assessment" className="min-h-[5rem]" />
      )}
    </div>
  );
}

interface ReviewStepProps {
  createdRun: CreateRunResponse | null;
  createError: string;
  isCreating: boolean;
  onRetry: () => void;
  onCreated?: (runId: string, state: string) => void;
}

function ReviewStep({ createdRun, createError, isCreating, onRetry, onCreated }: ReviewStepProps) {
  const answerDecision = useAnswerDecision(createdRun?.run_id ?? "");
  const [confirmText, setConfirmText] = useState("");
  const [submitting, setSubmitting] = useState(false);

  if (isCreating && !createdRun) {
    return <div className="flex items-center gap-2 p-6 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Creating run...</div>;
  }

  if (createError && !createdRun) {
    return (
      <div className="space-y-3">
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">{createError}</div>
        <Button type="button" size="sm" variant="outline" onClick={onRetry}>Retry</Button>
      </div>
    );
  }

  if (!createdRun) {
    return <div className="text-sm text-muted-foreground">No run created yet.</div>;
  }

  const preview = createdRun.preview;
  const decision = createdRun.decision;
  const destructive = preview.destructive;
  const requiredText = preview.required_confirmation_text || "";

  const budgets = preview.budgets as Record<string, unknown>;
  const skillActivations = (preview.skill_activations ?? []) as Array<{ name: string; reason: string }>;
  const skillErrors = preview.skill_errors ?? [];

  const submitConfirm = (e: React.FormEvent) => {
    e.preventDefault();
    if (!decision || submitting) return;
    setSubmitting(true);
    answerDecision.mutate(
      { decisionId: decision.id, answer: confirmText },
      {
        onSuccess: () => onCreated?.(createdRun.run_id, "running"),
        onError: () => setSubmitting(false),
      },
    );
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Run summary</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-xs sm:grid-cols-3">
            <SummaryRow label="Run ID" value={preview.run_id} />
            <SummaryRow label="Target" value={preview.target_ip} />
            <SummaryRow label="Mode" value={preview.mode} />
            <SummaryRow label="Goal" value={preview.goal_name || (reconFirstLabel(preview) ? "(suggested after recon)" : "-")} />
            <SummaryRow label="Model" value={preview.model_label ?? preview.model_alias} />
            <SummaryRow label="Transport" value={preview.transport_summary} />
            <SummaryRow label="Permission" value={preview.permission} />
            <SummaryRow label="Attack mode" value={String(preview.attack_mode ?? false)} />
            <SummaryRow label="Swarm" value={String(preview.swarm)} />
            <SummaryRow label="Peer models" value={String(preview.multi_model ?? false)} />
          </div>

          {destructive && (
            <div className="mt-2 flex items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-red-200">
              <AlertTriangle className="h-3.5 w-3.5" /> DESTRUCTIVE: permission={preview.permission}, attack_mode={String(preview.attack_mode)}
            </div>
          )}

          {budgets && Object.keys(budgets).length > 0 && (
            <div className="mt-2 text-xs">
              <span className="text-muted-foreground">Budget: </span>
              <span className="font-mono">{Object.entries(budgets).map(([k, v]) => `${k}=${String(v)}`).join(", ")}</span>
            </div>
          )}

          {skillActivations.length > 0 && (
            <div className="mt-2 space-y-0.5 text-xs">
              <div className="text-muted-foreground">Skills ({skillActivations.length}):</div>
              <ul className="pl-4">
                {skillActivations.map((s, i) => <li key={i}>- <span className="text-foreground">{s.name}</span> - {s.reason}</li>)}
              </ul>
            </div>
          )}
          {skillErrors.length > 0 && (
            <div className="mt-1 text-xs text-destructive/80">Skill errors: {skillErrors.join(", ")}</div>
          )}
        </CardContent>
      </Card>

      {decision && (
        <Card className={cn(destructive && "border-destructive/50")}>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Ready-to-begin gate</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {destructive ? (
              <form className="space-y-2" onSubmit={submitConfirm}>
                <div className="flex items-start gap-2 rounded border border-destructive/40 bg-destructive/10 p-2 text-xs text-red-200">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <div className="space-y-1">
                    <div>Destructive mode. Type the exact confirmation to proceed:</div>
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono">{requiredText}</code>
                  </div>
                </div>
                <Input value={confirmText} onChange={(e) => setConfirmText(e.target.value)} placeholder={requiredText} disabled={submitting} autoFocus autoComplete="off" />
                <Button type="submit" disabled={submitting || confirmText !== requiredText} className="w-full">
                  {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Confirm & start
                </Button>
              </form>
            ) : (
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Proceed with this run?</p>
                <Button type="button" className="w-full" disabled={submitting} onClick={submitConfirm}>
                  {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Proceed
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function reconFirstLabel(preview: CreateRunResponse["preview"]): boolean {
  return preview.goal_name === "" || preview.goal_name === undefined;
}

function SummaryRow({ label, value }: { label: string; value: string | undefined }) {
  return (
    <div>
      <span className="text-muted-foreground">{label}: </span>
      <span className="text-foreground">{value ?? "-"}</span>
    </div>
  );
}