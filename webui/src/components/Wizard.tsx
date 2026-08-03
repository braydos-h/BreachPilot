import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  Info,
  Loader2,
  Play,
  RefreshCw,
  Target,
  Settings as SettingsIcon,
  ClipboardCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { isValidTarget } from "@/lib/targetValidation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  SegmentedControl,
  SkillMultiSelect,
  TriStateToggle,
} from "@/components/RunForm";
import {
  useAnswerDecision,
  useCapabilities,
  useCreateRun,
  useLiveModels,
  useModels,
  useSkills,
} from "@/api/hooks";
import { Spinner } from "@/components/Loading";
import { ApiError } from "@/api/client";
import type {
  CreateRunResponse,
  RunCreateRequest,
  RunKind,
  SkillsMode,
} from "@/api/types";

interface WizardProps {
  onCreated?: (runId: string, state: string) => void;
}

const STEPS = ["settings", "target", "review"] as const;
type Step = (typeof STEPS)[number];

const STEP_META: Array<{ key: Step; label: string; icon: typeof Target }> = [
  { key: "settings", label: "Settings", icon: SettingsIcon },
  { key: "target", label: "Target", icon: Target },
  { key: "review", label: "Review & confirm", icon: ClipboardCheck },
];

const OBSERVER_OPTIONS = ["heuristic", "llm", "hybrid"] as const;
const SKILLS_OPTIONS: SkillsMode[] = ["off", "on", "hints", "lookup"];

const POWER_UPS = [
  { key: "swarm", label: "Swarm", hint: "Multi-agent swarm execution." },
  { key: "parallel_swarm", label: "Parallel swarm", hint: "Swarm agents run in parallel. Requires swarm." },
  { key: "critic", label: "Critic", hint: "Critic agent critiques swarm steps. Requires swarm." },
  { key: "reflection", label: "Reflection", hint: "Swarm self-reflects on each step. Requires swarm." },
  { key: "adaptive_exploits", label: "Adaptive exploits", hint: "Adapt exploit attempts to recon findings." },
  { key: "long_session", label: "Long session", hint: "Extend the agent session past the default cap." },
  { key: "multi_model_consult", label: "Multi-model consult", hint: "Consult peer models during the run." },
  { key: "ultrathink", label: "Ultrathink", hint: "Allocate extra thinking budget per step." },
] as const;

const POWER_UP_HINT: Record<string, string> = Object.fromEntries(
  POWER_UPS.map((p) => [p.key, p.hint]),
);

export function Wizard({ onCreated }: WizardProps) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [step, setStep] = useState<Step>("settings");

  // Settings state
  const [modelAlias, setModelAlias] = useState<string>("");
  const [powerUps, setPowerUps] = useState<Record<string, boolean>>({});
  const [reconFirst, setReconFirst] = useState<boolean | null>(true);
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
  const models = useModels();
  const liveModels = useLiveModels();
  const skills = useSkills();
  const createRun = useCreateRun();

  useEffect(() => {
    if (!modelAlias && models.data?.default_alias) setModelAlias(models.data.default_alias);
  }, [models.data, modelAlias]);

  // ponytail: ?path= query param kept for backward compat with HomePage links;
  // Wizard is recon-only now, so the value is ignored.
  void searchParams;

  const flags = capabilities.data?.run_options.flags ?? [];
  const skillsList = skills.data?.skills ?? [];

  const modelOptions = useMemo(() => {
    const set = new Set<string>();
    if (liveModels.data?.source === "ollama") liveModels.data.models.forEach((m) => set.add(m));
    Object.values(models.data?.registry ?? {}).forEach((m) => set.add(String(m)));
    if (models.data?.default_alias) set.add(models.data.default_alias);
    return Array.from(set);
  }, [liveModels.data, models.data]);

  const togglePowerUp = (key: string) => {
    setPowerUps((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const buildRequest = (): RunCreateRequest => ({
    target: target.trim(),
    mode: "recon",
    goal: "",
    custom_goal: "",
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
        // Advance to the confirmation gate so the required start_confirm
        // decision is reachable. Only auto-launch (no confirmation) when the
        // server says the run is already queued/running (e.g. `yes:true`).
        if (data.state === "queued" || data.state === "running") {
          onCreated?.(data.run_id, data.state);
        } else {
          setStep("review");
        }
      },
      onError: (err) => {
        setCreateError(err instanceof ApiError ? err.message : "Failed to create run.");
      },
    });
  };

  const stepIndex = STEPS.indexOf(step);
  const canGoNext = step === "settings" || (step === "target" && isValidTarget(target));

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
    else navigate(-1);
  };

  return (
    <div className="mx-auto flex w-full max-w-[1060px] flex-col gap-3 px-4 py-4 md:px-6 md:py-5">
      <div>
        <h1 className="text-lg font-semibold">New recon</h1>
        <p className="text-sm text-muted-foreground">Guided setup — mirrors the CLI recon-first flow.</p>
      </div>

      <Stepper current={step} />

      {step === "settings" && (
        <SettingsPanel
          modelAlias={modelAlias}
          setModelAlias={setModelAlias}
          modelOptions={modelOptions}
          liveModels={liveModels}
          powerUps={powerUps}
          togglePowerUp={togglePowerUp}
          flags={flags}
          reconFirst={reconFirst}
          setReconFirst={setReconFirst}
          observerMode={observerMode}
          setObserverMode={setObserverMode}
          skillsMode={skillsMode}
          setSkillsMode={setSkillsMode}
          skillsList={skillsList}
          skillsInclude={skillsInclude}
          setSkillsInclude={setSkillsInclude}
          skillsExclude={skillsExclude}
          setSkillsExclude={setSkillsExclude}
          kind={kind}
          setKind={setKind}
          yes={yes}
          setYes={setYes}
        />
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
        <div className="flex items-center justify-between border-t pt-3">
          <Button type="button" variant="ghost" size="sm" onClick={goBack} disabled={createRun.isPending}>
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

function InfoTip({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button type="button" aria-label={`${label} info`} className="text-muted-foreground/70 transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded">
          <Info className="h-3.5 w-3.5" />
        </button>
      </PopoverTrigger>
      <PopoverContent side="top" className="max-w-[16rem] leading-snug text-xs">{children}</PopoverContent>
    </Popover>
  );
}

interface SettingsPanelProps {
  modelAlias: string;
  setModelAlias: (v: string) => void;
  modelOptions: string[];
  liveModels: ReturnType<typeof useLiveModels>;
  powerUps: Record<string, boolean>;
  togglePowerUp: (key: string) => void;
  flags: string[];
  reconFirst: boolean | null;
  setReconFirst: (v: boolean | null) => void;
  observerMode: (typeof OBSERVER_OPTIONS)[number];
  setObserverMode: (v: (typeof OBSERVER_OPTIONS)[number]) => void;
  skillsMode: SkillsMode;
  setSkillsMode: (v: SkillsMode) => void;
  skillsList: { name: string }[];
  skillsInclude: string[];
  setSkillsInclude: (v: string[]) => void;
  skillsExclude: string[];
  setSkillsExclude: (v: string[]) => void;
  kind: RunKind;
  setKind: (v: RunKind) => void;
  yes: boolean;
  setYes: (v: boolean) => void;
}

function SettingsPanel(props: SettingsPanelProps) {
  const {
    modelAlias, setModelAlias, modelOptions, liveModels,
    powerUps, togglePowerUp, flags,
    reconFirst, setReconFirst,
    observerMode, setObserverMode,
    skillsMode, setSkillsMode, skillsList, skillsInclude, setSkillsInclude, skillsExclude, setSkillsExclude,
    kind, setKind, yes, setYes,
  } = props;

  const ollamaOnline = !!liveModels.data && liveModels.data.source === "ollama" && !liveModels.data.error;
  const visiblePowerUps = POWER_UPS.filter((p) => flags.includes(p.key));
  const skillsOpen = skillsMode !== "off";

  return (
    <div className="rounded-lg border bg-card/60 p-5 md:p-6">
      {/* Top configuration row: model selector + provider badge + refresh */}
      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-0 flex-1">
          <Label className="mb-1.5 flex items-center gap-1.5 text-xs text-muted-foreground">
            Model
          </Label>
          <Select value={modelAlias} onValueChange={setModelAlias}>
            <SelectTrigger className="h-9">
              <SelectValue placeholder="Default model" />
            </SelectTrigger>
            <SelectContent>
              {modelOptions.map((m) => <SelectItem key={m} value={m}>{m}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center gap-2 self-end pb-px">
          <Badge
            variant="outline"
            className={cn(
              "gap-1.5 px-2 py-1 text-xs",
              ollamaOnline
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                : "border-muted-foreground/30 text-muted-foreground",
            )}
          >
            <span className="relative flex h-1.5 w-1.5">
              {ollamaOnline && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/70" />
              )}
              <span className={cn("relative inline-flex h-1.5 w-1.5 rounded-full", ollamaOnline ? "bg-emerald-400" : "bg-muted-foreground/50")} />
            </span>
            Ollama {ollamaOnline ? "connected" : "offline"}
          </Badge>

          <Button
            type="button"
            size="icon"
            variant="outline"
            className="h-9 w-9 shrink-0"
            onClick={() => liveModels.refetch()}
            disabled={liveModels.isFetching}
            aria-label="Refresh models"
            title="Refresh models"
          >
            <RefreshCw className={cn("h-4 w-4", liveModels.isFetching && "animate-spin")} />
          </Button>
        </div>
      </div>

      {liveModels.data?.source === "registry" && liveModels.data.error && (
        <p className="mt-1.5 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[11px] text-amber-200">
          Ollama unreachable — using configured registry models.
        </p>
      )}
      {liveModels.data?.source === "ollama" && liveModels.data.error && (
        <p className="mt-1.5 truncate text-[11px] text-destructive/80">{liveModels.data.error}</p>
      )}

      {/* Power-ups section */}
      <div className="mt-5">
        <div className="mb-2 flex items-baseline gap-2">
          <h2 className="text-sm font-semibold">Power-ups</h2>
          <span className="text-xs text-muted-foreground">Toggle execution flags. Multi-agent options require swarm.</span>
        </div>
        <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
          {visiblePowerUps.map((p) => {
            const disabled = (p.key === "critic" || p.key === "reflection" || p.key === "parallel_swarm") && !powerUps.swarm;
            const checked = !!powerUps[p.key];
            return (
              <button
                key={p.key}
                type="button"
                onClick={() => !disabled && togglePowerUp(p.key)}
                disabled={disabled}
                aria-pressed={checked}
                title={POWER_UP_HINT[p.key]}
                className={cn(
                  "group flex h-11 items-center gap-2 rounded-md border px-2.5 text-[13px] transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                  disabled && "cursor-not-allowed opacity-45 hover:bg-transparent",
                  !disabled && !checked && "hover:bg-accent",
                  checked
                    ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-200"
                    : "border-border bg-background/40 text-foreground",
                )}
              >
                <Checkbox checked={checked} disabled={disabled} className={cn(checked && "border-emerald-500/60 bg-emerald-500 text-emerald-950")} />
                <span className="truncate">{p.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Core behavior section — two-column grid */}
      <div className="mt-5 grid gap-x-5 gap-y-3 sm:grid-cols-2">
        {/* Recon first */}
        <FieldLabel hint="Run recon before the goal phase. Auto defers when no goal is selected.">
          Recon first
        </FieldLabel>
        <TriStateToggle
          value={reconFirst}
          onChange={setReconFirst}
          labels={{ true: "On", false: "Off", null: "Auto" }}
        />

        {/* Observer mode */}
        <FieldLabel hint="Heuristic classifies tool results without an LLM call. LLM uses the model. Hybrid blends both.">
          Observer mode
        </FieldLabel>
        <SegmentedControl
          value={observerMode}
          onChange={(v) => setObserverMode(v as (typeof OBSERVER_OPTIONS)[number])}
          options={OBSERVER_OPTIONS.map((o) => ({ value: o, label: o.charAt(0).toUpperCase() + o.slice(1) }))}
        />

        {/* Skills */}
        <FieldLabel hint="Off disables skill lookups. On injects them. Hints shows suggestions. Lookup searches on demand.">
          Skills
        </FieldLabel>
        <div>
          <SegmentedControl
            value={skillsMode}
            onChange={(v) => setSkillsMode(v as SkillsMode)}
            options={SKILLS_OPTIONS.map((o) => ({ value: o, label: o.charAt(0).toUpperCase() + o.slice(1) }))}
          />
          {skillsOpen && (
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              <SkillMultiSelect label="Include" skills={skillsList.map((s) => s.name)} selected={skillsInclude} onChange={setSkillsInclude} />
              <SkillMultiSelect label="Exclude" skills={skillsList.map((s) => s.name)} selected={skillsExclude} onChange={setSkillsExclude} />
            </div>
          )}
        </div>

        {/* Run kind */}
        <FieldLabel hint="Agent runs the full agent loop. Manual is advertised by the API but currently executes the normal agent path.">
          Run kind
        </FieldLabel>
        <SegmentedControl
          value={kind}
          onChange={(v) => setKind(v as RunKind)}
          options={[{ value: "agent", label: "Agent" }, { value: "manual", label: "Manual" }]}
        />
      </div>

      {/* Skip start confirmation */}
      <div className="mt-4 flex items-start gap-2 rounded-md border bg-background/30 px-3 py-2">
        <Checkbox
          id="skip-confirm"
          checked={yes}
          onCheckedChange={(v) => setYes(v === true)}
          className="mt-0.5"
        />
        <Label htmlFor="skip-confirm" className="cursor-pointer text-[13px] font-normal leading-snug">
          Skip start confirmation
          <span className="ml-1.5 text-xs text-muted-foreground">Starts the assessment immediately after review.</span>
        </Label>
      </div>
    </div>
  );
}

function FieldLabel({ children, hint }: { children: React.ReactNode; hint: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <Label className="text-xs text-muted-foreground">{children}</Label>
      <InfoTip label={String(children)}>{hint}</InfoTip>
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
              active ? "bg-primary/10 text-primary" : done ? "text-emerald-400" : "text-muted-foreground",
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
    return <Spinner label="Creating run..." className="p-6" />;
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
            <SummaryRow label="Swarm" value={String(preview.swarm)} />
            <SummaryRow label="Peer models" value={String(preview.multi_model ?? false)} />
          </div>

          {destructive && (
            <div className="mt-2 flex items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-red-200">
              <AlertTriangle className="h-3.5 w-3.5" /> DESTRUCTIVE: permission={preview.permission}
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