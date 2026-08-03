import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Loader2, Play, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Badge } from "@/components/ui/badge";
import {
  useCapabilities,
  useCreateRun,
  useGoals,
  useLiveModels,
  useModels,
  useSkills,
} from "@/api/hooks";
import { ApiError } from "@/api/client";
import type {
  GoalPreset,
  RunCreateRequest,
  RunMode,
  SkillsMode,
} from "@/api/types";

interface RunFormProps {
  className?: string;
  onCreated?: (runId: string, state: string) => void;
}

const SKILLS_OPTIONS: SkillsMode[] = ["off", "on", "hints", "lookup"];
const OBSERVER_OPTIONS = ["heuristic", "llm", "hybrid"] as const;

export function RunForm({ className, onCreated }: RunFormProps) {
  const capabilities = useCapabilities();
  const goals = useGoals();
  const models = useModels();
  const liveModels = useLiveModels();
  const skills = useSkills();
  const createRun = useCreateRun();

  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<RunMode>("attack");
  const [goalMode, setGoalMode] = useState<"preset" | "custom">("preset");
  const [goal, setGoal] = useState<string>("");
  const [customGoal, setCustomGoal] = useState("");
  const [reconFirst, setReconFirst] = useState<boolean | null>(null);
  const [modelAlias, setModelAlias] = useState<string>("");
  const [swarm, setSwarm] = useState(false);
  const [parallelSwarm, setParallelSwarm] = useState(false);
  const [critic, setCritic] = useState(false);
  const [reflection, setReflection] = useState(false);
  const [adaptiveExploits, setAdaptiveExploits] = useState(false);
  const [longSession, setLongSession] = useState(false);
  const [multiModelConsult, setMultiModelConsult] = useState<boolean | null>(null);
  const [ultrathink, setUltrathink] = useState(false);
  const [observerMode, setObserverMode] = useState<(typeof OBSERVER_OPTIONS)[number]>("hybrid");
  const [skillsMode, setSkillsMode] = useState<SkillsMode>("off");
  const [skillsInclude, setSkillsInclude] = useState<string[]>([]);
  const [skillsExclude, setSkillsExclude] = useState<string[]>([]);
  const [yes, setYes] = useState(false);
  const [submitError, setSubmitError] = useState("");

  useEffect(() => {
    if (!modelAlias && models.data?.default_alias) setModelAlias(models.data.default_alias);
  }, [models.data, modelAlias]);

  const goalGroups = useMemo(() => {
    const groups: Record<string, GoalPreset[]> = { safe: [], gated: [], high: [] };
    for (const g of goals.data?.goals ?? []) {
      groups[g.risk]?.push(g);
    }
    return groups;
  }, [goals.data]);

  const modelOptions = useMemo(() => {
    const set = new Set<string>();
    if (liveModels.data?.source === "ollama") liveModels.data.models.forEach((m) => set.add(m));
    Object.values(models.data?.registry ?? {}).forEach((m) => set.add(String(m)));
    if (models.data?.default_alias) set.add(models.data.default_alias);
    return Array.from(set);
  }, [liveModels.data, models.data]);

  const skillsList = skills.data?.skills ?? [];

  const flags = capabilities.data?.run_options.flags ?? [];

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError("");
    const body: RunCreateRequest = {
      target: target.trim(),
      mode,
      goal: goalMode === "preset" ? goal : "",
      custom_goal: goalMode === "custom" ? customGoal.trim() : "",
      recon_first: reconFirst,
      model: modelAlias || undefined,
      swarm,
      parallel_swarm: parallelSwarm,
      critic: swarm && critic,
      reflection: swarm && reflection,
      adaptive_exploits: adaptiveExploits,
      long_session: longSession,
      multi_model_consult: multiModelConsult,
      observer_mode: observerMode,
      ultrathink,
      skills: skillsMode === "off" ? null : skillsMode,
      skills_include: skillsInclude,
      skills_exclude: skillsExclude,
      kind: "agent",
      yes,
    };
    createRun.mutate(body, {
      onSuccess: (data) => onCreated?.(data.run_id, data.state),
      onError: (err) => {
        setSubmitError(err instanceof ApiError ? err.message : "Failed to create run.");
      },
    });
  };

  const showSkillsSelectors = skillsMode !== "off";
  const criticDisabled = !swarm;

  return (
    <form className={cn("space-y-6", className)} onSubmit={submit}>
      <section className="space-y-3">
        <div className="space-y-2">
          <Label htmlFor="target">Target</Label>
          <Input
            id="target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="IP or domain (e.g. 10.0.0.50 or lab.example.com)"
            required
            autoComplete="off"
            spellCheck={false}
          />
          <p className="text-xs text-muted-foreground">Run only against assets you own or are authorized to test.</p>
        </div>

        <div className="space-y-2">
          <Label>Mode</Label>
          <SegmentedControl
            value={mode}
            onChange={(v) => setMode(v as RunMode)}
            options={[{ value: "recon", label: "Recon" }, { value: "attack", label: "Attack" }]}
          />
        </div>

        <div className="space-y-2">
          <Label>Goal</Label>
          <div className="flex flex-wrap items-center gap-2">
            <SegmentedControl
              value={goalMode}
              onChange={(v) => setGoalMode(v as "preset" | "custom")}
              options={[{ value: "preset", label: "Preset" }, { value: "custom", label: "Custom" }]}
            />
            {goalMode === "preset" && (
              <Select value={goal} onValueChange={setGoal}>
                <SelectTrigger className="min-w-[14rem]">
                  <SelectValue placeholder="Select a goal" />
                </SelectTrigger>
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
            )}
          </div>
          {goalMode === "custom" && (
            <Textarea
              value={customGoal}
              onChange={(e) => setCustomGoal(e.target.value)}
              placeholder="Describe the goal of this assessment"
              className="min-h-[5rem]"
            />
          )}
        </div>

        <div className="space-y-2">
          <Label>Recon first</Label>
          <TriStateToggle
            value={reconFirst}
            onChange={setReconFirst}
            labels={{ true: "On", false: "Off", null: "Auto" }}
          />
          <p className="text-xs text-muted-foreground">Auto enables recon-first when no goal is selected.</p>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label>Model</Label>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              className="gap-1.5 text-xs"
              onClick={() => liveModels.refetch()}
              disabled={liveModels.isFetching}
            >
              <RefreshCw className={cn("h-3 w-3", liveModels.isFetching && "animate-spin")} />
              Refresh
            </Button>
          </div>
          <Select value={modelAlias} onValueChange={setModelAlias}>
            <SelectTrigger>
              <SelectValue placeholder="Default model" />
            </SelectTrigger>
            <SelectContent>
              {modelOptions.map((m) => (
                <SelectItem key={m} value={m}>{m}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          {liveModels.data && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Badge variant="outline" className="text-xs">{liveModels.data.source}</Badge>
              {liveModels.data.source === "registry" && liveModels.data.error && (
                <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-amber-200">
                  Ollama unreachable — using configured registry models.
                </span>
              )}
              {liveModels.data.source === "ollama" && liveModels.data.error && (
                <span className="truncate">{liveModels.data.error}</span>
              )}
            </div>
          )}
        </div>
      </section>

      <section className="space-y-3">
        <h3 className="text-sm font-semibold">Execution options</h3>
        <div className="grid gap-3 sm:grid-cols-2">
          {flags.includes("swarm") && (
            <ToggleRow label="Swarm" checked={swarm} onChange={setSwarm} />
          )}
          {flags.includes("parallel_swarm") && (
            <ToggleRow label="Parallel swarm" checked={parallelSwarm} onChange={setParallelSwarm} disabled={!swarm} />
          )}
          {flags.includes("critic") && (
            <ToggleRow label="Critic" checked={critic} onChange={setCritic} disabled={criticDisabled} />
          )}
          {flags.includes("reflection") && (
            <ToggleRow label="Reflection" checked={reflection} onChange={setReflection} disabled={criticDisabled} />
          )}
          {flags.includes("adaptive_exploits") && (
            <ToggleRow label="Adaptive exploits" checked={adaptiveExploits} onChange={setAdaptiveExploits} />
          )}
          {flags.includes("long_session") && (
            <ToggleRow label="Long session" checked={longSession} onChange={setLongSession} />
          )}
          {flags.includes("multi_model_consult") && (
            <ToggleRow
              label="Multi-model consult"
              checked={multiModelConsult ?? false}
              onChange={(v) => setMultiModelConsult(v)}
            />
          )}
          {flags.includes("ultrathink") && (
            <ToggleRow label="Ultrathink" checked={ultrathink} onChange={setUltrathink} />
          )}
        </div>

        <div className="space-y-2">
          <Label>Observer mode</Label>
          <SegmentedControl
            value={observerMode}
            onChange={(v) => setObserverMode(v as (typeof OBSERVER_OPTIONS)[number])}
            options={OBSERVER_OPTIONS.map((o) => ({ value: o, label: o.charAt(0).toUpperCase() + o.slice(1) }))}
          />
        </div>
      </section>

      <section className="space-y-3">
        <h3 className="text-sm font-semibold">Skills</h3>
        <SegmentedControl
          value={skillsMode}
          onChange={(v) => setSkillsMode(v as SkillsMode)}
          options={SKILLS_OPTIONS.map((o) => ({ value: o, label: o.charAt(0).toUpperCase() + o.slice(1) }))}
        />
        {showSkillsSelectors && (
          <div className="grid gap-3 sm:grid-cols-2">
            <SkillMultiSelect
              label="Include"
              skills={skillsList.map((s) => s.name)}
              selected={skillsInclude}
              onChange={setSkillsInclude}
            />
            <SkillMultiSelect
              label="Exclude"
              skills={skillsList.map((s) => s.name)}
              selected={skillsExclude}
              onChange={setSkillsExclude}
            />
          </div>
        )}
      </section>

      <section className="space-y-3">
        <ToggleRow
          label="Skip start confirmation (yes)"
          checked={yes}
          onChange={setYes}
        />
        {yes && mode === "attack" && (
          <p className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-red-200">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            Skipping confirmation on attack mode bypasses the destructive-action gate. The server preview
            remains authoritative.
          </p>
        )}
      </section>

      {submitError && (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">
          {submitError}
        </div>
      )}

      <div className="flex items-center gap-2">
        <Button type="submit" disabled={!target.trim() || createRun.isPending}>
          {createRun.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          Create run
        </Button>
      </div>
    </form>
  );
}

interface SegmentedControlProps {
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}

export function SegmentedControl({ value, onChange, options }: SegmentedControlProps) {
  return (
    <div className="inline-flex h-9 items-center rounded-md border bg-muted/40 p-0.5" role="radiogroup">
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          role="radio"
          aria-checked={value === opt.value}
          onClick={() => onChange(opt.value)}
          className={cn(
            "h-8 rounded px-3 text-sm transition-colors",
            value === opt.value
              ? "bg-background text-foreground shadow"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

interface TriStateToggleProps {
  value: boolean | null;
  onChange: (value: boolean | null) => void;
  labels: { true: string; false: string; null: string };
}

export function TriStateToggle({ value, onChange, labels }: TriStateToggleProps) {
  return (
    <SegmentedControl
      value={String(value)}
      onChange={(v) => onChange(v === "true" ? true : v === "false" ? false : null)}
      options={[
        { value: "true", label: labels.true },
        { value: "false", label: labels.false },
        { value: "null", label: labels.null },
      ]}
    />
  );
}

interface ToggleRowProps {
  label: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}

export function ToggleRow({ label, checked, onChange, disabled }: ToggleRowProps) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border bg-card/30 px-3 py-2">
      <Label className="text-sm">{label}</Label>
      <Switch checked={checked} onCheckedChange={onChange} disabled={disabled} aria-label={label} />
    </div>
  );
}

interface SkillMultiSelectProps {
  label: string;
  skills: string[];
  selected: string[];
  onChange: (next: string[]) => void;
}

export function SkillMultiSelect({ label, skills, selected, onChange }: SkillMultiSelectProps) {
  const toggle = (name: string) => {
    onChange(selected.includes(name) ? selected.filter((n) => n !== name) : [...selected, name]);
  };
  return (
    <div className="space-y-1.5">
      <Label className="text-xs">{label}</Label>
      <div className="max-h-40 overflow-y-auto rounded-md border p-2 scrollbar-thin">
        {skills.length === 0 ? (
          <p className="text-xs text-muted-foreground">No skills available.</p>
        ) : (
          <ul className="space-y-1">
            {skills.map((name) => (
              <li key={name}>
                <Label className="flex cursor-pointer items-center gap-2 text-xs">
                  <Checkbox checked={selected.includes(name)} onCheckedChange={() => toggle(name)} />
                  <span className="font-mono">{name}</span>
                </Label>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}