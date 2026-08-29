// NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi
// Run-benchmark panel: suite/scenario selection, trials, model, sandbox, baseline options.
import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { FlaskConical, Loader2, Play } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchSuiteScenarios, startBenchmarkRun } from "@/features/benchmarks/api";
import type { ScenarioInfo, SuiteInfo } from "@/features/benchmarks/types";
import { cn } from "@/lib/utils";

export interface RunBenchmarkPanelProps {
  suites: SuiteInfo[];
  active: { run_id: string | null; state: string; error: string };
  defaultModel?: string;
}

export function RunBenchmarkPanel({ suites, active, defaultModel }: RunBenchmarkPanelProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [suite, setSuite] = useState(suites[0]?.suite_id ?? "");
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [selectedScenarios, setSelectedScenarios] = useState<Set<string>>(new Set());
  const [selectedTags, setSelectedTags] = useState<Set<string>>(new Set());
  const [loadingScenarios, setLoadingScenarios] = useState(false);
  const [trials, setTrials] = useState(1);
  const [model, setModel] = useState(defaultModel ?? "");
  const [sandboxRequired, setSandboxRequired] = useState(true);
  const [checkRegression, setCheckRegression] = useState(false);
  const [saveBaseline, setSaveBaseline] = useState(false);

  const busy = active.state === "running" || active.state === "starting" || active.state === "cancelling";

  const loadScenarios = async (suiteId: string) => {
    setSelectedScenarios(new Set());
    setScenarios([]);
    if (!suiteId) return;
    setLoadingScenarios(true);
    try {
      const data = await fetchSuiteScenarios(suiteId);
      setScenarios(data.scenarios);
    } catch {
      setScenarios([]);
    } finally {
      setLoadingScenarios(false);
    }
  };

  const allTags = useMemo(() => {
    const tags = new Set<string>();
    for (const s of scenarios) for (const t of s.tags) tags.add(t);
    return [...tags].sort();
  }, [scenarios]);

  const visibleScenarios = useMemo(() => {
    if (selectedTags.size === 0) return scenarios;
    return scenarios.filter((s) => s.tags.some((t) => selectedTags.has(t)));
  }, [scenarios, selectedTags]);

  const startRun = useMutation({
    mutationFn: () =>
      startBenchmarkRun({
        suite,
        scenarios: [...selectedScenarios],
        tags: [...selectedTags],
        trials,
        model: model || undefined,
        sandbox_required: sandboxRequired,
        save_baseline: saveBaseline,
        check_regression: checkRegression,
      }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["benchmarks"] });
      if (data.run_id) navigate(`/benchmarks/${data.run_id}`);
    },
  });

  const suiteInfo = suites.find((s) => s.suite_id === suite);
  const selectedCount = selectedTags.size > 0 ? visibleScenarios.length - selectedScenarios.size || visibleScenarios.length : selectedScenarios.size;

  return (
    <Card data-testid="run-benchmark-panel">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <FlaskConical className="h-4 w-4 text-primary" />
          Run benchmark
        </CardTitle>
        <CardDescription>
          Runs verified, sandboxed missions against lab targets and records reproducible metrics. Authorized lab
          environments only.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="bench-suite">Benchmark suite</Label>
            <select
              id="bench-suite"
              value={suite}
              disabled={busy}
              onChange={(e) => {
                setSuite(e.target.value);
                void loadScenarios(e.target.value);
              }}
              className="h-9 w-full rounded-md border bg-background px-2 text-sm"
            >
              <option value="">Select suite…</option>
              {suites.map((s) => (
                <option key={s.suite_id} value={s.suite_id}>
                  {s.suite_id} ({s.scenarios} scenarios)
                </option>
              ))}
            </select>
            {suiteInfo?.invalid_manifests ? (
              <p className="text-[11px] text-amber-500">{suiteInfo.invalid_manifests} invalid manifest(s) ignored.</p>
            ) : null}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="bench-model">Model alias</Label>
            <Input
              id="bench-model"
              value={model}
              disabled={busy}
              onChange={(e) => setModel(e.target.value)}
              placeholder={defaultModel || "default alias"}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="bench-trials">Trials per scenario</Label>
            <Input
              id="bench-trials"
              type="number"
              min={1}
              max={20}
              value={trials}
              disabled={busy}
              onChange={(e) => setTrials(Math.max(1, Math.min(20, Number(e.target.value) || 1)))}
            />
            <p className="text-[11px] text-muted-foreground">Repeated trials give per-scenario confidence intervals.</p>
          </div>
          <div className="space-y-2 pt-1">
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={sandboxRequired} disabled={busy} onCheckedChange={(v) => setSandboxRequired(v === true)} />
              Sandbox required
              <span className="text-[11px] text-muted-foreground">(no host-execution fallback)</span>
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={saveBaseline} disabled={busy} onCheckedChange={(v) => setSaveBaseline(v === true)} />
              Save as baseline
            </label>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={checkRegression} disabled={busy} onCheckedChange={(v) => setCheckRegression(v === true)} />
              Check regression vs baseline
            </label>
          </div>
        </div>

        {loadingScenarios && <div className="text-sm text-muted-foreground">Loading scenarios…</div>}
        {visibleScenarios.length > 0 && (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Tag filters">
              {allTags.map((tag) => (
                <button
                  key={tag}
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setSelectedTags((prev) => {
                      const next = new Set(prev);
                      if (next.has(tag)) next.delete(tag);
                      else next.add(tag);
                      return next;
                    });
                  }}
                  className={cn(
                    "rounded-full px-2 py-0.5 text-[11px] transition-colors",
                    selectedTags.has(tag)
                      ? "bg-primary/15 text-primary"
                      : "bg-muted/60 text-muted-foreground hover:text-foreground",
                  )}
                >
                  {tag}
                </button>
              ))}
            </div>
            <div className="max-h-40 space-y-1 overflow-y-auto rounded-lg border p-2">
              {visibleScenarios.map((s) => (
                <label key={s.scenario_id} className="flex items-center gap-2 rounded px-1 py-0.5 text-sm hover:bg-muted/40">
                  <Checkbox
                    checked={selectedScenarios.has(s.scenario_id) || selectedTags.size > 0}
                    disabled={busy}
                    onCheckedChange={(v) => {
                      setSelectedScenarios((prev) => {
                        const next = new Set(prev);
                        if (v === true) next.add(s.scenario_id);
                        else next.delete(s.scenario_id);
                        return next;
                      });
                    }}
                  />
                  <span className="font-mono text-xs">{s.scenario_id}</span>
                  <span className="truncate text-muted-foreground">{s.name}</span>
                  <span className="ml-auto text-[10px] uppercase tracking-wide text-muted-foreground">{s.difficulty}</span>
                </label>
              ))}
            </div>
          </div>
        )}

        {active.error && busy && (
          <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">{active.error}</div>
        )}

        <div className="flex items-center gap-3">
          <Button disabled={busy || !suite || startRun.isPending} onClick={() => startRun.mutate()} data-testid="run-benchmark-button">
            {startRun.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Run Benchmark
          </Button>
          {busy && <span className="text-sm text-amber-500">A benchmark run is active — watch progress on its page.</span>}
          <span className="ml-auto text-xs text-muted-foreground">
            {selectedCount > 0 ? `~${selectedCount} scenario(s) × ${trials} trial(s)` : `${suiteInfo?.scenarios ?? 0} scenario(s) × ${trials} trial(s)`}
          </span>
        </div>
        {startRun.isError && (
          <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            {startRun.error instanceof Error ? startRun.error.message : "Failed to start benchmark run."}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
