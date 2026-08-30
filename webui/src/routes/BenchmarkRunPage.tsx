// NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi
// Benchmark run detail: live progress, summary, config/environment, per-scenario
// results, structured timeline, evidence links, replay manifest, baseline result.
// Optimized: incremental event polling (single fetch per tick, not 10), progressive
// skeletons, live progress header always visible.
import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { Clock3, FlaskConical, GitCommitHorizontal, Loader2, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, SkeletonRows } from "@/components/Loading";
import { fetchRun, fetchRunEvents, cancelBenchmarkRun, saveBaseline, fetchOverview } from "@/features/benchmarks/api";
import { MetricCards, formatDuration } from "@/features/benchmarks/MetricCards";
import { ScenarioResultsTable, StatusBadge } from "@/features/benchmarks/ScenarioResultsTable";
import { BenchmarkTimeline } from "@/features/benchmarks/BenchmarkTimeline";
import type { BenchmarkEvent, RunDetail, Trial } from "@/features/benchmarks/types";
import { formatRelative } from "@/lib/utils";

const REFRESH_MS = 2000;

function isRunActive(status: string): boolean {
  return status === "running" || status === "starting" || status === "cancelling";
}

function derivePhases(trial: Trial | undefined): Array<{ label: string; state: "done" | "running" | "pending" }> {
  // Phase view for the currently-running trial: provision -> exploit -> verify.
  if (!trial) {
    return [
      { label: "Provision", state: "pending" },
      { label: "Exploit", state: "pending" },
      { label: "Verify", state: "pending" },
    ];
  }
  const done = trial.ended_at !== "";
  return [
    { label: "Provision", state: "done" },
    { label: "Exploit", state: done ? "done" : "running" },
    { label: "Verify", state: done ? "done" : "pending" },
  ];
}

export function BenchmarkRunPage() {
  const { runId = "" } = useParams();
  const queryClient = useQueryClient();

  const run = useQuery({
    queryKey: ["benchmarks", "run", runId],
    queryFn: () => fetchRun(runId),
    enabled: !!runId,
    placeholderData: keepPreviousData,
    staleTime: 5_000,
    gcTime: 5 * 60_000,
    refetchInterval: (query) => {
      const data = query.state.data as RunDetail | undefined;
      return data && (isRunActive(data.status) || !data.summary) ? REFRESH_MS : false;
    },
  });

  const overview = useQuery({
    queryKey: ["benchmarks", "overview"],
    queryFn: fetchOverview,
    placeholderData: keepPreviousData,
    staleTime: 15_000,
    refetchInterval: (query) => {
      const active = query.state.data?.active;
      // Only poll overview fast when this run is the active one
      if (active?.run_id === runId && isRunActive(active.state)) return REFRESH_MS;
      // When run itself is active but overview hasn't caught up yet, keep polling slowly
      if (run.data && isRunActive(run.data.status)) return REFRESH_MS;
      return false;
    },
  });

  // Incremental events: first load fetches full history (paginated once),
  // subsequent polls fetch only `after=latest_sequence` and append.
  const events = useQuery<{ events: BenchmarkEvent[]; latest_sequence?: number }>({
    queryKey: ["benchmarks", "run-events", runId],
    queryFn: async (): Promise<{ events: BenchmarkEvent[]; latest_sequence?: number }> => {
      const cached = queryClient.getQueryData<{ events: BenchmarkEvent[]; latest_sequence?: number }>([
        "benchmarks",
        "run-events",
        runId,
      ]);
      const hasCached = !!cached?.events?.length;
      if (hasCached) {
        const cursor = cached?.latest_sequence ?? (cached?.events[cached.events.length - 1]?.sequence ?? 0);
        const data = await fetchRunEvents(runId, { after: cursor, limit: 1000 });
        if (data.events.length === 0) return cached as { events: BenchmarkEvent[]; latest_sequence?: number };
        const merged = [...(cached?.events ?? []), ...data.events];
        // Deduplicate by sequence just in case
        const seen = new Set<number>();
        const deduped: BenchmarkEvent[] = [];
        for (const e of merged) {
          if (!seen.has(e.sequence)) {
            seen.add(e.sequence);
            deduped.push(e);
          }
        }
        return { events: deduped, latest_sequence: data.latest_sequence };
      }
      // Initial load: paginate once up to 5k events (5 pages) — only on first fetch
      let cursor = 0;
      let all: BenchmarkEvent[] = [];
      let latest = 0;
      for (let page = 0; page < 5; page++) {
        const data = await fetchRunEvents(runId, { after: cursor, limit: 1000 });
        all = all.concat(data.events);
        latest = data.latest_sequence;
        if (data.events.length < 1000) break;
        cursor = data.latest_sequence;
      }
      return { events: all, latest_sequence: latest };
    },
    enabled: !!runId,
    placeholderData: keepPreviousData,
    staleTime: 2_000,
    refetchInterval: () => {
      if (!run.data) return 2000;
      return isRunActive(run.data.status) ? REFRESH_MS : false;
    },
  });

  const isActiveRun = (overview.data?.active.run_id === runId && isRunActive(overview.data.active.state)) || (run.data ? isRunActive(run.data.status) : false);

  const activeTrial: Trial | undefined = useMemo(() => {
    const trials = run.data?.trials ?? [];
    return [...trials].reverse().find((t) => !t.ended_at);
  }, [run.data?.trials]);

  if (run.isLoading && !run.data) {
    return (
      <div className="mx-auto w-full max-w-6xl space-y-6 p-4 md:p-6">
        <div className="flex items-center gap-2 text-sm text-muted-foreground" aria-live="polite">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading benchmark run {runId}…
        </div>
        <Card><CardContent className="py-6"><Skeleton className="h-12 w-full" /></CardContent></Card>
        <Card><CardContent className="py-6"><SkeletonRows count={4} /></CardContent></Card>
        <Card><CardContent className="py-6"><SkeletonRows count={6} /></CardContent></Card>
      </div>
    );
  }
  if (run.isError || !run.data) {
    return (
      <div className="mx-auto w-full max-w-6xl p-4 md:p-6">
        <ErrorState
          message={run.error instanceof Error ? run.error.message : "Benchmark run not found"}
          onRetry={() => void run.refetch()}
        />
      </div>
    );
  }

  const data = run.data;
  const summary = data.summary;
  const env = data.environment;
  const manifest = data.replay_manifest;
  const phases = derivePhases(activeTrial);

  const onCancel = async () => {
    await cancelBenchmarkRun(runId);
    void run.refetch();
  };
  const onSaveBaseline = async () => {
    await saveBaseline(runId);
    void run.refetch();
  };

  const totalTrials = data.config.trials * Math.max(1, data.scenario_ids.length || data.trials.length || 1);
  const completedTrials = data.trials.filter((t) => t.ended_at).length;
  const progressPct = totalTrials > 0 ? Math.min(100, Math.round((completedTrials / totalTrials) * 100)) : 0;
  const elapsedSec = events.data?.events?.length ? events.data.events[events.data.events.length - 1]?.elapsed_seconds ?? 0 : 0;
  const eventCount = events.data?.events.length ?? 0;

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 p-4 md:p-6">
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <Link to="/benchmarks" className="text-sm text-muted-foreground underline-offset-4 hover:underline">
            Benchmarks
          </Link>
          <span className="text-muted-foreground">/</span>
          <h1 className="flex items-center gap-2 font-mono text-lg font-semibold">
            <FlaskConical className="h-4 w-4 text-primary" />
            {data.run_id}
          </h1>
          <StatusBadge status={isRunActive(data.status) ? "SKIPPED" : data.status === "completed" ? "VERIFIED" : "FAILED"} />
          <span className="text-xs text-muted-foreground">
            {data.suite} · {data.trials[0]?.started_at ? formatRelative(data.trials[0].started_at) : formatRelative(data.config.suite ? new Date().toISOString() : "")}
          </span>
          {isActiveRun && <span className="flex items-center gap-1 text-xs text-yellow-300"><Loader2 className="h-3 w-3 animate-spin" /> live</span>}
          {isActiveRun ? (
            <Button size="sm" variant="destructive" className="ml-auto" onClick={onCancel}>
              <XCircle className="h-4 w-4" />
              Cancel run
            </Button>
          ) : summary ? (
            <Button size="sm" variant="outline" className="ml-auto" onClick={onSaveBaseline}>
              Save as baseline
            </Button>
          ) : null}
        </div>
        {isActiveRun ? (
          <div className="space-y-2">
            <div className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-sm text-yellow-300">
              <Loader2 className="h-4 w-4 animate-spin shrink-0" />
              <span>Benchmark run in progress — {completedTrials}/{totalTrials} trials completed{activeTrial ? ` · now: ${activeTrial.scenario_id}` : ""}</span>
              <span className="ml-auto flex items-center gap-2 text-xs tabular-nums">
                <Clock3 className="h-3 w-3" /> {formatDuration(elapsedSec)} · {eventCount} events
              </span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div className="h-full bg-yellow-500 transition-all duration-500" style={{ width: `${progressPct}%` }} />
            </div>
          </div>
        ) : run.isFetching ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> refreshing…</div>
        ) : null}
      </header>

      {/* Live view — always show when active, with progress details */}
      {isActiveRun && (
        <Card data-testid="benchmark-live-view" className="border-yellow-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">Live progress <span className="h-2 w-2 animate-pulse rounded-full bg-yellow-400" /></CardTitle>
            <CardDescription>
              Operational events only — structured reasoning metadata, never raw chain-of-thought. Polling every 2s · {eventCount} events
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap items-center gap-3 rounded-md bg-muted/30 px-3 py-2 text-sm">
              {activeTrial ? (
                <>
                  <span className="font-mono text-xs font-medium">{activeTrial.scenario_id}</span>
                  <span className="text-muted-foreground">trial {activeTrial.trial_index + 1}</span>
                  <div className="flex gap-1.5" aria-label="Phases">
                    {phases.map((p) => (
                      <span
                        key={p.label}
                        className={
                          p.state === "done"
                            ? "rounded bg-emerald-500/15 px-1.5 py-0.5 text-emerald-500"
                            : p.state === "running"
                              ? "rounded bg-yellow-500/15 px-1.5 py-0.5 text-yellow-300"
                              : "rounded bg-muted px-1.5 py-0.5 text-muted-foreground"
                        }
                      >
                        {p.label} {p.state === "done" ? "✓" : p.state === "running" ? "●" : "○"}
                      </span>
                    ))}
                  </div>
                  <span className="ml-auto text-xs tabular-nums text-muted-foreground">
                    {completedTrials}/{totalTrials} trials · actions: {activeTrial.tool_calls} · sandbox:{" "}
                    {activeTrial.sandbox.enabled ? "healthy" : activeTrial.sandbox.required ? "required" : "disabled"}
                  </span>
                </>
              ) : (
                <span className="text-xs text-muted-foreground">Waiting for first trial… · {completedTrials}/{totalTrials} completed · {eventCount} events</span>
              )}
            </div>
            <BenchmarkTimeline
              events={(events.data as { events: BenchmarkEvent[] } | undefined)?.events ?? []}
              isLoading={events.isLoading && !((events.data as { events: BenchmarkEvent[] } | undefined)?.events?.length)}
              maxEvents={30}
            />
            {events.isFetching && <div className="flex items-center gap-1 text-[11px] text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> fetching new events…</div>}
          </CardContent>
        </Card>
      )}

      {/* Summary — show skeletons while running */}
      {summary ? (
        <section className="space-y-3" aria-label="Run summary">
          <MetricCards summary={summary} />
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Failure categories</CardTitle>
              <CardDescription>Why unverified trials failed — drives what to build next.</CardDescription>
            </CardHeader>
            <CardContent>
              {Object.keys(summary.failure_categories).length === 0 ? (
                <div className="text-sm text-muted-foreground">No categorized failures.</div>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {Object.entries(summary.failure_categories).map(([cat, count]) => (
                    <Badge key={cat} variant={cat === "FALSE_POSITIVE" ? "destructive" : "secondary"} className="font-mono text-[11px]">
                      {cat}: {count}
                    </Badge>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </section>
      ) : isActiveRun ? (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">Run summary</CardTitle><CardDescription>Summary computed after trials complete · {completedTrials}/{totalTrials} done</CardDescription></CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6"><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /></div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> waiting for trials to finish…</div>
          </CardContent>
        </Card>
      ) : null}

      {/* Scenario results */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Scenario results</CardTitle>
          <CardDescription>
            Verified outcomes from the independent oracle. “Agent claimed” is recorded separately for false-positive
            detection.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScenarioResultsTable trials={data.trials} />
        </CardContent>
      </Card>

      {/* Configuration + environment (reproducibility) */}
      <div className="grid gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Configuration</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-y-1.5 text-sm">
              <dt className="text-muted-foreground">Suite</dt>
              <dd className="font-mono text-xs">{data.config.suite}</dd>
              <dt className="text-muted-foreground">Trials</dt>
              <dd className="tabular-nums">{data.config.trials}</dd>
              <dt className="text-muted-foreground">Timeout</dt>
              <dd className="tabular-nums">{formatDuration(data.config.timeout_seconds)}</dd>
              <dt className="text-muted-foreground">Scenarios</dt>
              <dd className="font-mono text-xs">{data.config.scenario_ids.join(", ") || "all"}</dd>
              {data.config.tags.length > 0 && (
                <>
                  <dt className="text-muted-foreground">Tags</dt>
                  <dd className="font-mono text-xs">{data.config.tags.join(", ")}</dd>
                </>
              )}
              <dt className="text-muted-foreground">Sandbox required</dt>
              <dd>{data.config.sandbox_required ? "yes" : "no"}</dd>
              <dt className="text-muted-foreground">Replay command</dt>
              <dd className="col-span-2 font-mono text-xs text-muted-foreground">{manifest?.replay_command ?? "n/a"}</dd>
            </dl>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <GitCommitHorizontal className="h-4 w-4" />
              Environment (reproducibility pins)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-y-1.5 text-sm">
              <dt className="text-muted-foreground">Git SHA</dt>
              <dd className="font-mono text-xs">
                {env.git_sha}
                {env.git_dirty ? " (dirty)" : ""}
              </dd>
              <dt className="text-muted-foreground">Model</dt>
              <dd className="font-mono text-xs">
                {env.model_provider} / {env.model_id} ({env.model_alias})
              </dd>
              <dt className="text-muted-foreground">Model version</dt>
              <dd className="font-mono text-xs">{env.model_version}</dd>
              <dt className="text-muted-foreground">Config hash</dt>
              <dd className="font-mono text-xs">{env.config_hash}</dd>
              <dt className="text-muted-foreground">Sandbox image</dt>
              <dd className="font-mono text-xs">
                {env.sandbox_image} @ {env.sandbox_image_digest}
              </dd>
              <dt className="text-muted-foreground">Sandbox</dt>
              <dd>
                {env.sandbox_enabled ? "enabled" : "disabled"}
                {env.sandbox_required ? " (required)" : ""}
              </dd>
              <dt className="text-muted-foreground">Platform</dt>
              <dd className="text-xs">
                {env.platform} · Python {env.python_version}
              </dd>
            </dl>
          </CardContent>
        </Card>
      </div>

      {/* Full timeline — incremental, shows what's happening */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">Mission timeline</CardTitle>
            <span className="text-xs tabular-nums text-muted-foreground">{eventCount} events {events.isFetching ? "· updating…" : ""}</span>
          </div>
          <CardDescription>Structured events across all scenario trials — increments live while the run is active.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <BenchmarkTimeline events={(events.data as { events: BenchmarkEvent[] } | undefined)?.events ?? []} isLoading={events.isLoading && !((events.data as { events: BenchmarkEvent[] } | undefined)?.events?.length)} maxEvents={400} />
          {events.isFetching && (events.data as { events: BenchmarkEvent[] } | undefined)?.events?.length ? <div className="flex items-center gap-1 text-[11px] text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> polling for new events…</div> : null}
        </CardContent>
      </Card>
    </div>
  );
}
