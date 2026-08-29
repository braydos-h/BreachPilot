// NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi
// Benchmark run detail: live progress, summary, config/environment, per-scenario
// results, structured timeline, evidence links, replay manifest, baseline result.
import { useMemo } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { FlaskConical, GitCommitHorizontal, Loader2, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState, Spinner } from "@/components/Loading";
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

  const run = useQuery({
    queryKey: ["benchmarks", "run", runId],
    queryFn: () => fetchRun(runId),
    enabled: !!runId,
    refetchInterval: (query) => {
      const data = query.state.data as RunDetail | undefined;
      // Live while the service reports this run as active, or the stored run
      // has no terminal status yet.
      return data && (isRunActive(data.status) || !data.summary) ? REFRESH_MS : false;
    },
  });


  const overview = useQuery({
    queryKey: ["benchmarks", "overview"],
    queryFn: fetchOverview,
    refetchInterval: REFRESH_MS,
  });

  const events = useQuery({
    queryKey: ["benchmarks", "run-events", runId],
    queryFn: async () => {
      let cursor = 0;
      let all: BenchmarkEvent[] = [];
      for (let page = 0; page < 10; page++) {
        const data = await fetchRunEvents(runId, { after: cursor, limit: 1000 });
        all = all.concat(data.events);
        if (data.events.length === 0) break;
        cursor = data.latest_sequence;
      }
      return { events: all };
    },
    enabled: !!runId,
    refetchInterval: () => (run.data && isRunActive(run.data.status) ? REFRESH_MS : false),
  });

  const isActiveRun = overview.data?.active.run_id === runId && isRunActive(overview.data.active.state);

  const activeTrial: Trial | undefined = useMemo(() => {
    const trials = run.data?.trials ?? [];
    return [...trials].reverse().find((t) => !t.ended_at);
  }, [run.data?.trials]);

  if (run.isLoading) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <Spinner label="Loading benchmark run…" />
      </div>
    );
  }
  if (run.isError || !run.data) {
    return (
      <ErrorState
        message={run.error instanceof Error ? run.error.message : "Benchmark run not found"}
        onRetry={() => void run.refetch()}
      />
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

  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 p-4 md:p-6">
      <header className="space-y-1">
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
            {data.suite} · {data.trials[0]?.started_at ? formatRelative(data.trials[0].started_at) : ""}
          </span>
          {isActiveRun && (
            <Button size="sm" variant="destructive" className="ml-auto" onClick={onCancel}>
              <XCircle className="h-4 w-4" />
              Cancel run
            </Button>
          )}
          {!isActiveRun && summary && (
            <Button size="sm" variant="outline" className="ml-auto" onClick={onSaveBaseline}>
              Save as baseline
            </Button>
          )}
        </div>
        {isActiveRun && (
          <div className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-1.5 text-sm text-yellow-300">
            <Loader2 className="h-4 w-4 animate-spin" />
            Benchmark run in progress — live updates below.
          </div>
        )}
      </header>

      {/* Live view */}
      {isActiveRun && (
        <Card data-testid="benchmark-live-view">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Live progress</CardTitle>
            <CardDescription>
              Operational events only — structured reasoning metadata, never raw chain-of-thought.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {activeTrial && (
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-mono text-xs">{activeTrial.scenario_id}</span>
                <span className="text-muted-foreground">
                  trial {activeTrial.trial_index + 1}
                </span>
                <div className="flex gap-1.5" aria-label="Phases">
                  {phases.map((p) => (
                    <span
                      key={p.label}
                      className={
                        p.state === "done"
                          ? "text-emerald-500"
                          : p.state === "running"
                            ? "text-yellow-300"
                            : "text-muted-foreground"
                      }
                    >
                      {p.label} {p.state === "done" ? "✓" : p.state === "running" ? "running" : "pending"}
                    </span>
                  ))}
                </div>
                <span className="ml-auto text-xs text-muted-foreground">
                  actions: {activeTrial.tool_calls} · sandbox:{" "}
                  {activeTrial.sandbox.enabled ? "healthy" : activeTrial.sandbox.required ? "required" : "disabled"}
                </span>
              </div>
            )}
            <BenchmarkTimeline events={events.data?.events ?? []} isLoading={events.isLoading} maxEvents={25} />
          </CardContent>
        </Card>
      )}

      {/* Summary */}
      {summary && (
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
      )}

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

      {/* Full timeline */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Mission timeline</CardTitle>
          <CardDescription>Structured events across all scenario trials (use the filter per trial).</CardDescription>
        </CardHeader>
        <CardContent>
          <BenchmarkTimeline events={events.data?.events ?? []} isLoading={events.isLoading} maxEvents={400} />
        </CardContent>
      </Card>
    </div>
  );
}
