import { Badge } from "@/components/ui/badge";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ErrorState } from "@/components/Loading";
import { useStatsPage } from "@/features/stats/useStatsPage";
import { StatsHeader } from "@/features/stats/StatsHeader";
import { KpiOverview } from "@/features/stats/KpiOverview";
import { RunsChart } from "@/features/stats/RunsChart";
import { TokenUsageChart } from "@/features/stats/TokenUsageChart";
import { StateDistribution } from "@/features/stats/StateDistribution";
import { TelemetryOverview } from "@/features/stats/TelemetryOverview";
import { RecentRuns } from "@/features/stats/RecentRuns";
import { ReliabilitySection } from "@/features/stats/ReliabilitySection";
import {
  EmptyRunsState,
  EmptyTelemetryState,
  RunAnalyticsSkeleton,
  TelemetrySkeleton,
  UnavailableCard,
} from "@/features/stats/StatsStates";
import {
  aggregateRunsByDay,
  aggregateTokensByDay,
  formatCount,
  formatTelemetryError,
} from "@/features/stats/statsAggregations";

// Re-exported so existing unit tests keep importing from the route module.
export { aggregateRunsByDay, aggregateTokensByDay };

export function StatsPage() {
  const page = useStatsPage();
  const { runs, telemetry, rows, summary, recentTelemetry, runDays, tokenDays, stateCounts, recentRuns, telemetryEmpty } = page;

  return (
    <TooltipProvider delayDuration={120}>
      <div className="mx-auto max-w-[1600px] space-y-5 p-4 md:p-6">
        <StatsHeader page={page} />

        {(runs.error || telemetry.error) && (
          <div className="space-y-2" aria-live="polite">
            {runs.error && (
              <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3">
                <ErrorState
                  message={runs.data ? "Could not refresh runs; showing the last loaded window." : formatTelemetryError(runs.error, "Failed to load runs.")}
                  onRetry={() => void runs.refetch()}
                />
              </div>
            )}
            {telemetry.error && (
              <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3">
                <ErrorState
                  message={telemetry.data ? "Could not refresh telemetry; showing the last loaded summary." : formatTelemetryError(telemetry.error, "Failed to load telemetry.")}
                  onRetry={() => void telemetry.refetch()}
                />
              </div>
            )}
          </div>
        )}

        <section aria-labelledby="stats-overview-heading" className="space-y-3">
          <div className="flex flex-wrap items-end justify-between gap-2">
            <div>
              <h2 id="stats-overview-heading" className="text-sm font-semibold">Overview</h2>
              <p className="text-xs text-muted-foreground">Loaded run outcomes and model usage.</p>
            </div>
            {runs.data?.total != null && runs.data.total > rows.length && (
              <span className="text-[11px] text-muted-foreground">{formatCount(runs.data.total)} stored runs total</span>
            )}
          </div>
          <KpiOverview page={page} />
        </section>

        {runs.isLoading && !runs.data && <RunAnalyticsSkeleton />}
        {runs.data && rows.length === 0 && <EmptyRunsState />}
        {!runs.data && !runs.isLoading && runs.error && (
          <UnavailableCard title="Run analytics unavailable" message="The run window could not be loaded. Retry when the API is available." />
        )}

        {runs.data && rows.length > 0 && (
          <>
            <section aria-labelledby="run-activity-heading" className="space-y-3">
              <div>
                <h2 id="run-activity-heading" className="text-sm font-semibold">Run activity</h2>
                <p className="text-xs text-muted-foreground">Daily activity across the loaded run window.</p>
              </div>
              <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)]">
                <RunsChart data={runDays} />
                <StateDistribution counts={stateCounts} total={rows.length} />
              </div>
            </section>
            <RecentRuns rows={recentRuns} />
          </>
        )}

        <ReliabilitySection />

        <section aria-labelledby="llm-telemetry-heading" className="space-y-3">
          <div className="flex flex-wrap items-end justify-between gap-2">
            <div>
              <h2 id="llm-telemetry-heading" className="text-sm font-semibold">LLM telemetry</h2>
              <p className="text-xs text-muted-foreground">Generation throughput, context pressure, and recent token flow.</p>
            </div>
            {summary?.aliases.length ? <Badge variant="muted">{summary.aliases.join(", ")}</Badge> : null}
          </div>

          {telemetry.isLoading && !telemetry.data && <TelemetrySkeleton />}
          {telemetry.data && summary && telemetryEmpty && <EmptyTelemetryState />}
          {telemetry.data && summary && !telemetryEmpty && (
            <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)]">
              <TokenUsageChart data={tokenDays} />
              <TelemetryOverview summary={summary} recentCount={recentTelemetry.length} />
            </div>
          )}
          {!telemetry.data && !telemetry.isLoading && telemetry.error && (
            <UnavailableCard title="LLM telemetry unavailable" message="Recent model usage could not be loaded. Retry to restore this section." />
          )}
        </section>
      </div>
    </TooltipProvider>
  );
}
