import { useMemo } from "react";
import { useRuns, useTelemetry } from "@/api/hooks";
import { isActiveState, isTerminalState, type RunState } from "@/api/types";
import {
  aggregateRunsByDay,
  aggregateTokensByDay,
  lastNDays,
  ratioPercent,
  timestampMs,
  DAYS,
  RECENT_RUN_COUNT,
  RUN_LIMIT,
} from "./statsAggregations";

/** Stats page state: run + telemetry windows with derived KPIs and charts. */
export function useStatsPage() {
  const runs = useRuns(RUN_LIMIT, 0);
  const telemetry = useTelemetry();
  const rows = runs.data?.runs ?? [];
  const summary = telemetry.data?.summary;
  const recentTelemetry = telemetry.data?.recent ?? [];
  const days = useMemo(() => lastNDays(DAYS), []);
  const runDays = useMemo(() => aggregateRunsByDay(days, rows), [days, rows]);
  const tokenDays = useMemo(() => aggregateTokensByDay(days, recentTelemetry), [days, recentTelemetry]);
  const stateCounts = useMemo(() => {
    const counts = new Map<RunState, number>();
    for (const row of rows) counts.set(row.state, (counts.get(row.state) ?? 0) + 1);
    return counts;
  }, [rows]);
  const recentRuns = useMemo(
    () => [...rows].sort((a, b) => timestampMs(b.created_at) - timestampMs(a.created_at)).slice(0, RECENT_RUN_COUNT),
    [rows],
  );

  const active = rows.filter((row) => isActiveState(row.state)).length;
  const completed = stateCounts.get("completed") ?? 0;
  const failed = stateCounts.get("failed") ?? 0;
  const cancelled = stateCounts.get("cancelled") ?? 0;
  const interrupted = stateCounts.get("interrupted") ?? 0;
  const terminal = rows.filter((row) => isTerminalState(row.state)).length;
  const successRate = ratioPercent(completed, terminal);
  const llmCalls = summary?.calls ?? 0;
  const llmSuccessRate = summary ? ratioPercent(summary.successful_calls, llmCalls) : null;
  const refreshing = runs.isFetching || telemetry.isFetching;
  const runsAvailable = Boolean(runs.data);
  const telemetryAvailable = Boolean(telemetry.data);
  const telemetryEmpty = Boolean(summary && summary.calls === 0 && recentTelemetry.length === 0);

  return {
    runs,
    telemetry,
    rows,
    summary,
    recentTelemetry,
    runDays,
    tokenDays,
    stateCounts,
    recentRuns,
    active,
    completed,
    failed,
    cancelled,
    interrupted,
    terminal,
    successRate,
    llmCalls,
    llmSuccessRate,
    refreshing,
    runsAvailable,
    telemetryAvailable,
    telemetryEmpty,
  };
}

export type StatsPageState = ReturnType<typeof useStatsPage>;
