import { Activity, CheckCircle2, Coins, Gauge, HeartPulse, XCircle } from "lucide-react";
import { formatTokens } from "@/lib/format";
import { StatCard } from "./StatCard";
import { formatCount, formatPercent, formatRate, safeNonNegative } from "./statsAggregations";
import type { StatsPageState } from "./useStatsPage";

export function KpiOverview({ page }: { page: StatsPageState }) {
  const {
    runsAvailable,
    telemetryAvailable,
    runs,
    telemetry,
    rows,
    active,
    completed,
    terminal,
    successRate,
    failed,
    cancelled,
    interrupted,
    summary,
    llmCalls,
    llmSuccessRate,
  } = page;
  const failureDetails =
    [cancelled > 0 ? `${cancelled} cancelled` : null, interrupted > 0 ? `${interrupted} interrupted` : null]
      .filter(Boolean)
      .join(" · ") || "No cancellations or interruptions";
  const llmFailureCount = summary?.failed_calls ?? 0;
  const llmSuccessCount = summary?.successful_calls ?? 0;

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      <StatCard
        icon={Activity}
        label="Runs loaded"
        value={String(rows.length)}
        sub={`${active} active`}
        tone="neutral"
        loading={runs.isLoading && !runs.data}
        available={runsAvailable}
      />
      <StatCard
        icon={CheckCircle2}
        label="Success rate"
        value={formatPercent(successRate)}
        sub={terminal > 0 ? `${completed} completed · ${terminal} terminal` : "No terminal runs yet"}
        tone="success"
        loading={runs.isLoading && !runs.data}
        available={runsAvailable}
      />
      <StatCard
        icon={XCircle}
        label="Failed runs"
        value={String(failed)}
        sub={failureDetails}
        tone="danger"
        loading={runs.isLoading && !runs.data}
        available={runsAvailable}
      />
      <StatCard
        icon={Coins}
        label="LLM volume"
        value={summary ? formatTokens(safeNonNegative(summary.total_tokens)) : "—"}
        sub={
          telemetryAvailable
            ? `${formatCount(llmCalls)} calls · ${formatTokens(safeNonNegative(summary?.prompt_tokens))} prompt`
            : "Telemetry unavailable"
        }
        tone="neutral"
        loading={telemetry.isLoading && !telemetry.data}
        available={telemetryAvailable}
      />
      <StatCard
        icon={HeartPulse}
        label="LLM reliability"
        value={formatPercent(llmSuccessRate)}
        sub={
          telemetryAvailable
            ? `${formatCount(llmSuccessCount)} successful · ${formatCount(llmFailureCount)} failed`
            : "Telemetry unavailable"
        }
        tone={llmFailureCount > 0 ? "warning" : "success"}
        loading={telemetry.isLoading && !telemetry.data}
        available={telemetryAvailable}
      />
      <StatCard
        icon={Gauge}
        label="Throughput"
        value={summary ? formatRate(summary.average_tokens_per_second) : "—"}
        sub={summary ? `completion ${formatRate(summary.average_completion_tokens_per_second)}` : "Telemetry unavailable"}
        tone="neutral"
        loading={telemetry.isLoading && !telemetry.data}
        available={telemetryAvailable}
      />
    </div>
  );
}
