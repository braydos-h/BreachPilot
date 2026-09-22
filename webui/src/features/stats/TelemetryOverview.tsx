import { Activity, CheckCircle2, Clock3, Coins, Gauge, Layers3, Timer } from "lucide-react";
import { formatRelative } from "@/lib/utils";
import type { TelemetrySummary } from "@/api/types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { formatTokens } from "@/lib/format";
import { ContextMeter, MetricHelp } from "./ContextMeter";
import { formatCount, formatPercent, formatRate, ratioPercent, safeNonNegative } from "./statsAggregations";

export function TelemetryOverview({
  summary,
  recentCount,
}: {
  summary: TelemetrySummary;
  recentCount: number;
}) {
  const callSuccessRate = ratioPercent(summary.successful_calls, summary.calls);
  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm">LLM performance</CardTitle>
        <CardDescription className="mt-1">Summary across recorded telemetry; the chart uses the recent window.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <TelemetryMetric
            icon={CheckCircle2}
            label="Call success rate"
            value={formatPercent(callSuccessRate)}
            sub={`${formatCount(summary.successful_calls)} successful · ${formatCount(summary.failed_calls)} failed`}
          />
          <TelemetryMetric
            icon={Gauge}
            label="Average tokens/sec"
            help="Average generated throughput for calls with a measured token rate."
            value={formatRate(summary.average_tokens_per_second)}
            sub={`${formatCount(summary.calls)} total calls`}
          />
          <TelemetryMetric
            icon={Timer}
            label="Completion tokens/sec"
            help="Average completion-only throughput, separate from prompt processing."
            value={formatRate(summary.average_completion_tokens_per_second)}
            sub="Completion generation"
          />
          <TelemetryMetric
            icon={Layers3}
            label="Prompt tokens"
            value={formatTokens(safeNonNegative(summary.prompt_tokens))}
            sub="Recorded input volume"
          />
          <TelemetryMetric
            icon={Coins}
            label="Completion tokens"
            value={formatTokens(safeNonNegative(summary.completion_tokens))}
            sub="Recorded output volume"
          />
          <TelemetryMetric
            icon={Clock3}
            label="Last LLM call"
            value={formatRelative(summary.last_call_at)}
            sub={recentCount > 0 ? `${recentCount} recent records available` : "No recent records"}
            valueTitle={summary.last_call_at || undefined}
          />
        </div>
        <div className="grid gap-4 border-t pt-4 sm:grid-cols-2">
          <ContextMeter label="Average context usage" value={summary.average_context_usage_pct} />
          <ContextMeter label="Maximum context usage" value={summary.max_context_usage_pct} />
        </div>
      </CardContent>
    </Card>
  );
}

function TelemetryMetric({
  icon: Icon,
  label,
  value,
  sub,
  help,
  valueTitle,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  sub: string;
  help?: string;
  valueTitle?: string;
}) {
  return (
    <div className="min-w-0 rounded-md border bg-card/40 p-3">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3 w-3" aria-hidden="true" />
        <span className="truncate">{label}</span>
        {help && <MetricHelp label={label} help={help} />}
      </div>
      <div className="mt-1 truncate font-mono text-base font-semibold tabular-nums" title={valueTitle}>{value}</div>
      <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{sub}</div>
    </div>
  );
}
