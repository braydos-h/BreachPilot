import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { formatTokens } from "@/lib/format";
import { DailyStackedBarChart, ChartLegend, ChartTooltip } from "./DailyStackedBarChart";
import { TELEMETRY_LIMIT, formatCount, type DailyChartPoint, type DailyChartSegment, type TokenDay } from "./statsAggregations";

export function TokenUsageChart({ data }: { data: TokenDay[] }) {
  const chartData: DailyChartPoint[] = data.map((point) => ({
    date: point.date,
    total: point.total,
    values: { prompt: point.prompt, completion: point.completion, unattributed: point.unattributed },
  }));
  const hasUnattributed = data.some((point) => point.unattributed > 0);
  // Completion is a categorical identity (prompt vs completion), not a status —
  // emerald stays reserved for success states.
  const segments: DailyChartSegment[] = [
    { key: "prompt", label: "Prompt", className: "bg-primary/75" },
    { key: "completion", label: "Completion", className: "bg-sky-500/80" },
  ];
  if (hasUnattributed) segments.push({ key: "unattributed", label: "Unattributed", className: "bg-muted-foreground/45" });

  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-sm">LLM usage over time</CardTitle>
            <CardDescription className="mt-1">Prompt and completion tokens from the latest {TELEMETRY_LIMIT} recorded calls.</CardDescription>
          </div>
          <Badge variant="muted" className="shrink-0">Recent window</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <DailyStackedBarChart
          data={chartData}
          segments={segments}
          formatValue={formatTokens}
          emptyLabel="No recent token activity"
          ariaLabel="LLM token usage over time chart"
          tooltip={(point) => (
            <ChartTooltip
              date={point.date}
              rows={[
                { label: "Total tokens", value: formatTokens(point.total) },
                { label: "Prompt tokens", value: formatTokens(point.values.prompt ?? 0), colorClass: "bg-primary" },
                { label: "Completion tokens", value: formatTokens(point.values.completion ?? 0), colorClass: "bg-sky-500" },
                ...(hasUnattributed
                  ? [{ label: "Unattributed", value: formatTokens(point.values.unattributed ?? 0), colorClass: "bg-muted-foreground/60" }]
                  : []),
                { label: "Recorded calls", value: formatCount(data.find((item) => item.date === point.date)?.calls ?? 0) },
              ]}
            />
          )}
        />
        <ChartLegend
          items={[
            { label: "Prompt", className: "bg-primary" },
            { label: "Completion", className: "bg-sky-500" },
            ...(hasUnattributed ? [{ label: "Unattributed", className: "bg-muted-foreground/60" }] : []),
          ]}
        />
        <p className="mt-3 text-[11px] text-muted-foreground">This chart is limited to recent telemetry; summary KPIs may include older recorded calls.</p>
      </CardContent>
    </Card>
  );
}
