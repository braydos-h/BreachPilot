import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { DailyStackedBarChart, ChartLegend, ChartTooltip } from "./DailyStackedBarChart";
import { DAYS, RUN_LIMIT, formatCount, type DailyChartPoint, type RunDay } from "./statsAggregations";

export function RunsChart({ data }: { data: RunDay[] }) {
  const chartData: DailyChartPoint[] = data.map((point) => ({
    date: point.date,
    total: point.total,
    values: { completed: point.completed, failed: point.failed, other: point.other },
  }));
  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-sm">Runs over time</CardTitle>
            <CardDescription className="mt-1">Created runs by day across the latest {RUN_LIMIT}-run window.</CardDescription>
          </div>
          <Badge variant="muted" className="shrink-0">{DAYS} days</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <DailyStackedBarChart
          data={chartData}
          segments={[
            { key: "completed", label: "Completed", className: "bg-emerald-500/85" },
            { key: "failed", label: "Failed", className: "bg-destructive/85" },
            { key: "other", label: "Other", className: "bg-muted-foreground/45" },
          ]}
          formatValue={formatCount}
          emptyLabel="No run activity in this window"
          ariaLabel="Runs over time chart"
          tooltip={(point) => (
            <ChartTooltip
              date={point.date}
              rows={[
                { label: "Total runs", value: formatCount(point.total) },
                { label: "Completed", value: formatCount(point.values.completed ?? 0), colorClass: "bg-emerald-500" },
                { label: "Failed", value: formatCount(point.values.failed ?? 0), colorClass: "bg-destructive" },
                { label: "Other", value: formatCount(point.values.other ?? 0), colorClass: "bg-muted-foreground/60" },
              ]}
            />
          )}
        />
        <ChartLegend
          items={[
            { label: "Completed", className: "bg-emerald-500" },
            { label: "Failed", className: "bg-destructive" },
            { label: "Other states", className: "bg-muted-foreground/60" },
          ]}
        />
      </CardContent>
    </Card>
  );
}
