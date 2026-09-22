import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  AXIS_RATIOS,
  formatChartDay,
  formatFullDay,
  safeNonNegative,
  type DailyChartPoint,
  type DailyChartSegment,
} from "./statsAggregations";

export function DailyStackedBarChart({
  data,
  segments,
  formatValue,
  emptyLabel,
  ariaLabel,
  tooltip,
}: {
  data: DailyChartPoint[];
  segments: DailyChartSegment[];
  formatValue: (value: number) => string;
  emptyLabel: string;
  ariaLabel: string;
  tooltip: (point: DailyChartPoint) => ReactNode;
}) {
  const max = Math.max(1, ...data.map((point) => point.total));
  const hasData = data.some((point) => point.total > 0);

  return (
    <div className="space-y-2">
      <div className="relative h-64" role="group" aria-label={ariaLabel}>
        <div className="absolute bottom-6 left-8 right-0 top-0" aria-hidden="true">
          {AXIS_RATIOS.map((ratio) => (
            <div key={ratio} className="absolute inset-x-0 border-t border-border/70" style={{ top: `${(1 - ratio) * 100}%` }}>
              <span className="absolute -left-8 -top-2 w-7 text-right text-[9px] tabular-nums text-muted-foreground">
                {formatValue(max * ratio)}
              </span>
            </div>
          ))}
        </div>
        <div className="absolute bottom-6 left-8 right-0 top-0 flex gap-1.5">
          {data.map((point) => {
            const stackTotal = segments.reduce((total, segment) => total + safeNonNegative(point.values[segment.key]), 0);
            const breakdown = segments
              .map((segment) => `${segment.label} ${formatValue(safeNonNegative(point.values[segment.key]))}`)
              .join(", ");
            const ariaLabelForPoint = `${formatFullDay(point.date)}: ${formatValue(point.total)} total, ${breakdown}`;
            return (
              <Tooltip key={point.date}>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    className="group flex h-full min-w-0 flex-1 flex-col justify-end rounded-sm p-0.5 text-left outline-none transition-colors hover:bg-primary/5 focus-visible:bg-primary/10"
                    aria-label={ariaLabelForPoint}
                  >
                    {point.total > 0 && stackTotal > 0 ? (
                      <div
                        className="flex w-full flex-col-reverse gap-px overflow-hidden rounded-t-sm border border-foreground/10 bg-background p-px shadow-sm transition-[filter] group-hover:brightness-110 group-focus-visible:brightness-110"
                        style={{ height: `${Math.max(6, (point.total / max) * 100)}%` }}
                      >
                        {segments.map((segment) => {
                          const value = safeNonNegative(point.values[segment.key]);
                          if (value === 0) return null;
                          return <div key={segment.key} className={segment.className} style={{ height: `${(value / stackTotal) * 100}%` }} />;
                        })}
                      </div>
                    ) : (
                      <div className="h-px w-full bg-border" aria-hidden="true" />
                    )}
                  </button>
                </TooltipTrigger>
                <TooltipContent side="top" align="center" className="min-w-[12rem] border border-border bg-popover text-popover-foreground shadow-lg">
                  {tooltip(point)}
                </TooltipContent>
              </Tooltip>
            );
          })}
        </div>
        <div className="absolute bottom-0 left-8 right-0 flex h-6 gap-1.5" aria-hidden="true">
          {data.map((point) => (
            <span key={point.date} className="min-w-0 flex-1 truncate text-center text-[9px] tabular-nums text-muted-foreground">
              {formatChartDay(point.date)}
            </span>
          ))}
        </div>
        {!hasData && (
          <div className="pointer-events-none absolute bottom-8 left-8 right-0 top-0 flex items-center justify-center">
            <span className="rounded-md border border-dashed bg-background/80 px-3 py-2 text-xs text-muted-foreground">{emptyLabel}</span>
          </div>
        )}
      </div>
    </div>
  );
}

export function ChartTooltip({
  date,
  rows,
}: {
  date: string;
  rows: Array<{ label: string; value: string; colorClass?: string }>;
}) {
  return (
    <div className="space-y-1.5">
      <div className="font-medium">{formatFullDay(date)}</div>
      <div className="space-y-1">
        {rows.map((row) => (
          <div key={row.label} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <span className={cn("h-1.5 w-1.5 rounded-sm", row.colorClass ?? "bg-muted-foreground")} aria-hidden="true" />
              {row.label}
            </span>
            <span className="font-mono tabular-nums">{row.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ChartLegend({ items }: { items: Array<{ label: string; className: string }> }) {
  return (
    <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[11px] text-muted-foreground" aria-label="Chart legend">
      {items.map((item) => (
        <span key={item.label} className="inline-flex items-center gap-1.5">
          <span className={cn("h-2 w-2 rounded-sm", item.className)} aria-hidden="true" />
          {item.label}
        </span>
      ))}
    </div>
  );
}
