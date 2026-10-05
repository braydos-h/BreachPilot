// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Benchmark history charts (verified rate / FP rate / solve time / cost over runs).
// Pure SVG sparkline — no chart library dependency (same as components/run/Sparkline).
import { formatRelative } from "@/lib/utils";
import { formatCost, formatDuration, formatPct } from "@/features/benchmarks/format";
import type { RunIndexRow } from "@/features/benchmarks/types";

interface ChartProps {
  runs: RunIndexRow[];
  extract: (run: RunIndexRow) => number | null;
  format?: (v: number) => string;
  label: string;
}

const W = 320;
const H = 64;

function computePath(values: Array<number | null>): { segments: { points: string; marker: { x: number; y: number } | null }[]; min: number; max: number } {
  const finite = values.filter((v): v is number => v !== null && Number.isFinite(v));
  if (finite.length === 0) return { segments: [], min: 0, max: 0 };
  let min = Math.min(...finite);
  let max = Math.max(...finite);
  if (min === max) {
    min -= 1;
    max += 1;
  }
  const span = max - min;
  const segments: { points: string; marker: { x: number; y: number } | null }[] = [];
  let segment: { x: number; y: number }[] = [];
  values.forEach((value, i) => {
    if (value === null || !Number.isFinite(value)) {
      if (segment.length > 0) {
        segments.push({
          points: segment.map(({ x, y }) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" "),
          marker: segment.length === 1 ? (segment[0] ?? null) : null,
        });
      }
      segment = [];
      return;
    }
    const x = values.length === 1 ? W / 2 : (i / (values.length - 1)) * (W - 4) + 2;
    const y = H - 4 - ((value - min) / span) * (H - 8);
    segment.push({ x, y });
  });
  if (segment.length > 0) {
    segments.push({
      points: segment.map(({ x, y }) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" "),
      marker: segment.length === 1 ? (segment[0] ?? null) : null,
    });
  }
  return { segments, min, max };
}

export function HistoryChart({ runs, extract, format, label }: ChartProps) {
  const ordered = [...runs].reverse(); // oldest -> newest
  const valuesByRun = ordered.map((run) => {
    const value = extract(run);
    return value !== null && Number.isFinite(value) ? value : null;
  });
  const measuredRuns = valuesByRun.filter((value) => value !== null);
  const values = measuredRuns;
  if (values.length < 2) {
    return (
      <div className="rounded-lg border p-4" data-testid={`history-${label}`}>
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
        <div className="py-4 text-center text-xs text-muted-foreground">
          {values.length === 0 ? "No data recorded for this metric yet." : "Not enough data points yet (need ≥ 2 runs)."}
        </div>
      </div>
    );
  }
  const { segments, min, max } = computePath(valuesByRun);
  const latest = valuesByRun[valuesByRun.length - 1] ?? null;
  const latestRun = ordered[ordered.length - 1];
  const first = values[0] ?? 0;
  // Flat series are padded by ±1 for the line path — never show that
  // synthetic padding as a numeric range ("$-0.99 – $1.01" for two $0.01
  // costs would be nonsense).
  const flat = values.every((v) => v === values[0]);
  const range = flat
    ? (format ? format(first) : first.toLocaleString())
    : `${format ? format(min) : min.toLocaleString()} – ${format ? format(max) : max.toLocaleString()}`;
  return (
    <div className="rounded-lg border p-4" data-testid={`history-${label}`}>
      <div className="flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</span>
        <span className="text-sm font-medium tabular-nums">{latest === null ? "n/a" : format ? format(latest) : latest.toLocaleString()}</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="mt-2 h-16 w-full" role="img" aria-label={`${label} over benchmark runs: latest ${latest === null ? "n/a" : format ? format(latest) : latest.toLocaleString()}, range ${range}`}>
        <title>{`${label}: latest ${latest === null ? "n/a" : format ? format(latest) : latest.toLocaleString()} (${range})`}</title>
        {segments.map((segment, i) => (
          <g key={i}>
            {segment.marker ? (
              <circle
                cx={segment.marker.x.toFixed(1)}
                cy={segment.marker.y.toFixed(1)}
                r="3"
                className="fill-primary"
                data-testid="history-chart-point"
              />
            ) : (
              <polyline
                points={segment.points}
                fill="none"
                stroke="currentColor"
                strokeWidth={1.5}
                strokeLinejoin="round"
                strokeLinecap="round"
                vectorEffect="non-scaling-stroke"
                className="text-primary/80"
              />
            )}
          </g>
        ))}
      </svg>
      <ul className="sr-only" aria-label={`${label} values by run`}>
        {ordered.map((run, index) => {
          const value = valuesByRun[index] ?? null;
          return <li key={run.run_id}>{run.run_id}: {value === null ? "unavailable" : format ? format(value) : value}</li>;
        })}
      </ul>
      <div className="mt-1 flex items-center justify-between text-[10px] text-muted-foreground">
        <span>
          {measuredRuns.length} measured runs · latest {formatRelative(latestRun?.timestamp ?? "")}
        </span>
        <span className="tabular-nums">{range}</span>
      </div>
    </div>
  );
}

export interface HistoryChartsProps {
  runs: RunIndexRow[];
}

export function HistoryCharts({ runs }: HistoryChartsProps) {
  const completed = runs.filter((r) => r.status === "completed");
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4" data-testid="benchmark-history">
      <HistoryChart
        runs={completed}
        label="Verified success rate"
        extract={(r) => (r.trials_completed == null ? null : r.verified_success_rate)}
        format={(v) => formatPct(v)}
      />
      <HistoryChart
        runs={completed}
        label="False-positive rate"
        extract={(r) => (r.trials_completed == null ? null : r.false_positive_rate)}
        format={(v) => formatPct(v)}
      />
      <HistoryChart
        runs={completed}
        label="Median solve time"
        extract={(r) => r.median_solve_time}
        format={(v) => formatDuration(v)}
      />
      <HistoryChart runs={completed} label="Cost" extract={(r) => r.estimated_cost} format={(v) => formatCost(v)} />
    </div>
  );
}
