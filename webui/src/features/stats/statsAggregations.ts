import { ApiError } from "@/api/client";
import type { RunListRow, RunState, TelemetryRecord } from "@/api/types";

export const RUN_LIMIT = 200;
export const TELEMETRY_LIMIT = 50;
export const DAYS = 14;
export const RECENT_RUN_COUNT = 8;
export const AXIS_RATIOS = [1, 0.75, 0.5, 0.25, 0];

export type Tone = "neutral" | "success" | "danger" | "warning";

export interface RunDay {
  date: string;
  total: number;
  completed: number;
  failed: number;
  other: number;
}

export interface TokenDay {
  date: string;
  total: number;
  prompt: number;
  completion: number;
  unattributed: number;
  calls: number;
}

export interface DailyChartPoint {
  date: string;
  total: number;
  values: Record<string, number>;
}

export interface DailyChartSegment {
  key: string;
  label: string;
  className: string;
}

export interface StateMeta {
  label: string;
  barClass: string;
}

// Each state gets a distinct fixed-order hue — sharing one amber across four
// distinct actives made color meaningless; identity is dot + label regardless.
export const STATE_META: Record<RunState, StateMeta> = {
  draft: { label: "Draft", barClass: "bg-muted-foreground/45" },
  preparing: { label: "Preparing", barClass: "bg-muted-foreground/50" },
  awaiting_confirmation: { label: "Awaiting confirmation", barClass: "bg-amber-500/80" },
  queued: { label: "Queued", barClass: "bg-sky-500/75" },
  running: { label: "Running", barClass: "bg-primary/80" },
  awaiting_input: { label: "Awaiting input", barClass: "bg-violet-500/75" },
  completed: { label: "Completed", barClass: "bg-emerald-500/85" },
  failed: { label: "Failed", barClass: "bg-destructive/85" },
  cancelled: { label: "Cancelled", barClass: "bg-slate-500/75" },
  interrupted: { label: "Interrupted", barClass: "bg-orange-500/80" },
  cancelling: { label: "Cancelling", barClass: "bg-amber-500/60" },
};

export const STATE_ORDER: RunState[] = [
  "running",
  "queued",
  "awaiting_confirmation",
  "awaiting_input",
  "cancelling",
  "completed",
  "failed",
  "cancelled",
  "interrupted",
  "draft",
];

const chartDateFormatter = new Intl.DateTimeFormat(undefined, { month: "numeric", day: "numeric" });
const fullDateFormatter = new Intl.DateTimeFormat(undefined, {
  weekday: "short",
  month: "short",
  day: "numeric",
  year: "numeric",
});

export function dayKey(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

export function dayKeyFromValue(value?: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : dayKey(date);
}

function dateFromKey(value: string): Date {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(year ?? 0, (month ?? 1) - 1, day ?? 1);
}

export function formatChartDay(value: string): string {
  return chartDateFormatter.format(dateFromKey(value));
}

export function formatFullDay(value: string): string {
  return fullDateFormatter.format(dateFromKey(value));
}

export function lastNDays(n: number): string[] {
  const now = new Date();
  const out: string[] = [];
  for (let i = n - 1; i >= 0; i -= 1) {
    out.push(dayKey(new Date(now.getFullYear(), now.getMonth(), now.getDate() - i)));
  }
  return out;
}

export function safeNonNegative(value: number | null | undefined): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, value) : 0;
}

export function timestampMs(value?: string): number {
  if (!value) return Number.NEGATIVE_INFINITY;
  const time = Date.parse(value);
  return Number.isNaN(time) ? Number.NEGATIVE_INFINITY : time;
}

export function formatCount(value: number): string {
  return Math.round(value).toLocaleString();
}

export function formatPercent(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  return `${Math.round(value)}%`;
}

export function ratioPercent(numerator: number, denominator: number): number | null {
  return denominator > 0 ? (numerator / denominator) * 100 : null;
}

export function formatRate(value: number | null | undefined): string {
  return value != null && Number.isFinite(value) ? `${value.toFixed(1)} tok/s` : "—";
}

export function formatTelemetryError(error: unknown, fallback: string): string {
  return error instanceof ApiError && error.message ? error.message : fallback;
}

export function aggregateRunsByDay(days: string[], rows: RunListRow[]): RunDay[] {
  const points = days.map<RunDay>((date) => ({ date, total: 0, completed: 0, failed: 0, other: 0 }));
  const byDate = new Map(points.map((point) => [point.date, point]));
  for (const row of rows) {
    const point = byDate.get(dayKeyFromValue(row.created_at) ?? "");
    if (!point) continue;
    point.total += 1;
    if (row.state === "completed") point.completed += 1;
    else if (row.state === "failed") point.failed += 1;
    else point.other += 1;
  }
  return points;
}

export function aggregateTokensByDay(days: string[], records: TelemetryRecord[]): TokenDay[] {
  const points = days.map<TokenDay>((date) => ({
    date,
    total: 0,
    prompt: 0,
    completion: 0,
    unattributed: 0,
    calls: 0,
  }));
  const byDate = new Map(points.map((point) => [point.date, point]));
  for (const record of records) {
    const point = byDate.get(dayKeyFromValue(record.started_at ?? record.ended_at) ?? "");
    if (!point) continue;
    const prompt = safeNonNegative(record.prompt_tokens);
    const completion = safeNonNegative(record.completion_tokens);
    const reportedTotal = safeNonNegative(record.total_tokens);
    point.prompt += prompt;
    point.completion += completion;
    point.total += Math.max(reportedTotal, prompt + completion);
    point.calls += 1;
  }
  for (const point of points) {
    point.unattributed = Math.max(0, point.total - point.prompt - point.completion);
  }
  return points;
}
