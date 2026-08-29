// NetAttackAI by @braydos-h — https://github.com/braydos-h/NetAttackAi
// Dashboard metric cards for a benchmark run summary.
import { AlertTriangle, CheckCircle2, Clock3, Coins, Flame, ShieldAlert, Target } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { RunSummary } from "@/features/benchmarks/types";

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "n/a";
  const s = Math.round(seconds);
  const minutes = Math.floor(s / 60);
  const secs = s % 60;
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${String(minutes % 60).padStart(2, "0")}m`;
  }
  return `${minutes}m ${String(secs).padStart(2, "0")}s`;
}

export function formatCost(value: number | null | undefined): string {
  if (value === null || value === undefined) return "n/a";
  return `$${value.toFixed(2)}`;
}

export function formatPct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined) return "n/a";
  return `${(value * 100).toFixed(digits)}%`;
}

interface MetricCardProps {
  title: string;
  value: string;
  sub?: string;
  icon: React.ComponentType<{ className?: string }>;
  tone?: "neutral" | "success" | "danger" | "warning";
}

export function MetricCard({ title, value, sub, icon: Icon, tone = "neutral" }: MetricCardProps) {
  const toneClass =
    tone === "success"
      ? "text-emerald-500"
      : tone === "danger"
        ? "text-red-500"
        : tone === "warning"
          ? "text-amber-500"
          : "text-primary";
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-1">
        <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{title}</CardTitle>
        <Icon className={cn("h-4 w-4", toneClass)} />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        {sub && <div className="mt-0.5 text-xs text-muted-foreground">{sub}</div>}
      </CardContent>
    </Card>
  );
}

export interface MetricCardsProps {
  summary: RunSummary;
}

export function MetricCards({ summary }: MetricCardsProps) {
  const fpTone = summary.false_positive_rate > 0.02 ? "danger" : summary.false_positive_rate > 0 ? "warning" : "success";
  const infraTone = summary.infra_error_count > 0 ? "warning" : "neutral";
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6" data-testid="benchmark-metric-cards">
      <MetricCard
        title="Verified success"
        value={formatPct(summary.verified_success_rate)}
        sub={`${summary.solved}/${summary.trials_total} trials verified`}
        icon={CheckCircle2}
        tone="success"
      />
      <MetricCard title="Solved" value={String(summary.solved)} sub={`${summary.trials_total} trials`} icon={Target} />
      <MetricCard
        title="False positives"
        value={formatPct(summary.false_positive_rate)}
        sub="claimed but unverified"
        icon={AlertTriangle}
        tone={fpTone}
      />
      <MetricCard
        title="Median solve time"
        value={formatDuration(summary.median_solve_time)}
        sub="across verified trials"
        icon={Clock3}
      />
      <MetricCard
        title="Average cost"
        value={formatCost(summary.estimated_cost)}
        sub={`${summary.total_tokens.toLocaleString()} tokens`}
        icon={Coins}
      />
      <MetricCard
        title="Sandbox violations"
        value={String(summary.sandbox_blocked_actions)}
        sub={`${summary.infra_error_count} infra errors`}
        icon={summary.sandbox_blocked_actions > 0 ? ShieldAlert : Flame}
        tone={summary.sandbox_blocked_actions > 0 ? "danger" : infraTone}
      />
    </div>
  );
}
