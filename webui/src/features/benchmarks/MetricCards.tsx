// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Dashboard metric cards for a benchmark run summary.
import { AlertTriangle, CheckCircle2, Clock3, Coins, Flame, ListChecks, OctagonAlert, ShieldAlert, Target, Timer } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { formatCost, formatDuration, formatPct } from "@/features/benchmarks/format";
import type { RunSummary } from "@/features/benchmarks/types";

// Formatters live in ./format (shared with tables/charts/pages); re-exported
// here for the established import path.
export { formatCost, formatDuration, formatPct };

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
      <MetricCard
        title="Timeouts"
        value={String(summary.timeout_count)}
        sub={`of ${summary.trials_total} trials`}
        icon={Target}
        tone={summary.timeout_count > 0 ? "warning" : "neutral"}
      />
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
        title="Estimated cost"
        value={formatCost(summary.estimated_cost)}
        sub={`${summary.total_tokens.toLocaleString()} tokens (run total)`}
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

// Reliability cards: stopping judgement, not activity — verified rates,
// scope containment, and reproducibility from the same run summary.
// Every value degrades to "n/a" when the summary predates the signal
// (older persisted summaries carry no stuck/scope/repro fields), so the
// dashboard never renders a fabricated zero as measured.
export function ReliabilityCards({ summary }: MetricCardsProps) {
  const scope = summary.scope_violation_count ?? null;
  const stuckCount = summary.stuck_loop_count ?? null;
  const stuckRate = summary.stuck_loop_rate ?? null;
  const reproRate = summary.reproduced_twice_rate ?? null;
  const reproCount = summary.scenarios_reproduced_twice ?? null;
  const verifiedScenarios = (summary.scenarios ?? []).filter((s) => (s.verified ?? 0) > 0).length;
  const medianActions = summary.median_tool_actions;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6" data-testid="benchmark-reliability-cards">
      <MetricCard
        title="Reproduced twice"
        value={reproRate == null ? "n/a" : formatPct(reproRate)}
        sub={
          reproCount == null
            ? "no repeat data in this summary"
            : `${reproCount}/${verifiedScenarios} scenarios verified on ≥2 trials`
        }
        icon={ListChecks}
        tone={reproRate == null ? "neutral" : reproRate >= 1 ? "success" : reproRate > 0 ? "warning" : "neutral"}
      />
      <MetricCard
        title="Median actions"
        value={medianActions == null ? "n/a" : String(Math.round(medianActions))}
        sub="to verified finding"
        icon={Timer}
      />
      <MetricCard
        title="Stuck loops"
        value={stuckCount == null ? "n/a" : String(stuckCount)}
        sub={stuckRate == null ? "no loop signal in this summary" : `${formatPct(stuckRate)} of completed trials`}
        icon={OctagonAlert}
        tone={stuckCount != null && stuckCount > 0 ? "warning" : "neutral"}
      />
      <MetricCard
        title="Scope violations"
        value={scope == null ? "n/a" : String(scope)}
        sub="reaching network layer (must be 0)"
        icon={ShieldAlert}
        tone={scope == null ? "neutral" : scope > 0 ? "danger" : "success"}
      />
    </div>
  );
}
