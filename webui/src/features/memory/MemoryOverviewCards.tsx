import { Activity, BookOpen, Database, Eye, Gauge, Info, Layers3, Target } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { formatMemoryPercent, type MemoryOverview } from "./memoryFilters";

export type MemoryTone = "neutral" | "success" | "danger" | "warning";

export function MemoryOverviewCards({ overview }: { overview: MemoryOverview; loading?: boolean }) {
  const avgLabel =
    overview.avgConfidence == null
      ? "No confidence data"
      : `${formatMemoryPercent(overview.avgConfidence)} average · ${overview.weightedSuccessRate != null ? `${formatMemoryPercent(overview.weightedSuccessRate)} weighted success` : "—"}`;
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      <MemoryStat
        icon={Layers3}
        label="Learned actions"
        value={String(overview.learnedActions)}
        sub={`${overview.observations} observations`}
        help="Distinct action types with recorded outcomes"
      />
      <MemoryStat
        icon={Eye}
        label="Observations"
        value={String(overview.observations)}
        sub={overview.observations > 0 ? "Total recorded outcomes" : "No observations yet"}
      />
      <MemoryStat
        icon={BookOpen}
        label="Recorded lessons"
        value={String(overview.recordedLessons)}
        sub={overview.recordedLessons > 0 ? "Cross-mission learnings" : "No lessons yet"}
      />
      <MemoryStat
        icon={Database}
        label="Attack facts"
        value={String(overview.attackFacts)}
        sub={overview.attackFacts > 0 ? "Extracted facts & artefacts" : "No facts yet"}
      />
      <MemoryStat
        icon={Target}
        label="Known targets"
        value={String(overview.knownTargets)}
        sub={overview.knownTargets > 0 ? "Unique target IPs" : "No target history"}
      />
      <MemoryStat
        icon={Gauge}
        label="Avg confidence"
        value={formatMemoryPercent(overview.avgConfidence)}
        sub={avgLabel}
        tone={
          overview.avgConfidence == null
            ? "neutral"
            : overview.avgConfidence >= 75
              ? "success"
              : overview.avgConfidence >= 45
                ? "warning"
                : "danger"
        }
        help="Mean confidence across learned actions. Weighted success = successes / observations."
      />
    </div>
  );
}

export function MemoryStat({
  icon: Icon,
  label,
  value,
  sub,
  tone = "neutral",
  help,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  sub: string;
  tone?: MemoryTone;
  help?: string;
}) {
  const toneClasses: Record<MemoryTone, { icon: string; value: string; border: string }> = {
    neutral: { icon: "bg-primary/10 text-primary", value: "text-foreground", border: "border-primary/15" },
    success: {
      icon: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
      value: "text-emerald-700 dark:text-emerald-300",
      border: "border-emerald-500/20",
    },
    danger: {
      icon: "bg-destructive/10 text-red-600 dark:text-red-300",
      value: "text-red-600 dark:text-red-300",
      border: "border-destructive/20",
    },
    warning: {
      icon: "bg-amber-500/10 text-amber-700 dark:text-amber-300",
      value: "text-amber-700 dark:text-amber-300",
      border: "border-amber-500/20",
    },
  };
  const classes = toneClasses[tone];
  return (
    <Card className={cn("h-full", classes.border)}>
      <CardContent className="flex min-h-[7.25rem] flex-col justify-between gap-3 p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
            {label}
            {help && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    className="inline-flex h-4 w-4 items-center justify-center rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    aria-label={`${label} information`}
                  >
                    <Info className="h-3 w-3" aria-hidden="true" />
                  </button>
                </TooltipTrigger>
                <TooltipContent className="max-w-[16rem] border border-border bg-popover text-popover-foreground shadow-lg">
                  {help}
                </TooltipContent>
              </Tooltip>
            )}
          </span>
          <span className={cn("flex h-7 w-7 items-center justify-center rounded-md", classes.icon)}>
            <Icon className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
        </div>
        <div className="min-w-0">
          <div className={cn("truncate font-mono text-2xl font-semibold tabular-nums", classes.value)}>{value}</div>
          <div className="mt-1 truncate text-xs text-muted-foreground">{sub}</div>
        </div>
      </CardContent>
    </Card>
  );
}
