import { AlertTriangle, Info, OctagonAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { formatPercent } from "./statsAggregations";

export function MetricHelp({ label, help }: { label: string; help: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" className="inline-flex h-4 w-4 items-center justify-center rounded-sm text-muted-foreground hover:text-foreground" aria-label={`${label} information`}>
          <Info className="h-3 w-3" aria-hidden="true" />
        </button>
      </TooltipTrigger>
      <TooltipContent className="max-w-[16rem] border border-border bg-popover text-popover-foreground shadow-lg">{help}</TooltipContent>
    </Tooltip>
  );
}

export function ContextMeter({ label, value }: { label: string; value: number | null }) {
  const percentage = value != null && Number.isFinite(value) ? value : null;
  const clamped = percentage == null ? 0 : Math.min(100, Math.max(0, percentage));
  const level = percentage != null && percentage >= 90 ? "critical" : percentage != null && percentage >= 75 ? "high" : null;
  const LevelIcon = level === "critical" ? OctagonAlert : level === "high" ? AlertTriangle : null;

  return (
    <div>
      <div className="flex items-center justify-between gap-2 text-xs">
        <span className="flex items-center gap-1.5">
          <span className="font-medium">{label}</span>
          <MetricHelp label={label} help="Estimated context tokens as a percentage of the configured model context window. Higher values mean less remaining context, not an automatic error." />
        </span>
        <span className="flex items-center gap-1.5 font-mono font-semibold tabular-nums">
          {formatPercent(percentage)}
          {level && LevelIcon && (
            <span className={cn("inline-flex items-center gap-0.5 text-[10px] uppercase tracking-wide", level === "critical" ? "text-destructive" : "text-amber-700 dark:text-amber-300")}>
              <LevelIcon className="h-3 w-3" aria-hidden />
              {level}
            </span>
          )}
        </span>
      </div>
      <div
        className="mt-2 h-2 overflow-hidden rounded-full bg-muted"
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percentage == null ? undefined : clamped}
        aria-valuetext={percentage == null ? "No context sample" : `${percentage.toFixed(1)} percent`}
      >
        {percentage != null && <div className="h-full rounded-full bg-primary transition-[width]" style={{ width: `${clamped}%` }} />}
      </div>
      <p className="mt-1 text-[10px] text-muted-foreground">Higher means less remaining context.</p>
    </div>
  );
}
