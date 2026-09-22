import { BarChart3, RefreshCw } from "lucide-react";
import { cn, formatRelative } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { RUN_LIMIT, TELEMETRY_LIMIT } from "./statsAggregations";
import type { StatsPageState } from "./useStatsPage";

export function StatsHeader({ page }: { page: StatsPageState }) {
  const { runs, telemetry, refreshing } = page;
  return (
    <header className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex min-w-0 items-start gap-2.5">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border bg-card">
          <BarChart3 className="h-5 w-5 text-primary" />
        </div>
        <div className="min-w-0">
          <h1 className="text-lg font-semibold leading-tight">Stats</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">Operational activity and LLM efficiency at a glance.</p>
          <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-muted-foreground">
            <span className="font-mono">Last {RUN_LIMIT} runs</span>
            <span aria-hidden="true">·</span>
            <span className="font-mono">Last {TELEMETRY_LIMIT} LLM calls</span>
            {telemetry.dataUpdatedAt > 0 && (
              <>
                <span aria-hidden="true">·</span>
                <span>telemetry updated {formatRelative(new Date(telemetry.dataUpdatedAt).toISOString())}</span>
              </>
            )}
          </div>
        </div>
      </div>
      <Button
        size="sm"
        variant="outline"
        className="self-start sm:mt-0"
        onClick={() => void Promise.allSettled([runs.refetch(), telemetry.refetch()])}
        disabled={refreshing}
        aria-label="Refresh runs and telemetry"
      >
        <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
        <span>Refresh</span>
      </Button>
    </header>
  );
}
