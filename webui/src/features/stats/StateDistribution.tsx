import { ListChecks } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RunState } from "@/api/types";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { STATE_META, STATE_ORDER, formatCount, formatPercent, ratioPercent } from "./statsAggregations";

export function StateDistribution({ counts, total }: { counts: Map<RunState, number>; total: number }) {
  const entries = [...counts.entries()].sort(
    ([stateA, countA], [stateB, countB]) => countB - countA || STATE_ORDER.indexOf(stateA) - STATE_ORDER.indexOf(stateB),
  );

  return (
    <Card className="h-full">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="text-sm">Run state distribution</CardTitle>
            <CardDescription className="mt-1">How the loaded run window is currently resolving.</CardDescription>
          </div>
          <ListChecks className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {entries.map(([state, count]) => {
          const percentage = ratioPercent(count, total) ?? 0;
          const meta = STATE_META[state];
          return (
            <div key={state} className="space-y-1.5">
              <div className="flex items-center gap-2 text-xs">
                <span className={cn("h-2 w-2 shrink-0 rounded-sm", meta.barClass)} aria-hidden="true" />
                <span className="min-w-0 flex-1 truncate">{meta.label}</span>
                <span className="font-mono tabular-nums text-muted-foreground">{formatCount(count)}</span>
                <span className="w-10 text-right font-mono tabular-nums text-muted-foreground">{formatPercent(percentage)}</span>
              </div>
              <div
                className="h-1.5 overflow-hidden rounded-full bg-muted"
                role="progressbar"
                aria-label={`${meta.label}: ${formatCount(count)} of ${formatCount(total)} runs`}
                aria-valuemin={0}
                aria-valuemax={total}
                aria-valuenow={count}
              >
                <div className={cn("h-full rounded-full transition-[width]", meta.barClass)} style={{ width: `${Math.min(100, percentage)}%` }} />
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
