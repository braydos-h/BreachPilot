import { Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { MetricCards, formatCost, formatDuration, formatPct } from "@/features/benchmarks/MetricCards";
import type { BenchmarkRunState } from "./useBenchmarkRun";

export function BenchmarkOverviewTab({ page }: { page: BenchmarkRunState }) {
  const { summary, isActiveRun, completedTrials, totalTrials } = page;
  if (summary) {
    return (
      <>
        <MetricCards summary={summary} />
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Failure categories</CardTitle>
            <CardDescription>Why unverified trials failed — drives what to build next.</CardDescription>
          </CardHeader>
          <CardContent>
            {Object.keys(summary.failure_categories).length === 0 ? (
              <div className="text-sm text-muted-foreground">No categorized failures.</div>
            ) : (
              <div className="flex flex-wrap gap-2">
                {Object.entries(summary.failure_categories).map(([cat, count]) => (
                  <Badge
                    key={cat}
                    variant={cat === "FALSE_POSITIVE" ? "destructive" : "secondary"}
                    className="font-mono text-[11px]"
                  >
                    {cat}: {count}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Summary</CardTitle>
            <CardDescription>
              {summary.solved}/{summary.trials_total} verified · {formatPct(summary.verified_success_rate)} success ·{" "}
              {formatPct(summary.false_positive_rate)} false positives
            </CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
            <div>
              <div className="text-xs text-muted-foreground">Median solve</div>
              <div className="font-medium tabular-nums">{formatDuration(summary.median_solve_time)}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Mean solve</div>
              <div className="font-medium tabular-nums">{formatDuration(summary.mean_solve_time)}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Tokens</div>
              <div className="font-medium tabular-nums">{summary.total_tokens.toLocaleString()}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Cost</div>
              <div className="font-medium tabular-nums">{formatCost(summary.estimated_cost)}</div>
            </div>
          </CardContent>
        </Card>
      </>
    );
  }
  if (isActiveRun) {
    return (
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Run summary</CardTitle>
          <CardDescription>
            Summary computed after trials complete · {completedTrials}/{totalTrials} done
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" /> waiting for trials to finish…
          </div>
        </CardContent>
      </Card>
    );
  }
  return (
    <Card>
      <CardContent className="py-8 text-center text-sm text-muted-foreground">
        No summary yet — run hasn't completed.
      </CardContent>
    </Card>
  );
}
