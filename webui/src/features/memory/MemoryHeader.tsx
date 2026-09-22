import { Brain, RefreshCw } from "lucide-react";
import { cn, formatRelative } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import type { MemoryPageState } from "./useMemoryPage";

export function MemoryHeader({ page }: { page: MemoryPageState }) {
  const { memory, overview, isRefreshing } = page;
  return (
    <header className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex min-w-0 items-start gap-2.5">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border bg-card">
          <Brain className="h-5 w-5 text-primary" aria-hidden="true" />
        </div>
        <div className="min-w-0">
          <h1 className="text-lg font-semibold leading-tight">Memory &amp; Experience</h1>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Knowledge accumulated across attacks and missions — confidence, lessons, and extracted facts.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-muted-foreground">
            <span className="font-mono">
              {overview.learnedActions} actions · {overview.recordedLessons} lessons · {overview.attackFacts} facts
            </span>
            {memory.dataUpdatedAt > 0 && (
              <>
                <span aria-hidden="true">·</span>
                <span>updated {formatRelative(new Date(memory.dataUpdatedAt).toISOString())}</span>
              </>
            )}
            {isRefreshing && (
              <>
                <span aria-hidden="true">·</span>
                <span className="inline-flex items-center gap-1">
                  <RefreshCw className="h-3 w-3 animate-spin" aria-hidden="true" /> refreshing
                </span>
              </>
            )}
          </div>
        </div>
      </div>
      <Button
        size="sm"
        variant="outline"
        className="self-start sm:mt-0"
        onClick={() => void memory.refetch()}
        disabled={memory.isFetching}
        aria-label="Refresh memory"
      >
        <RefreshCw className={cn("h-3.5 w-3.5", memory.isFetching && "animate-spin")} aria-hidden="true" />
        <span>Refresh</span>
      </Button>
    </header>
  );
}
