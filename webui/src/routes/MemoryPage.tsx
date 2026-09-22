import { AlertTriangle, Brain } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ErrorState } from "@/components/Loading";
import { useMemoryPage } from "@/features/memory/useMemoryPage";
import { MemoryHeader } from "@/features/memory/MemoryHeader";
import { MemoryOverviewCards } from "@/features/memory/MemoryOverviewCards";
import { ConfidenceTab } from "@/features/memory/ConfidenceTab";
import { LessonsTab } from "@/features/memory/LessonsTab";
import { AttackMemoryTab } from "@/features/memory/AttackMemoryTab";
import { MemorySkeleton } from "@/features/memory/MemoryStates";
import {
  deriveMemoryOverview,
  filterAndSortAttackMemory,
  filterAndSortConfidence,
  filterAndSortLessons,
  formatMemoryError,
} from "@/features/memory/memoryFilters";

// Re-exported so existing unit tests keep importing from the route module.
export { deriveMemoryOverview, filterAndSortAttackMemory, filterAndSortConfidence, filterAndSortLessons };
export type {
  AttackResultFilter,
  AttackSort,
  ConfidenceSort,
  LessonOutcomeFilter,
  LessonSort,
  MemoryOverview,
} from "@/features/memory/memoryFilters";

export function MemoryPage() {
  const page = useMemoryPage();
  const { memory, overview, rawConfidence, rawLessons, rawAttack, isInitialLoading, hasCached, hasError, isEmptyStore, activeTab, setActiveTab } = page;

  return (
    <TooltipProvider delayDuration={120}>
      <div className="mx-auto max-w-[1600px] space-y-5 p-4 md:p-6">
        <MemoryHeader page={page} />

        {hasError && hasCached && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3" aria-live="polite">
            <ErrorState
              message={formatMemoryError(memory.error, "Could not refresh memory; showing the last loaded snapshot.")}
              onRetry={() => void memory.refetch()}
            />
          </div>
        )}

        {hasError && !hasCached && !isInitialLoading && (
          <Card className="border-destructive/30">
            <CardContent className="flex flex-col gap-3 p-6">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 shrink-0 text-destructive" aria-hidden="true" />
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold">Failed to load memory</h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {formatMemoryError(memory.error, "The memory store could not be loaded.")}
                  </p>
                </div>
              </div>
              <div className="flex justify-end">
                <Button size="sm" variant="outline" onClick={() => void memory.refetch()}>
                  Retry
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {isInitialLoading && <MemorySkeleton />}

        {isEmptyStore && !hasError && (
          <Card>
            <CardContent className="flex flex-col items-center justify-center gap-3 p-8 text-center">
              <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary">
                <Brain className="h-5 w-5" aria-hidden="true" />
              </span>
              <div className="max-w-md">
                <h2 className="font-medium">No memory yet</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  BreachPilot records skill confidence, cross-mission lessons, and attack facts as runs complete. This
                  dashboard will populate once outcomes have been observed.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {!isInitialLoading && !(hasError && !hasCached) && !isEmptyStore && (
          <>
            <section aria-labelledby="memory-overview-heading" className="space-y-3">
              <div>
                <h2 id="memory-overview-heading" className="text-sm font-semibold">
                  Overview
                </h2>
                <p className="text-xs text-muted-foreground">Snapshot of accumulated operator knowledge.</p>
              </div>
              <MemoryOverviewCards overview={overview} loading={isInitialLoading} />
            </section>

            <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-3">
              <div className="overflow-x-auto scrollbar-thin">
                <TabsList className="inline-flex h-auto min-w-full justify-start gap-1 p-1 sm:min-w-0">
                  <TabsTrigger value="confidence" className="gap-2 data-[state=active]:bg-background">
                    Skill confidence
                    <Badge variant="muted" className="ml-1 px-1.5 py-0 text-[11px] font-mono tabular-nums">
                      {rawConfidence.length}
                    </Badge>
                  </TabsTrigger>
                  <TabsTrigger value="lessons" className="gap-2">
                    Lessons
                    <Badge variant="muted" className="ml-1 px-1.5 py-0 text-[11px] font-mono tabular-nums">
                      {rawLessons.length}
                    </Badge>
                  </TabsTrigger>
                  <TabsTrigger value="attack" className="gap-2">
                    Attack memory
                    <Badge variant="muted" className="ml-1 px-1.5 py-0 text-[11px] font-mono tabular-nums">
                      {rawAttack.length}
                    </Badge>
                  </TabsTrigger>
                </TabsList>
              </div>

              <TabsContent value="confidence" className="mt-3 space-y-3 focus-visible:outline-none">
                <ConfidenceTab page={page} />
              </TabsContent>

              <TabsContent value="lessons" className="mt-3 space-y-3 focus-visible:outline-none">
                <LessonsTab page={page} />
              </TabsContent>

              <TabsContent value="attack" className="mt-3 space-y-3 focus-visible:outline-none">
                <AttackMemoryTab page={page} />
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>
    </TooltipProvider>
  );
}
