// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Benchmark run detail — tabbed like the normal run page (RunPage).
// Layout: header + live bar, main tabs (Overview/Trials/Timeline/Evidence/Config)
// + aside telemetry. Route composes feature hooks + tab components below.
import { BarChart3, FileSearch, FlaskConical, ScrollText, Settings2 } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useBenchmarkRun } from "@/features/benchmarks/useBenchmarkRun";
import { BenchmarkRunHeader } from "@/features/benchmarks/BenchmarkRunHeader";
import { BenchmarkLiveStrip, BenchmarkRunBanners } from "@/features/benchmarks/BenchmarkRunBanners";
import { BenchmarkOverviewTab } from "@/features/benchmarks/BenchmarkOverviewTab";
import { BenchmarkConfigTab } from "@/features/benchmarks/BenchmarkConfigTab";
import { BenchmarkEvidenceTab, BenchmarkTimelineTab, BenchmarkTrialsTab } from "@/features/benchmarks/BenchmarkResultTabs";
import { BenchmarkRunAside } from "@/features/benchmarks/BenchmarkRunAside";
import { BenchmarkRunError, BenchmarkRunSkeleton } from "@/features/benchmarks/BenchmarkRunStates";

export function BenchmarkRunPage() {
  const page = useBenchmarkRun();
  const { run, tab, setTab, events, runScenarios } = page;

  if (run.isLoading && !run.data) {
    return <BenchmarkRunSkeleton />;
  }
  if (run.isError || !run.data) {
    return <BenchmarkRunError page={page} />;
  }

  return (
    <div className="flex min-h-0 flex-col gap-2 p-2 xl:h-full xl:flex-1 xl:overflow-hidden">
      <BenchmarkRunHeader page={page} />
      <BenchmarkRunBanners page={page} />

      <div className="flex min-h-0 flex-1 flex-col gap-2 xl:flex-row xl:overflow-hidden">
        <div className="flex min-w-0 flex-1 flex-col gap-2 xl:min-h-0 xl:overflow-hidden">
          {(events.isError || runScenarios.isError) && (
            <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
              {events.isError && (
                <span>
                  Live events unavailable: {events.error instanceof Error ? events.error.message : "fetch failed"}.{" "}
                </span>
              )}
              {runScenarios.isError && (
                <span>
                  Live trial results unavailable:{" "}
                  {runScenarios.error instanceof Error ? runScenarios.error.message : "fetch failed"}.
                </span>
              )}
              <button
                type="button"
                className="ml-2 underline underline-offset-4"
                onClick={() => {
                  void events.refetch();
                  void runScenarios.refetch();
                }}
              >
                Retry
              </button>
            </div>
          )}

          <BenchmarkLiveStrip page={page} />

          <Tabs
            value={tab}
            onValueChange={setTab}
            className="flex min-h-[280px] flex-col overflow-hidden rounded-md border bg-card/30 xl:min-h-0 xl:flex-1"
          >
            <div className="shrink-0 border-b bg-muted/30">
              <ScrollArea type="scroll" className="w-full">
                <TabsList className="h-7 bg-transparent p-0.5">
                  <TabsTrigger value="overview" className="h-6 px-2 py-0 text-xs">
                    <BarChart3 className="mr-1 h-3 w-3" /> Overview
                  </TabsTrigger>
                  <TabsTrigger value="trials" className="h-6 px-2 py-0 text-xs">
                    <FlaskConical className="mr-1 h-3 w-3" /> Trials
                  </TabsTrigger>
                  <TabsTrigger value="timeline" className="h-6 px-2 py-0 text-xs">
                    <ScrollText className="mr-1 h-3 w-3" /> Timeline
                  </TabsTrigger>
                  <TabsTrigger value="evidence" className="h-6 px-2 py-0 text-xs">
                    <FileSearch className="mr-1 h-3 w-3" /> Evidence
                  </TabsTrigger>
                  <TabsTrigger value="config" className="h-6 px-2 py-0 text-xs">
                    <Settings2 className="mr-1 h-3 w-3" /> Config
                  </TabsTrigger>
                </TabsList>
              </ScrollArea>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden p-2 scrollbar-thin">
              <TabsContent value="overview" className="mt-0 space-y-3">
                <BenchmarkOverviewTab page={page} />
              </TabsContent>

              <TabsContent value="trials" className="mt-0">
                <BenchmarkTrialsTab page={page} />
              </TabsContent>

              <TabsContent value="timeline" className="mt-0 space-y-2">
                <BenchmarkTimelineTab page={page} />
              </TabsContent>

              <TabsContent value="evidence" className="mt-0 space-y-3">
                <BenchmarkEvidenceTab page={page} />
              </TabsContent>

              <TabsContent value="config" className="mt-0">
                <BenchmarkConfigTab page={page} />
              </TabsContent>
            </div>
          </Tabs>
        </div>

        <BenchmarkRunAside page={page} />
      </div>
    </div>
  );
}
