import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/Loading";
import type { BenchmarkRunState } from "./useBenchmarkRun";

export function BenchmarkRunSkeleton() {
  return (
    <div className="flex min-h-0 flex-col gap-2 p-2 xl:h-full xl:overflow-hidden" role="status" aria-live="polite">
      <div className="rounded-md border bg-card/50 px-2.5 py-2">
        <div className="flex items-center gap-2">
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-4 w-16 rounded-full" />
        </div>
        <div className="mt-1.5 flex flex-wrap gap-x-2 gap-y-1">
          <Skeleton className="h-3 w-32" />
          <Skeleton className="h-3 w-24" />
          <Skeleton className="h-3 w-28" />
        </div>
      </div>
      <div className="flex flex-1 gap-2 xl:overflow-hidden">
        <div className="flex flex-1 flex-col gap-2">
          <Skeleton className="h-20 rounded-md" />
          <Skeleton className="h-[40vh] flex-1 rounded-md xl:min-h-0" />
        </div>
        <div className="hidden w-[320px] xl:block">
          <Skeleton className="h-[60vh] rounded-md" />
        </div>
      </div>
    </div>
  );
}

export function BenchmarkRunError({ page }: { page: BenchmarkRunState }) {
  const { run } = page;
  return (
    <div className="mx-auto w-full max-w-6xl p-4 md:p-6">
      <ErrorState
        message={run.error instanceof Error ? run.error.message : "Benchmark run not found"}
        onRetry={() => void run.refetch()}
      />
    </div>
  );
}
