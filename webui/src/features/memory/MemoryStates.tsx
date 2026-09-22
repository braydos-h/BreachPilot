import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { SkeletonRows } from "@/components/Loading";

export function MemoryEmptyState({ message }: { message: string }) {
  return (
    <div
      className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground"
      role="status"
      aria-live="polite"
    >
      {message}
    </div>
  );
}

export function MemorySkeleton() {
  return (
    <div className="space-y-5" role="status" aria-label="Loading memory" aria-live="polite">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <Card key={i} className="border-primary/10">
            <CardContent className="flex min-h-[7.25rem] flex-col justify-between gap-3 p-4">
              <div className="flex items-center justify-between">
                <Skeleton className="h-3 w-20" />
                <Skeleton className="h-7 w-7 rounded-md" />
              </div>
              <div className="space-y-2">
                <Skeleton className="h-7 w-16" />
                <Skeleton className="h-3 w-28" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      <Card>
        <CardHeader className="pb-3">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="mt-2 h-3 w-64" />
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Skeleton className="h-8 flex-1" />
            <Skeleton className="h-8 w-32" />
            <Skeleton className="h-8 w-32" />
          </div>
          <SkeletonRows count={5} />
        </CardContent>
      </Card>
    </div>
  );
}
