import { AlertTriangle, CheckCircle2, Clock3, Layers, PlugZap, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { ConnectionsHeaderStat } from "./ConnectionBits";
import type { ConnectionsPageState } from "./useConnectionsPage";

export function ConnectionsHeader({ page }: { page: ConnectionsPageState }) {
  const { connectionsQuery, counts, isLoading } = page;
  return (
    <header className="flex flex-col gap-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <div
            className="hidden h-10 w-10 shrink-0 items-center justify-center rounded-xl border bg-card shadow-sm sm:flex"
            aria-hidden
          >
            <PlugZap className="h-5 w-5 text-foreground" />
          </div>
          <div className="min-w-0">
            <h1 className="text-xl font-semibold leading-tight tracking-tight">Connections</h1>
            <p className="mt-1 max-w-2xl text-sm leading-relaxed text-muted-foreground">
              Persisted operator access channels created during authorized runs. Monitor beacon health and manage
              lifecycle — creations are automatic after successful persistence.
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => void connectionsQuery.refetch()}
            disabled={connectionsQuery.isFetching}
            aria-label="Refresh connections"
            className="h-8 gap-1.5"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", connectionsQuery.isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-4">
        <ConnectionsHeaderStat label="Active" value={counts.active} accent="emerald" Icon={CheckCircle2} loading={isLoading} />
        <ConnectionsHeaderStat label="Stale" value={counts.stale} accent="amber" Icon={Clock3} loading={isLoading} />
        <ConnectionsHeaderStat label="Error" value={counts.error} accent="red" Icon={AlertTriangle} loading={isLoading} />
        <ConnectionsHeaderStat label="Total" value={counts.total} Icon={Layers} loading={isLoading} />
      </div>
    </header>
  );
}
