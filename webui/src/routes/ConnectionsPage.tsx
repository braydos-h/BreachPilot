import { AlertTriangle, Radio, Search } from "lucide-react";
import { Link } from "react-router-dom";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useConnectionsPage } from "@/features/connections/useConnectionsPage";
import { ConnectionsHeader } from "@/features/connections/ConnectionsHeader";
import { ConnectionsToolbar } from "@/features/connections/ConnectionsToolbar";
import { ConnectionsTable } from "@/features/connections/ConnectionsTable";
import { ConnectionCards } from "@/features/connections/ConnectionCards";
import { ConnectionDetailsDrawer } from "@/features/connections/ConnectionDetailsDrawer";
import { ConnectionsSkeleton } from "@/features/connections/ConnectionBits";

export function ConnectionsPage() {
  const page = useConnectionsPage();
  const { connectionsQuery, selectedId, setSelectedId, drawerOpen, setDrawerOpen, isLoading, isError, isEmpty, filtered, sorted, debouncedSearch, filter, clearFilters } = page;

  return (
    <TooltipProvider delayDuration={150}>
      <div className="mx-auto flex max-w-[1600px] flex-col gap-4 p-4 md:p-6">
        <ConnectionsHeader page={page} />
        <ConnectionsToolbar page={page} />

        {isLoading && <ConnectionsSkeleton />}

        {isError && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
            <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" aria-hidden />
            <span className="flex-1 text-destructive">
              {connectionsQuery.error instanceof ApiError ? connectionsQuery.error.message : "Failed to load connections."}
            </span>
            <Button size="sm" variant="outline" onClick={() => void connectionsQuery.refetch()}>
              Retry
            </Button>
          </div>
        )}

        {isEmpty && !isLoading && !isError && (
          <Card className="border-dashed">
            <CardContent className="flex flex-col items-center justify-center gap-3 p-8 text-center">
              <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary">
                <Radio className="h-5 w-5" />
              </span>
              <div className="space-y-1">
                <h2 className="font-medium">No persisted connections</h2>
                <p className="mx-auto max-w-md text-sm leading-relaxed text-muted-foreground">
                  Channels appear here automatically after the persistence phase succeeds in an authorized assessment
                  run. No manual setup is required — check sessions for recent activity.
                </p>
              </div>
              <Button asChild size="sm" variant="outline">
                <Link to="/sessions">View sessions</Link>
              </Button>
            </CardContent>
          </Card>
        )}

        {!isLoading && !isError && !isEmpty && filtered.length === 0 && (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-8 text-center">
            <Search className="h-6 w-6 text-muted-foreground/40" aria-hidden />
            <p className="text-sm font-medium">No connections match your filters</p>
            <p className="text-xs text-muted-foreground">
              {debouncedSearch ? `No results for “${debouncedSearch}”` : `No ${filter} connections found.`} Try
              adjusting filters or search.
            </p>
            <Button size="sm" variant="outline" className="mt-1" onClick={clearFilters}>
              Clear filters
            </Button>
          </div>
        )}

        {!isLoading && !isError && sorted.length > 0 && (
          <>
            <ConnectionsTable page={page} />
            <ConnectionCards page={page} />
          </>
        )}

        {selectedId && (
          <ConnectionDetailsDrawer
            connectionId={selectedId}
            open={drawerOpen}
            onOpenChange={(open) => {
              setDrawerOpen(open);
              if (!open) setSelectedId(null);
            }}
            onRemoveSuccess={() => {
              setDrawerOpen(false);
              setSelectedId(null);
            }}
          />
        )}
      </div>
    </TooltipProvider>
  );
}
