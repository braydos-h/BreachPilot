import { AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { ConnectionStatusBadge } from "./ConnectionStatusBadge";
import {
  ConnectionDangerZone,
  ConnectionHealthCheck,
  ConnectionRemoveDialog,
} from "./ConnectionDrawerActions";
import {
  ConnectionIdentitySection,
  ConnectionNetworkSection,
  ConnectionProvenanceSection,
  ConnectionTimelineSection,
} from "./ConnectionDrawerSections";
import { ConnectionListenerOutput } from "./ConnectionListenerOutput";
import { humanizeMethod } from "./connectionFormat";
import { useConnectionDrawer } from "./useConnectionDrawer";

export function ConnectionDetailsDrawer({
  connectionId,
  open,
  onOpenChange,
  onRemoveSuccess,
}: {
  connectionId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onRemoveSuccess: () => void;
}) {
  const drawer = useConnectionDrawer(connectionId, open, { onRemoveSuccess });
  const { conn, connQuery, guidance } = drawer;

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent
          className={cn(
            "flex max-h-[90vh] max-w-[560px] flex-col gap-0 overflow-hidden p-0",
            "data-[state=open]:animate-in data-[state=closed]:animate-out",
            "sm:max-w-[560px]",
            "md:fixed md:inset-y-0 md:right-0 md:left-auto md:top-0 md:h-dvh md:max-h-dvh md:w-[520px] md:max-w-[92vw] md:translate-x-0 md:translate-y-0 md:rounded-l-lg md:rounded-r-none md:border-l",
          )}
          aria-describedby={undefined}
        >
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
            <div className="shrink-0 border-b px-5 py-4">
              <div className="flex items-start justify-between gap-3 pr-6">
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold tracking-tight">Connection Details</h2>
                  <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={connectionId}>
                    {connectionId}
                  </p>
                  {conn && (
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                      <span className="font-mono font-medium">{conn.target_ip}</span>
                      <span className="text-muted-foreground">·</span>
                      <span>{humanizeMethod(conn.method)}</span>
                    </div>
                  )}
                </div>
                {conn && <ConnectionStatusBadge status={conn.status} />}
              </div>
              {guidance && (
                <div
                  className={cn(
                    "mt-3 rounded-md border px-3 py-2 text-xs leading-relaxed",
                    guidance.tone === "emerald" && "border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300",
                    guidance.tone === "amber" && "border-amber-500/20 bg-amber-500/5 text-amber-700 dark:text-amber-300",
                    guidance.tone === "red" && "border-destructive/20 bg-destructive/5 text-destructive",
                    guidance.tone === "muted" && "border-border bg-muted/30 text-muted-foreground",
                  )}
                >
                  {guidance.text}
                </div>
              )}
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto scrollbar-thin">
              {connQuery.isLoading && (
                <div className="space-y-3 p-5" role="status" aria-label="Loading connection">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-4 w-1/2" />
                  <Skeleton className="h-20 w-full" />
                  <Skeleton className="h-32 w-full" />
                </div>
              )}
              {connQuery.error && (
                <div className="p-5">
                  <div className="flex items-center gap-2 text-sm text-destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <span>{connQuery.error instanceof ApiError ? connQuery.error.message : "Failed to load connection."}</span>
                  </div>
                  <Button size="sm" variant="outline" className="mt-3" onClick={() => void connQuery.refetch()}>
                    Retry
                  </Button>
                </div>
              )}
              {conn && (
                <div className="space-y-5 p-5">
                  <ConnectionIdentitySection drawer={drawer} />
                  <ConnectionProvenanceSection drawer={drawer} />
                  <ConnectionNetworkSection drawer={drawer} />
                  <ConnectionTimelineSection drawer={drawer} />
                  <ConnectionHealthCheck drawer={drawer} />
                  <ConnectionListenerOutput drawer={drawer} />
                  <ConnectionDangerZone drawer={drawer} />
                </div>
              )}
            </div>

            <div className="shrink-0 border-t bg-card px-5 py-3">
              <Button variant="outline" size="sm" className="w-full" onClick={() => onOpenChange(false)}>
                Close
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <ConnectionRemoveDialog drawer={drawer} />
    </>
  );
}
