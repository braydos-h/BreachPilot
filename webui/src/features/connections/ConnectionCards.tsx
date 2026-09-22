import { Activity, Eye } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { ConnectionStatusBadge } from "./ConnectionStatusBadge";
import { beaconDotClass, formatAge, formatBeacon, humanizeMethod } from "./connectionFormat";
import type { ConnectionsPageState } from "./useConnectionsPage";

export function ConnectionCards({ page }: { page: ConnectionsPageState }) {
  const { sorted, openDrawer } = page;
  return (
    <div className="grid gap-3 md:hidden">
      {sorted.map((conn) => (
        <Card
          key={conn.connection_id}
          className="group cursor-pointer overflow-hidden bg-card/40 transition-colors hover:border-primary/20 focus-within:ring-2 focus-within:ring-ring"
          onClick={() => openDrawer(conn.connection_id)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              openDrawer(conn.connection_id);
            }
          }}
          aria-label={`Open details for ${conn.target_ip}`}
        >
          <CardContent className="space-y-2.5 p-3">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <span
                    className={cn("h-1.5 w-1.5 rounded-full", beaconDotClass(conn.last_beacon, conn.status))}
                    aria-hidden
                  />
                  <span className="truncate font-mono text-sm font-semibold">{conn.target_ip}</span>
                </div>
                <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">{humanizeMethod(conn.method)}</span>
                  {conn.os_family && (
                    <>
                      <span>·</span>
                      <span className="capitalize">{conn.os_family}</span>
                    </>
                  )}
                  {conn.mitre_technique && (
                    <>
                      <span>·</span>
                      <span className="font-mono text-[11px]">{conn.mitre_technique}</span>
                    </>
                  )}
                </div>
              </div>
              <ConnectionStatusBadge status={conn.status} />
            </div>

            <div className="grid gap-1.5 rounded-md border bg-muted/20 p-2">
              <div className="flex items-center justify-between gap-2 text-xs">
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Callback</span>
                <span className="truncate font-mono text-xs">
                  {conn.callback_host}:{conn.callback_port}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2 text-xs">
                <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Listener</span>
                <span className="max-w-[10rem] truncate font-mono text-xs" title={conn.listener_name}>
                  {conn.listener_name || "—"}
                </span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
              <span className="inline-flex items-center gap-1.5 tabular-nums">
                <Activity className="h-3 w-3 text-muted-foreground" aria-hidden />
                {formatBeacon(conn.last_beacon)}
              </span>
              <span className="text-muted-foreground">·</span>
              <span className="tabular-nums text-muted-foreground">{formatAge(conn.created_at)} ago</span>
              <span className="ml-auto inline-flex items-center gap-1 text-muted-foreground">
                <Eye className="h-3 w-3" />
                View details
              </span>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
