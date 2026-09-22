import { Eye } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ConnectionStatusBadge } from "./ConnectionStatusBadge";
import { SortTh } from "./ConnectionBits";
import { beaconDotClass, formatAge, formatBeacon, humanizeMethod } from "./connectionFormat";
import type { ConnectionsPageState } from "./useConnectionsPage";

export function ConnectionsTable({ page }: { page: ConnectionsPageState }) {
  const { sorted, sortKey, sortDir, onSort, openDrawer } = page;
  return (
    <div className="hidden overflow-hidden rounded-lg border md:block">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <caption className="sr-only">Operator connections</caption>
          <thead>
            <tr>
              <SortTh label="Target" sortKey="target" activeKey={sortKey} dir={sortDir} onSort={onSort} />
              <SortTh label="Method" sortKey="method" activeKey={sortKey} dir={sortDir} onSort={onSort} />
              <SortTh label="Status" sortKey="status" activeKey={sortKey} dir={sortDir} onSort={onSort} />
              <th scope="col" className="whitespace-nowrap px-3 py-2.5 text-left text-[11px] font-medium uppercase tracking-wide">
                Callback
              </th>
              <th scope="col" className="whitespace-nowrap px-3 py-2.5 text-left text-[11px] font-medium uppercase tracking-wide">
                Listener
              </th>
              <SortTh label="Last beacon" sortKey="beacon" activeKey={sortKey} dir={sortDir} onSort={onSort} />
              <SortTh label="Age" sortKey="created" activeKey={sortKey} dir={sortDir} onSort={onSort} />
              <th scope="col" className="px-3 py-2.5 text-right text-[11px] font-medium uppercase tracking-wide">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((conn) => (
              <tr
                key={conn.connection_id}
                onClick={() => openDrawer(conn.connection_id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    openDrawer(conn.connection_id);
                  }
                }}
                tabIndex={0}
                role="button"
                aria-label={`Open details for ${conn.target_ip} ${conn.connection_id}`}
                className="group cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
              >
                <td className="whitespace-nowrap px-3 py-2.5">
                  <span className="font-mono text-xs font-medium">{conn.target_ip}</span>
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex flex-col gap-1">
                    <span className="text-xs font-medium leading-none">{humanizeMethod(conn.method)}</span>
                    <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                      {conn.os_family && (
                        <span className="inline-flex items-center rounded bg-muted px-1 py-0 font-medium capitalize">
                          {conn.os_family}
                        </span>
                      )}
                      {conn.mitre_technique && <span className="font-mono">{conn.mitre_technique}</span>}
                      {!conn.os_family && !conn.mitre_technique && (
                        <span className="font-mono opacity-60">{conn.method}</span>
                      )}
                    </span>
                  </div>
                </td>
                <td className="px-3 py-2.5">
                  <ConnectionStatusBadge status={conn.status} />
                </td>
                <td className="whitespace-nowrap px-3 py-2.5 font-mono text-xs">
                  {conn.callback_host}:{conn.callback_port}
                </td>
                <td className="max-w-[14rem] px-3 py-2.5">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="block truncate font-mono text-xs" title={conn.listener_name}>
                        {conn.listener_name || "—"}
                      </span>
                    </TooltipTrigger>
                    {conn.listener_name && conn.listener_name.length > 18 && (
                      <TooltipContent className="max-w-xs break-all font-mono text-xs">
                        {conn.listener_name}
                      </TooltipContent>
                    )}
                  </Tooltip>
                </td>
                <td className="whitespace-nowrap px-3 py-2.5">
                  <span className="inline-flex items-center gap-1.5 text-xs tabular-nums">
                    <span
                      className={cn("h-1.5 w-1.5 rounded-full", beaconDotClass(conn.last_beacon, conn.status))}
                      aria-hidden
                    />
                    {formatBeacon(conn.last_beacon)}
                  </span>
                </td>
                <td className="whitespace-nowrap px-3 py-2.5 text-xs tabular-nums text-muted-foreground">
                  {formatAge(conn.created_at)}
                </td>
                <td className="px-3 py-2.5 text-right">
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 gap-1 px-2 text-xs opacity-60 group-hover:opacity-100 group-focus-within:opacity-100"
                    onClick={(e) => {
                      e.stopPropagation();
                      openDrawer(conn.connection_id);
                    }}
                    aria-label={`View ${conn.target_ip}`}
                  >
                    <Eye className="h-3.5 w-3.5" />
                    View
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
