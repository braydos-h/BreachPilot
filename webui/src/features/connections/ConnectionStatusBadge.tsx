import { cn } from "@/lib/utils";
import type { ConnectionStatus } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { STATUS_META } from "./connectionFormat";

export function ConnectionStatusBadge({ status }: { status: ConnectionStatus }) {
  const meta = STATUS_META[status];
  if (!meta) {
    return (
      <Badge variant="muted" className="gap-1.5 font-mono text-[10px] uppercase tracking-wide">
        <span className="h-1.5 w-1.5 rounded-full bg-zinc-400" aria-hidden />
        {status?.toUpperCase() ?? "UNKNOWN"}
      </Badge>
    );
  }
  const Icon = meta.Icon;
  return (
    <Badge variant={meta.variant} className="gap-1.5 font-mono text-[10px] uppercase tracking-wide">
      <span className={cn("h-1.5 w-1.5 rounded-full", meta.dot)} aria-hidden />
      <Icon className="h-3 w-3" aria-hidden />
      {meta.label}
    </Badge>
  );
}
