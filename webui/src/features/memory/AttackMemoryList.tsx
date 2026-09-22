import { CheckCircle2, XCircle } from "lucide-react";
import { formatRelative } from "@/lib/utils";
import type { AttackMemoryItem } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "@/components/CopyButton";

export function AttackMemoryList({ items }: { items: AttackMemoryItem[] }) {
  return (
    <ul className="space-y-1.5" role="list">
      {items.map((m) => {
        const hasValue = Boolean(m.item_value);
        return (
          <li key={m.id} className="rounded-md border p-2.5 transition-colors hover:bg-muted/20">
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <Badge variant="outline" className="text-[10px] font-medium">
                {m.category || "unknown"}
              </Badge>
              <span className="font-mono text-muted-foreground">{m.target_ip || "—"}</span>
              {m.source_tool && <span className="font-mono text-muted-foreground">· {m.source_tool}</span>}
              {m.success ? (
                <Badge variant="success" className="gap-1 text-[10px]">
                  <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                  success
                </Badge>
              ) : (
                <Badge variant="danger" className="gap-1 text-[10px]">
                  <XCircle className="h-3 w-3" aria-hidden="true" />
                  fail
                </Badge>
              )}
              <span className="ml-auto inline-flex items-center gap-2 text-muted-foreground">
                {m.seen_count > 1 && (
                  <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] tabular-nums">
                    Seen {m.seen_count}×
                  </span>
                )}
                <time dateTime={m.last_seen_at} title={m.last_seen_at} className="whitespace-nowrap tabular-nums">
                  {formatRelative(m.last_seen_at)}
                </time>
              </span>
            </div>
            <div className="mt-2 flex items-start gap-2">
              <div className="min-w-0 flex-1 break-words font-mono text-xs leading-relaxed">
                {m.item_key ? <span className="text-muted-foreground">{m.item_key}: </span> : null}
                <span className="break-words text-foreground">{hasValue ? m.item_value : "—"}</span>
              </div>
              {hasValue && (
                <CopyButton value={m.item_value} label="Copy" size="sm" className="h-7 shrink-0 px-2 text-xs" />
              )}
            </div>
            {(m.session_id || m.id) && (
              <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                {m.session_id && <span className="font-mono">session {m.session_id.slice(0, 8)}</span>}
                <span className="font-mono">id {m.id.slice(0, 8)}</span>
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
