import { AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import { formatRelative } from "@/lib/utils";
import type { MemoryLesson } from "@/api/types";
import { Badge } from "@/components/ui/badge";

function outcomeMeta(outcome: string): {
  variant: "success" | "danger" | "outline" | "warn";
  label: string;
  icon: typeof CheckCircle2;
} {
  const o = (outcome ?? "").toLowerCase();
  if (o === "success") return { variant: "success", label: "success", icon: CheckCircle2 };
  if (o === "failure") return { variant: "danger", label: "failure", icon: XCircle };
  return { variant: "outline", label: o || "partial", icon: AlertTriangle };
}

export function LessonsList({ items }: { items: MemoryLesson[] }) {
  return (
    <ul className="divide-y rounded-md border" role="list">
      {items.map((l) => {
        const meta = outcomeMeta(l.outcome);
        const Icon = meta.icon;
        return (
          <li
            key={l.id}
            className="flex flex-col gap-1.5 p-2.5 transition-colors hover:bg-muted/20 sm:flex-row sm:items-start sm:justify-between"
          >
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={meta.variant} className="gap-1 text-[10px] capitalize">
                  <Icon className="h-3 w-3" aria-hidden="true" />
                  {meta.label}
                </Badge>
                <span className="font-mono text-xs text-muted-foreground break-all">{l.action_type}</span>
              </div>
              {l.target_signature ? (
                <div className="mt-1.5 break-words font-mono text-xs text-muted-foreground">{l.target_signature}</div>
              ) : (
                <div className="mt-1 text-xs italic text-muted-foreground/60">No target signature</div>
              )}
            </div>
            <time
              dateTime={l.created_at}
              title={l.created_at}
              className="shrink-0 whitespace-nowrap text-xs tabular-nums text-muted-foreground sm:ml-4"
            >
              {formatRelative(l.created_at)}
            </time>
          </li>
        );
      })}
    </ul>
  );
}
