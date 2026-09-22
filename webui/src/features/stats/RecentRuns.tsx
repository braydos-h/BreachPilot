import { Link } from "react-router-dom";
import { ArrowUpRight, History } from "lucide-react";
import { formatRelative } from "@/lib/utils";
import type { RunListRow } from "@/api/types";
import { StatusBadge } from "@/components/StatusBadge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";

export function RecentRuns({ rows }: { rows: RunListRow[] }) {
  return (
    <section aria-labelledby="recent-runs-heading" className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 id="recent-runs-heading" className="text-sm font-semibold">Recent runs</h2>
          <p className="text-xs text-muted-foreground">A compact snapshot of the latest loaded activity.</p>
        </div>
        <Badge variant="muted"><History className="h-3 w-3" /> Latest {rows.length}</Badge>
      </div>
      <Card>
        <CardContent className="p-0">
          <div className="divide-y">
          {rows.map((row) => {
            const title = row.title || row.target || row.target_ip || "Untitled run";
            const target = row.target || row.target_ip || "Target unavailable";
            return (
              <Link
                key={row.id}
                to={`/runs/${row.id}`}
                className="flex min-w-0 items-start gap-3 p-3 transition-colors hover:bg-primary/5 focus-visible:bg-primary/10"
                aria-label={`Open ${title}, ${row.state}`}
              >
                <StatusBadge state={row.state} className="mt-0.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">{title}</div>
                  <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">{target}</div>
                  <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                    <span><span className="text-foreground/70">mode</span> {row.mode}</span>
                    <span className="max-w-[15rem] truncate"><span className="text-foreground/70">goal</span> {row.goal_name || "—"}</span>
                    <span className="font-mono"><span className="font-sans text-foreground/70">model</span> {row.model_alias || "—"}</span>
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1 text-right text-[11px] text-muted-foreground">
                  <time dateTime={row.created_at} title={row.created_at}>{formatRelative(row.created_at)}</time>
                  <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
                </div>
              </Link>
            );
          })}
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
