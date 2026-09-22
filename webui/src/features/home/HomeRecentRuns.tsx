import { Link } from "react-router-dom";
import { History, ListFilter, Target } from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/StatusBadge";
import { SkeletonRows } from "@/components/Loading";
import { formatRelative, truncateId } from "@/lib/utils";
import type { RunListRow } from "@/api/types";
import type { HomePageState } from "./useHomePage";

export function HomeRecentRuns({ page }: { page: HomePageState }) {
  const { runs, rows, recent } = page;
  return (
    <section className="rounded-xl border bg-card/30">
      <header className="flex items-center justify-between gap-2 border-b px-4 py-2.5">
        <div className="flex items-center gap-2">
          <History className="h-4 w-4 text-muted-foreground" />
          <div>
            <div className="text-sm font-medium">Recent runs</div>
            <p className="text-[13px] text-muted-foreground">
              Latest {recent.length || 0} of {rows.length || 0} runs.
            </p>
          </div>
        </div>
        <Button asChild size="sm" variant="outline" className="gap-1.5">
          <Link to="/runs">
            <ListFilter className="h-3.5 w-3.5" />
            View all
          </Link>
        </Button>
      </header>

      {runs.error && (
        <div className="flex items-center gap-2 p-4 text-sm text-destructive">
          <span>Failed to load recent runs.</span>
          <Button size="sm" variant="outline" onClick={() => runs.refetch()}>Retry</Button>
          <Button size="sm" variant="ghost" asChild>
            <Link to="/system">Open provider settings</Link>
          </Button>
        </div>
      )}

      {recent.length === 0 && !runs.isLoading && !runs.error && (
        <div className="flex flex-col items-center gap-2 p-6 text-center text-sm text-muted-foreground">
          <Target className="h-7 w-7 opacity-40" />
          <span>No runs yet. Run the local self-test or explore a demo run above.</span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" asChild>
              <Link to="/system">Run local self-test</Link>
            </Button>
            <Button size="sm" asChild>
              <Link to="/runs/new">New run</Link>
            </Button>
          </div>
        </div>
      )}

      {runs.isLoading && recent.length === 0 && (
        <SkeletonRows count={3} className="p-2" />
      )}

      {recent.length > 0 && (
        <ul className="divide-y">
          {recent.map((row) => (
            <RecentRow key={row.id} row={row} />
          ))}
        </ul>
      )}
    </section>
  );
}

function RecentRow({ row }: { row: RunListRow }) {
  const target = row.target || row.target_ip || "—";
  const title = row.title || "";
  return (
    <li>
      <Link
        to={`/runs/${row.id}`}
        className="flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-accent/40"
      >
        <span className="font-mono text-xs text-muted-foreground" title={row.id}>
          {truncateId(row.id)}
        </span>
        <StatusBadge state={row.state} />
        {title ? (
          <span className="max-w-[16rem] truncate text-xs" title={title}>{title}</span>
        ) : (
          <span className="max-w-[16rem] truncate font-mono text-xs" title={target}>{target}</span>
        )}
        <span className="ml-auto hidden text-xs text-muted-foreground sm:inline">
          {row.mode}
        </span>
        <span
          className="text-xs text-muted-foreground"
          title={row.created_at}
        >
          {formatRelative(row.created_at)}
        </span>
      </Link>
    </li>
  );
}
