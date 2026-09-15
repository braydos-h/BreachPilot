import { Link } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { breadcrumbsForPath } from "@/lib/productRoutes";

/** Breadcrumbs generated from the route registry (todo 32), not per-page hand code. */
export function Breadcrumbs({ pathname, runTitle, runId }: { pathname: string; runTitle?: string; runId?: string }) {
  const crumbs = breadcrumbsForPath(pathname);
  return (
    <nav aria-label="Breadcrumb" className="flex min-w-0 flex-wrap items-center gap-1 text-[13px] text-muted-foreground">
      {crumbs.map((c, i) => {
        const isLast = i === crumbs.length - 1;
        const label = c.label === "Run detail" && runTitle ? `${runTitle}` : c.label;
        return (
          <span key={`${c.label}-${i}`} className="flex min-w-0 items-center gap-1">
            {i > 0 && <ChevronRight className="h-3.5 w-3.5 shrink-0" aria-hidden />}
            {c.to && !isLast ? (
              <Link to={c.to} className="truncate hover:text-foreground hover:underline">
                {label}
              </Link>
            ) : (
              <span aria-current={isLast ? "page" : undefined} className={isLast ? "truncate font-medium text-foreground" : "truncate"}>
                {label}
                {runId && isLast && <span className="ml-1 font-mono text-xs text-muted-foreground">{runId.slice(0, 8)}</span>}
              </span>
            )}
          </span>
        );
      })}
      {runId && (
        <Link to={`/runs/${runId}`} className="ml-2 shrink-0 text-[13px] font-medium text-primary underline-offset-4 hover:underline">
          Back to run
        </Link>
      )}
    </nav>
  );
}
