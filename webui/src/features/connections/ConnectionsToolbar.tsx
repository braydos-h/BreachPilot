import { Search, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { FILTER_OPTIONS, type SortDir, type SortKey } from "./connectionFormat";
import type { ConnectionsPageState } from "./useConnectionsPage";

export function ConnectionsToolbar({ page }: { page: ConnectionsPageState }) {
  const {
    filter,
    setFilter,
    search,
    setSearch,
    debouncedSearch,
    sortKey,
    setSortKey,
    sortDir,
    setSortDir,
    counts,
    raw,
    sorted,
    isLoading,
    isError,
    isEmpty,
    hasActiveFilters,
    clearFilters,
  } = page;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap items-center gap-1.5" role="tablist" aria-label="Filter by status">
          {FILTER_OPTIONS.map((opt) => {
            const count =
              opt.key === "all"
                ? counts.total
                : opt.key === "active"
                  ? counts.active
                  : opt.key === "stale"
                    ? counts.stale
                    : opt.key === "removed"
                      ? counts.removed
                      : counts.error;
            const active = filter === opt.key;
            const Icon = opt.Icon;
            return (
              <button
                key={opt.key}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setFilter(opt.key)}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                  active
                    ? "border-primary/60 bg-primary text-primary-foreground shadow-sm"
                    : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground",
                )}
              >
                <Icon className="h-3.5 w-3.5" aria-hidden />
                {opt.label}
                <span
                  className={cn(
                    "ml-0.5 rounded-full px-1.5 py-0 text-[10px] tabular-nums",
                    active ? "bg-primary-foreground/15 text-primary-foreground" : "bg-muted text-muted-foreground",
                  )}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-2">
          <div className="relative w-full sm:w-72">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              placeholder="Search target, listener, method, MITRE..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-8 pl-8 pr-8 text-sm"
              aria-label="Search connections"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch("")}
                aria-label="Clear search"
                className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <div className="hidden items-center gap-1.5 sm:flex lg:hidden">
            <span className="text-xs text-muted-foreground">Sort</span>
            <select
              value={`${sortKey}:${sortDir}`}
              onChange={(e) => {
                const [k, d] = e.target.value.split(":") as [SortKey, SortDir];
                setSortKey(k);
                setSortDir(d);
              }}
              className="h-8 rounded-md border border-input bg-background px-2 text-xs"
              aria-label="Sort connections"
            >
              <option value="status:asc">Status</option>
              <option value="target:asc">Target A→Z</option>
              <option value="target:desc">Target Z→A</option>
              <option value="beacon:desc">Recent beacon</option>
              <option value="beacon:asc">Oldest beacon</option>
              <option value="created:desc">Newest</option>
              <option value="method:asc">Method</option>
            </select>
          </div>
        </div>
      </div>

      {(hasActiveFilters || sorted.length !== raw.length) && !isLoading && !isError && !isEmpty && (
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
          <span>
            Showing <span className="font-medium tabular-nums text-foreground">{sorted.length}</span> of{" "}
            <span className="tabular-nums">{raw.length}</span> connection{raw.length !== 1 ? "s" : ""}
            {filter !== "all" && (
              <>
                {" "}
                · filtered to <span className="font-medium text-foreground">{filter}</span>
              </>
            )}
            {debouncedSearch && (
              <>
                {" "}
                · search <span className="font-mono text-foreground">“{debouncedSearch}”</span>
              </>
            )}
          </span>
          {hasActiveFilters && (
            <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={clearFilters}>
              Clear filters
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
