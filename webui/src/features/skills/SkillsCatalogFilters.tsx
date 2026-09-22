import { ChevronDown, Loader2, Search, Tag, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { STATUS_OPTIONS, type SortKey } from "./skillsConfig";
import type { SkillsPageState } from "./useSkillsPage";

export function SkillsCatalogFilters({ page }: { page: SkillsPageState }) {
  const {
    query,
    setQuery,
    tag,
    setTag,
    status,
    setStatus,
    sort,
    setSort,
    topTags,
    total,
    filtered,
    skills,
    hasActiveFilters,
    clearFilters,
    isSearching,
  } = page;
  return (
    <div className="shrink-0 space-y-3 border-b bg-card p-3">
      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search skills…"
          aria-label="Search skills"
          className="h-9 pl-8 pr-8 text-sm"
        />
        {query ? (
          <button
            type="button"
            onClick={() => setQuery("")}
            aria-label="Clear search"
            className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        ) : null}
        {isSearching && (
          <Loader2 className="absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 animate-spin text-muted-foreground" />
        )}
      </div>

      <div className="flex items-center gap-2">
        <div className="flex flex-1 items-center rounded-md border bg-muted/30 p-0.5" role="group" aria-label="Filter by state">
          {STATUS_OPTIONS.map((o) => (
            <button
              key={o.value}
              type="button"
              aria-pressed={status === o.value}
              onClick={() => setStatus(o.value)}
              className={cn(
                "flex-1 rounded-sm px-2 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                status === o.value
                  ? "bg-background shadow-sm text-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {o.label}
            </button>
          ))}
        </div>
        <Select value={sort} onValueChange={(v) => setSort(v as SortKey)}>
          <SelectTrigger className="h-7 w-[128px] shrink-0 text-xs" aria-label="Sort skills">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="default">Default order</SelectItem>
            <SelectItem value="name">Name A→Z</SelectItem>
            <SelectItem value="state">State</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="flex items-center gap-1.5">
        <Popover>
          <PopoverTrigger asChild>
            <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs">
              <Tag className="h-3 w-3" />
              {tag ? tag : "All tags"}
              <ChevronDown className="h-3 w-3 opacity-50" />
            </Button>
          </PopoverTrigger>
          <PopoverContent align="start" className="w-64 p-2">
            <div className="max-h-64 space-y-1 overflow-auto scrollbar-thin">
              <button
                type="button"
                onClick={() => setTag(null)}
                className={cn(
                  "flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-xs transition-colors",
                  tag === null ? "bg-primary text-primary-foreground" : "hover:bg-accent",
                )}
              >
                All tags <span className="tabular-nums text-muted-foreground">{total}</span>
              </button>
              {topTags.map(([t, count]) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTag(t)}
                  className={cn(
                    "flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-xs transition-colors",
                    tag === t ? "bg-primary text-primary-foreground" : "hover:bg-accent",
                  )}
                >
                  <span className="truncate">{t}</span>
                  <span className="ml-2 shrink-0 tabular-nums opacity-60">{count}</span>
                </button>
              ))}
              {topTags.length === 0 && <p className="px-2 py-2 text-xs text-muted-foreground">No tags</p>}
            </div>
          </PopoverContent>
        </Popover>
        {tag && (
          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => setTag(null)}>
            <X className="mr-1 h-3 w-3" /> Clear
          </Button>
        )}
        {hasActiveFilters && !tag && (
          <Button variant="ghost" size="sm" className="ml-auto h-7 px-2 text-xs" onClick={clearFilters}>
            Clear filters
          </Button>
        )}
      </div>

      <div className="flex items-center justify-between text-xs">
        <span className="tabular-nums text-muted-foreground">
          {skills.isLoading
            ? "Loading…"
            : hasActiveFilters
              ? `${filtered.length} of ${total} skills`
              : `${total} skills`}
        </span>
        {hasActiveFilters && <span className="text-muted-foreground/60">filtered</span>}
      </div>
    </div>
  );
}
