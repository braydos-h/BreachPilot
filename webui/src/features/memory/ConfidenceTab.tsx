import { Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SkeletonRows } from "@/components/Loading";
import { ConfidenceTable } from "./ConfidenceTable";
import { MemoryEmptyState } from "./MemoryStates";
import type { ConfidenceSort } from "./memoryFilters";
import type { MemoryPageState } from "./useMemoryPage";

export function ConfidenceTab({ page }: { page: MemoryPageState }) {
  const {
    memory,
    rawConfidence,
    confidenceFiltered,
    confQuery,
    setConfQuery,
    confSort,
    setConfSort,
    confMinObs,
    setConfMinObs,
    confHasActiveFilters,
    clearConfidenceFilters,
  } = page;
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm">Skill outcome confidence</CardTitle>
            <CardDescription className="mt-1">
              Calibrated per-action outcomes. Higher confidence means more consistent historical performance.
            </CardDescription>
          </div>
          <span className="text-xs tabular-nums text-muted-foreground">
            {confidenceFiltered.length} of {rawConfidence.length} actions
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
          <div className="relative flex-1 min-w-[180px]">
            <Search
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              value={confQuery}
              onChange={(e) => setConfQuery(e.target.value)}
              placeholder="Search action type…"
              aria-label="Search skill confidence by action type"
              className="h-8 pl-8 pr-8 text-sm"
            />
            {confQuery && (
              <button
                type="button"
                onClick={() => setConfQuery("")}
                aria-label="Clear skill search"
                className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>
          <Select value={confSort} onValueChange={(v) => setConfSort(v as ConfidenceSort)}>
            <SelectTrigger className="h-8 w-full sm:w-[180px] text-xs" aria-label="Sort skill confidence">
              <SelectValue placeholder="Sort" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="confidence_desc">Confidence high → low</SelectItem>
              <SelectItem value="confidence_asc">Confidence low → high</SelectItem>
              <SelectItem value="observations_desc">Most observations</SelectItem>
              <SelectItem value="recent">Most recent</SelectItem>
              <SelectItem value="name_asc">Name A → Z</SelectItem>
            </SelectContent>
          </Select>
          <Select value={confMinObs} onValueChange={setConfMinObs}>
            <SelectTrigger className="h-8 w-full sm:w-[150px] text-xs" aria-label="Minimum observations filter">
              <SelectValue placeholder="Min obs" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="0">All observations</SelectItem>
              <SelectItem value="2">≥ 2 obs</SelectItem>
              <SelectItem value="5">≥ 5 obs</SelectItem>
              <SelectItem value="10">≥ 10 obs</SelectItem>
            </SelectContent>
          </Select>
          {confHasActiveFilters && (
            <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={clearConfidenceFilters}>
              <X className="h-3 w-3" aria-hidden="true" /> Clear filters
            </Button>
          )}
        </div>

        {memory.isLoading && !memory.data ? (
          <SkeletonRows count={4} />
        ) : rawConfidence.length === 0 ? (
          <MemoryEmptyState message="No cross-mission outcome data recorded yet." />
        ) : confidenceFiltered.length === 0 ? (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-6 text-center">
            <Search className="h-6 w-6 text-muted-foreground/40" aria-hidden="true" />
            <p className="text-sm font-medium">No matching actions</p>
            <p className="text-xs text-muted-foreground">
              No actions match the current search or filter. Try adjusting the query or minimum observations.
            </p>
            <Button size="sm" variant="outline" onClick={clearConfidenceFilters} className="mt-1">
              Clear filters
            </Button>
          </div>
        ) : (
          <ConfidenceTable items={confidenceFiltered} />
        )}
      </CardContent>
    </Card>
  );
}
