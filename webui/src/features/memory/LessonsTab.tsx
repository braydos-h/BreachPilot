import { Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SkeletonRows } from "@/components/Loading";
import { LessonsList } from "./LessonsList";
import { MemoryEmptyState } from "./MemoryStates";
import type { LessonOutcomeFilter, LessonSort } from "./memoryFilters";
import type { MemoryPageState } from "./useMemoryPage";

export function LessonsTab({ page }: { page: MemoryPageState }) {
  const {
    memory,
    rawLessons,
    lessonsFiltered,
    lessonQuery,
    setLessonQuery,
    lessonOutcome,
    setLessonOutcome,
    lessonSort,
    setLessonSort,
    lessonHasActiveFilters,
    clearLessonFilters,
  } = page;
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm">Cross-mission learnings</CardTitle>
            <CardDescription className="mt-1">Outcome-labelled lessons keyed by action and signature.</CardDescription>
          </div>
          <span className="text-xs tabular-nums text-muted-foreground">
            {lessonsFiltered.length} of {rawLessons.length} lessons
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
              value={lessonQuery}
              onChange={(e) => setLessonQuery(e.target.value)}
              placeholder="Search action or signature…"
              aria-label="Search lessons by action type or target signature"
              className="h-8 pl-8 pr-8 text-sm"
            />
            {lessonQuery && (
              <button
                type="button"
                onClick={() => setLessonQuery("")}
                aria-label="Clear lesson search"
                className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            )}
          </div>
          <Select value={lessonOutcome} onValueChange={(v) => setLessonOutcome(v as LessonOutcomeFilter)}>
            <SelectTrigger className="h-8 w-full sm:w-[150px] text-xs" aria-label="Filter lessons by outcome">
              <SelectValue placeholder="Outcome" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All outcomes</SelectItem>
              <SelectItem value="success">Success</SelectItem>
              <SelectItem value="partial">Partial / other</SelectItem>
              <SelectItem value="failure">Failure</SelectItem>
            </SelectContent>
          </Select>
          <Select value={lessonSort} onValueChange={(v) => setLessonSort(v as LessonSort)}>
            <SelectTrigger className="h-8 w-full sm:w-[150px] text-xs" aria-label="Sort lessons">
              <SelectValue placeholder="Sort" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="newest">Newest first</SelectItem>
              <SelectItem value="oldest">Oldest first</SelectItem>
              <SelectItem value="action">Action A → Z</SelectItem>
            </SelectContent>
          </Select>
          {lessonHasActiveFilters && (
            <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={clearLessonFilters}>
              <X className="h-3 w-3" aria-hidden="true" /> Clear filters
            </Button>
          )}
        </div>

        {memory.isLoading && !memory.data ? (
          <SkeletonRows count={4} />
        ) : rawLessons.length === 0 ? (
          <MemoryEmptyState message="No recorded lessons." />
        ) : lessonsFiltered.length === 0 ? (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-6 text-center">
            <Search className="h-6 w-6 text-muted-foreground/40" aria-hidden="true" />
            <p className="text-sm font-medium">No matching lessons</p>
            <p className="text-xs text-muted-foreground">Adjust the search or outcome filter to see more.</p>
            <Button size="sm" variant="outline" onClick={clearLessonFilters} className="mt-1">
              Clear filters
            </Button>
          </div>
        ) : (
          <LessonsList items={lessonsFiltered} />
        )}
      </CardContent>
    </Card>
  );
}
