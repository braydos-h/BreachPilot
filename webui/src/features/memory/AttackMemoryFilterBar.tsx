import { Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { AttackResultFilter, AttackSort } from "./memoryFilters";
import type { MemoryPageState } from "./useMemoryPage";

export function AttackMemoryFilterBar({ page }: { page: MemoryPageState }) {
  const {
    attackQuery,
    setAttackQuery,
    attackSort,
    setAttackSort,
    attackTarget,
    setAttackTarget,
    attackCategory,
    setAttackCategory,
    attackResult,
    setAttackResult,
    targetOptions,
    categoryOptions,
    rawAttack,
    attackFiltered,
    attackHasActiveFilters,
    clearAttackFilters,
  } = page;
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            value={attackQuery}
            onChange={(e) => setAttackQuery(e.target.value)}
            placeholder="Search target, category, tool, key, value…"
            aria-label="Search attack memory"
            className="h-8 pl-8 pr-8 text-sm"
          />
          {attackQuery && (
            <button
              type="button"
              onClick={() => setAttackQuery("")}
              aria-label="Clear attack memory search"
              className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </div>
        <Select value={attackSort} onValueChange={(v) => setAttackSort(v as AttackSort)}>
          <SelectTrigger className="h-8 w-full sm:w-[170px] text-xs" aria-label="Sort attack memory">
            <SelectValue placeholder="Sort" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="recent">Most recently seen</SelectItem>
            <SelectItem value="frequent">Most frequently seen</SelectItem>
            <SelectItem value="target">Target A → Z</SelectItem>
            <SelectItem value="category">Category A → Z</SelectItem>
          </SelectContent>
        </Select>
        {attackHasActiveFilters && (
          <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={clearAttackFilters}>
            <X className="h-3 w-3" aria-hidden="true" /> Clear filters
          </Button>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Select value={attackTarget || "__all__"} onValueChange={(v) => setAttackTarget(v === "__all__" ? "" : v)}>
          <SelectTrigger className="h-8 w-full sm:w-[180px] text-xs" aria-label="Filter attack memory by target">
            <SelectValue placeholder="All targets" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all__">All targets</SelectItem>
            {targetOptions.map((t) => (
              <SelectItem key={t} value={t}>
                <span className="font-mono">{t}</span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={attackCategory || "__all__"}
          onValueChange={(v) => setAttackCategory(v === "__all__" ? "" : v)}
        >
          <SelectTrigger className="h-8 w-full sm:w-[180px] text-xs" aria-label="Filter attack memory by category">
            <SelectValue placeholder="All categories" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__all__">All categories</SelectItem>
            {categoryOptions.map((c) => (
              <SelectItem key={c} value={c}>
                {c}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={attackResult} onValueChange={(v) => setAttackResult(v as AttackResultFilter)}>
          <SelectTrigger className="h-8 w-full sm:w-[140px] text-xs" aria-label="Filter attack memory by result">
            <SelectValue placeholder="Result" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All results</SelectItem>
            <SelectItem value="success">Success</SelectItem>
            <SelectItem value="failure">Failure</SelectItem>
          </SelectContent>
        </Select>
        <span className="ml-auto text-xs tabular-nums text-muted-foreground">
          {attackHasActiveFilters ? `${attackFiltered.length} of ${rawAttack.length} entries` : `${rawAttack.length} entries`}
        </span>
      </div>
    </div>
  );
}
