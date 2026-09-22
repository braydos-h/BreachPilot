import { Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SkeletonRows } from "@/components/Loading";
import { AttackMemoryFilterBar } from "./AttackMemoryFilterBar";
import { AttackMemoryList } from "./AttackMemoryList";
import { MemoryEmptyState } from "./MemoryStates";
import type { MemoryPageState } from "./useMemoryPage";

export function AttackMemoryTab({ page }: { page: MemoryPageState }) {
  const { memory, rawAttack, attackFiltered, clearAttackFilters } = page;
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm">Attack memory explorer</CardTitle>
            <CardDescription className="mt-1">
              Extracted facts, credentials, and observations keyed by target and category.
            </CardDescription>
          </div>
          <span className="text-xs tabular-nums text-muted-foreground">
            {attackFiltered.length} of {rawAttack.length} entries
          </span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <AttackMemoryFilterBar page={page} />

        {memory.isLoading && !memory.data ? (
          <SkeletonRows count={4} />
        ) : rawAttack.length === 0 ? (
          <MemoryEmptyState message="No attack-memory items captured." />
        ) : attackFiltered.length === 0 ? (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-6 text-center">
            <Search className="h-6 w-6 text-muted-foreground/40" aria-hidden="true" />
            <p className="text-sm font-medium">No matching entries</p>
            <p className="text-xs text-muted-foreground">Try adjusting the search or filter selections.</p>
            <Button size="sm" variant="outline" onClick={clearAttackFilters} className="mt-1">
              Clear filters
            </Button>
          </div>
        ) : (
          <AttackMemoryList items={attackFiltered} />
        )}
      </CardContent>
    </Card>
  );
}
