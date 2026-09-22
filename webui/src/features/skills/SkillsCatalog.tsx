import { AlertTriangle, Plus, Search, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";
import { ApiError } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/Loading";
import { STATE_META, type SkillState } from "./skillsConfig";
import { SkillCatalogRow } from "./SkillCatalogRow";
import { SkillsCatalogFilters } from "./SkillsCatalogFilters";
import type { SkillsPageState } from "./useSkillsPage";

export function SkillsCatalog({ page }: { page: SkillsPageState }) {
  const {
    skills,
    query,
    tag,
    status,
    filtered,
    total,
    skillsCfg,
    selected,
    setSelected,
    patch,
    masterEnabled,
    hasActiveFilters,
    clearFilters,
    onEnable,
    onAuto,
    onBlock,
    setConfirmDelete,
    setAddOpen,
  } = page;
  return (
    <Card
      className={cn(
        "flex max-h-[520px] flex-col overflow-hidden lg:sticky lg:top-4 lg:max-h-[calc(100vh-8rem)]",
        !masterEnabled && "opacity-90",
      )}
    >
      <SkillsCatalogFilters page={page} />

      <div className="min-h-0 flex-1 overflow-auto scrollbar-thin">
        <div className="space-y-1 p-2">
          {skills.isLoading && (
            <div className="space-y-2 p-1">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="space-y-2 rounded-lg border p-3">
                  <Skeleton className="h-3 w-28" />
                  <Skeleton className="h-3 w-full" />
                  <Skeleton className="h-3 w-2/3" />
                </div>
              ))}
            </div>
          )}
          {skills.error && !skills.isLoading && (
            <div className="flex flex-col items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-4 text-center">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              <p className="text-sm font-medium text-destructive">Failed to load skills</p>
              <p className="text-xs text-muted-foreground">
                {skills.error instanceof ApiError ? skills.error.message : "Could not reach the skills endpoint."}
              </p>
              <Button size="sm" variant="outline" onClick={() => skills.refetch()} className="mt-1">
                Retry
              </Button>
            </div>
          )}
          {!skills.isLoading && !skills.error && total === 0 && (
            <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed p-6 text-center">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                <Sparkles className="h-5 w-5 text-muted-foreground" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium">No skills installed</p>
                <p className="text-xs text-muted-foreground">
                  Add your first skill to extend the agent with specialist methodology.
                </p>
              </div>
              <Button size="sm" onClick={() => setAddOpen(true)}>
                <Plus className="h-4 w-4" /> Add skill
              </Button>
            </div>
          )}
          {!skills.isLoading && !skills.error && total > 0 && filtered.length === 0 && (
            <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-6 text-center">
              <Search className="h-6 w-6 text-muted-foreground/40" />
              <p className="text-sm font-medium">No results</p>
              <p className="text-xs text-muted-foreground">
                {query.trim()
                  ? `No skills match “${query.trim()}”`
                  : tag || status !== "all"
                    ? "No skills match the current filters."
                    : "No skills match."}
              </p>
              {hasActiveFilters && (
                <Button size="sm" variant="outline" onClick={clearFilters} className="mt-1">
                  Clear filters
                </Button>
              )}
            </div>
          )}
          {!skills.isLoading &&
            filtered.map((s) => (
              <SkillCatalogRow
                key={s.name}
                skill={s}
                skillsCfg={skillsCfg}
                selected={selected === s.name}
                patchPending={patch.isPending}
                dimmed={!masterEnabled}
                onSelect={() => setSelected(s.name)}
                onEnable={() => onEnable(s.name)}
                onAuto={() => onAuto(s.name)}
                onBlock={() => onBlock(s.name)}
                onDelete={() => setConfirmDelete(s.name)}
              />
            ))}
        </div>
      </div>
    </Card>
  );
}

export function SkillStateBadge({ state, className }: { state: SkillState; className?: string }) {
  const meta = STATE_META[state];
  return (
    <Badge variant={meta.variant} className={cn("gap-1 text-[10px]", className)}>
      <meta.icon className="h-3 w-3" /> {meta.label}
    </Badge>
  );
}
