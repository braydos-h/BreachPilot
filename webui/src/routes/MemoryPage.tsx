import { useMemo, useState } from "react";
import {
  AlertTriangle,
  Activity,
  BookOpen,
  Brain,
  CheckCircle2,
  Database,
  Eye,
  Layers3,
  Gauge,
  RefreshCw,
  Search,
  Target,
  X,
  XCircle,
  Info,
} from "lucide-react";
import { cn, formatRelative } from "@/lib/utils";
import { ApiError } from "@/api/client";
import { useMemory } from "@/api/hooks";
import type { AttackMemoryItem, MemoryConfidence, MemoryLesson } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, SkeletonRows } from "@/components/Loading";
import { CopyButton } from "@/components/CopyButton";

// ── pure helpers (exported for testing) ─────────────────────────────────────

export type ConfidenceSort =
  | "confidence_desc"
  | "confidence_asc"
  | "observations_desc"
  | "recent"
  | "name_asc";
export type LessonOutcomeFilter = "all" | "success" | "failure" | "partial";
export type LessonSort = "newest" | "oldest" | "action";
export type AttackResultFilter = "all" | "success" | "failure";
export type AttackSort = "recent" | "frequent" | "target" | "category";

export interface MemoryOverview {
  learnedActions: number;
  observations: number;
  recordedLessons: number;
  attackFacts: number;
  knownTargets: number;
  avgConfidence: number | null;
  weightedSuccessRate: number | null;
}

function timestampMs(value?: string): number {
  if (!value) return Number.NEGATIVE_INFINITY;
  const t = Date.parse(value);
  return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
}

function formatPercent(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  return `${Math.round(value)}%`;
}

export function deriveMemoryOverview(
  confidence: MemoryConfidence[],
  lessons: MemoryLesson[],
  attackMemory: AttackMemoryItem[],
): MemoryOverview {
  const learnedActions = confidence.length;
  const observations = confidence.reduce((acc, c) => acc + (Number.isFinite(c.observations) ? c.observations : 0), 0);
  const recordedLessons = lessons.length;
  const attackFacts = attackMemory.length;
  const knownTargets = new Set(attackMemory.map((m) => m.target_ip).filter(Boolean)).size;
  const avgConfidence =
    confidence.length > 0
      ? confidence.reduce((acc, c) => acc + (Number.isFinite(c.confidence) ? c.confidence : 0), 0) / confidence.length
      : null;
  const totalSuccesses = confidence.reduce((acc, c) => acc + (Number.isFinite(c.successes) ? c.successes : 0), 0);
  const weightedSuccessRate = observations > 0 ? (totalSuccesses / observations) * 100 : null;
  return {
    learnedActions,
    observations,
    recordedLessons,
    attackFacts,
    knownTargets,
    avgConfidence: avgConfidence != null && Number.isFinite(avgConfidence) ? avgConfidence * 100 : null,
    weightedSuccessRate,
  };
}

export function filterAndSortConfidence(
  items: MemoryConfidence[],
  query: string,
  sortKey: ConfidenceSort,
  minObservations: number,
): MemoryConfidence[] {
  const q = query.trim().toLowerCase();
  let out = items;
  if (q) out = out.filter((c) => c.action_type.toLowerCase().includes(q));
  if (minObservations > 0) out = out.filter((c) => c.observations >= minObservations);
  const cloned = [...out];
  switch (sortKey) {
    case "confidence_desc":
      cloned.sort((a, b) => b.confidence - a.confidence || b.observations - a.observations);
      break;
    case "confidence_asc":
      cloned.sort((a, b) => a.confidence - b.confidence || a.observations - b.observations);
      break;
    case "observations_desc":
      cloned.sort((a, b) => b.observations - a.observations || b.confidence - a.confidence);
      break;
    case "recent":
      cloned.sort((a, b) => timestampMs(b.last_seen) - timestampMs(a.last_seen));
      break;
    case "name_asc":
      cloned.sort((a, b) => a.action_type.localeCompare(b.action_type));
      break;
  }
  return cloned;
}

export function filterAndSortLessons(
  items: MemoryLesson[],
  query: string,
  outcome: LessonOutcomeFilter,
  sortKey: LessonSort,
): MemoryLesson[] {
  const q = query.trim().toLowerCase();
  let out = items;
  if (q) {
    out = out.filter(
      (l) =>
        l.action_type.toLowerCase().includes(q) ||
        (l.target_signature ?? "").toLowerCase().includes(q),
    );
  }
  if (outcome !== "all") {
    out = out.filter((l) => {
      const o = (l.outcome ?? "").toLowerCase();
      if (outcome === "success") return o === "success";
      if (outcome === "failure") return o === "failure";
      // partial/other = everything not success/failure
      return o !== "success" && o !== "failure";
    });
  }
  const cloned = [...out];
  switch (sortKey) {
    case "newest":
      cloned.sort((a, b) => timestampMs(b.created_at) - timestampMs(a.created_at));
      break;
    case "oldest":
      cloned.sort((a, b) => timestampMs(a.created_at) - timestampMs(b.created_at));
      break;
    case "action":
      cloned.sort((a, b) => a.action_type.localeCompare(b.action_type));
      break;
  }
  return cloned;
}

export function filterAndSortAttackMemory(
  items: AttackMemoryItem[],
  query: string,
  targetFilter: string,
  categoryFilter: string,
  resultFilter: AttackResultFilter,
  sortKey: AttackSort,
): AttackMemoryItem[] {
  const q = query.trim().toLowerCase();
  let out = items;
  if (targetFilter) out = out.filter((m) => m.target_ip === targetFilter);
  if (categoryFilter) out = out.filter((m) => m.category === categoryFilter);
  if (resultFilter !== "all") {
    out = out.filter((m) => (resultFilter === "success" ? m.success : !m.success));
  }
  if (q) {
    out = out.filter((m) => {
      const hay = [m.target_ip, m.category, m.source_tool, m.item_key, m.item_value]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }
  const cloned = [...out];
  switch (sortKey) {
    case "recent":
      cloned.sort((a, b) => timestampMs(b.last_seen_at) - timestampMs(a.last_seen_at));
      break;
    case "frequent":
      cloned.sort((a, b) => b.seen_count - a.seen_count || timestampMs(b.last_seen_at) - timestampMs(a.last_seen_at));
      break;
    case "target":
      cloned.sort((a, b) => (a.target_ip ?? "").localeCompare(b.target_ip ?? "") || (a.category ?? "").localeCompare(b.category ?? ""));
      break;
    case "category":
      cloned.sort((a, b) => (a.category ?? "").localeCompare(b.category ?? "") || (a.target_ip ?? "").localeCompare(b.target_ip ?? ""));
      break;
  }
  return cloned;
}

function formatMemoryError(error: unknown, fallback: string): string {
  if (error instanceof ApiError && error.message) return error.message;
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}

// ── page ────────────────────────────────────────────────────────────────────

export function MemoryPage() {
  const memory = useMemory();
  const rawConfidence = memory.data?.confidence ?? [];
  const rawLessons = memory.data?.lessons ?? [];
  const rawAttack = memory.data?.attack_memory ?? [];

  const isInitialLoading = memory.isLoading && !memory.data;
  const isRefreshing = memory.isFetching && Boolean(memory.data);
  const hasCached = Boolean(memory.data);
  const hasError = Boolean(memory.error);
  const isEmptyStore =
    !isInitialLoading && !hasError && rawConfidence.length === 0 && rawLessons.length === 0 && rawAttack.length === 0;

  const overview = useMemo(
    () => deriveMemoryOverview(rawConfidence, rawLessons, rawAttack),
    [rawConfidence, rawLessons, rawAttack],
  );

  // confidence filters
  const [confQuery, setConfQuery] = useState("");
  const [confSort, setConfSort] = useState<ConfidenceSort>("confidence_desc");
  const [confMinObs, setConfMinObs] = useState<string>("0");

  // lessons filters
  const [lessonQuery, setLessonQuery] = useState("");
  const [lessonOutcome, setLessonOutcome] = useState<LessonOutcomeFilter>("all");
  const [lessonSort, setLessonSort] = useState<LessonSort>("newest");

  // attack memory filters
  const [attackQuery, setAttackQuery] = useState("");
  const [attackTarget, setAttackTarget] = useState("");
  const [attackCategory, setAttackCategory] = useState("");
  const [attackResult, setAttackResult] = useState<AttackResultFilter>("all");
  const [attackSort, setAttackSort] = useState<AttackSort>("recent");

  const [activeTab, setActiveTab] = useState("confidence");

  const targetOptions = useMemo(
    () => [...new Set(rawAttack.map((m) => m.target_ip).filter(Boolean))].sort(),
    [rawAttack],
  );
  const categoryOptions = useMemo(
    () => [...new Set(rawAttack.map((m) => m.category).filter(Boolean))].sort(),
    [rawAttack],
  );

  const confidenceFiltered = useMemo(
    () => filterAndSortConfidence(rawConfidence, confQuery, confSort, Number(confMinObs) || 0),
    [rawConfidence, confQuery, confSort, confMinObs],
  );

  const lessonsFiltered = useMemo(
    () => filterAndSortLessons(rawLessons, lessonQuery, lessonOutcome, lessonSort),
    [rawLessons, lessonQuery, lessonOutcome, lessonSort],
  );

  const attackFiltered = useMemo(
    () => filterAndSortAttackMemory(rawAttack, attackQuery, attackTarget, attackCategory, attackResult, attackSort),
    [rawAttack, attackQuery, attackTarget, attackCategory, attackResult, attackSort],
  );

  const confHasActiveFilters = confQuery.trim().length > 0 || confMinObs !== "0";
  const lessonHasActiveFilters = lessonQuery.trim().length > 0 || lessonOutcome !== "all";
  const attackHasActiveFilters =
    attackQuery.trim().length > 0 || attackTarget !== "" || attackCategory !== "" || attackResult !== "all";

  const clearConfidenceFilters = () => {
    setConfQuery("");
    setConfMinObs("0");
    setConfSort("confidence_desc");
  };
  const clearLessonFilters = () => {
    setLessonQuery("");
    setLessonOutcome("all");
    setLessonSort("newest");
  };
  const clearAttackFilters = () => {
    setAttackQuery("");
    setAttackTarget("");
    setAttackCategory("");
    setAttackResult("all");
    setAttackSort("recent");
  };

  return (
    <TooltipProvider delayDuration={120}>
      <div className="mx-auto max-w-[1600px] space-y-5 p-4 md:p-6">
        {/* Header */}
        <header className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 items-start gap-2.5">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border bg-card">
              <Brain className="h-5 w-5 text-primary" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <h1 className="text-lg font-semibold leading-tight">Memory &amp; Experience</h1>
              <p className="mt-0.5 text-sm text-muted-foreground">
                Knowledge accumulated across attacks and missions — confidence, lessons, and extracted facts.
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-muted-foreground">
                <span className="font-mono">
                  {overview.learnedActions} actions · {overview.recordedLessons} lessons · {overview.attackFacts} facts
                </span>
                {memory.dataUpdatedAt > 0 && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span>updated {formatRelative(new Date(memory.dataUpdatedAt).toISOString())}</span>
                  </>
                )}
                {isRefreshing && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span className="inline-flex items-center gap-1">
                      <RefreshCw className="h-3 w-3 animate-spin" aria-hidden="true" /> refreshing
                    </span>
                  </>
                )}
              </div>
            </div>
          </div>
          <Button
            size="sm"
            variant="outline"
            className="self-start sm:mt-0"
            onClick={() => void memory.refetch()}
            disabled={memory.isFetching}
            aria-label="Refresh memory"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", memory.isFetching && "animate-spin")} aria-hidden="true" />
            <span>Refresh</span>
          </Button>
        </header>

        {/* Error with cached data (non-blocking) */}
        {hasError && hasCached && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3" aria-live="polite">
            <ErrorState
              message={formatMemoryError(memory.error, "Could not refresh memory; showing the last loaded snapshot.")}
              onRetry={() => void memory.refetch()}
            />
          </div>
        )}

        {/* Full error */}
        {hasError && !hasCached && !isInitialLoading && (
          <Card className="border-destructive/30">
            <CardContent className="flex flex-col gap-3 p-6">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 shrink-0 text-destructive" aria-hidden="true" />
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold">Failed to load memory</h2>
                  <p className="mt-1 text-sm text-muted-foreground">
                    {formatMemoryError(memory.error, "The memory store could not be loaded.")}
                  </p>
                </div>
              </div>
              <div className="flex justify-end">
                <Button size="sm" variant="outline" onClick={() => void memory.refetch()}>
                  Retry
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Initial loading skeleton */}
        {isInitialLoading && <MemorySkeleton />}

        {/* Empty store page-level */}
        {isEmptyStore && !hasError && (
          <Card>
            <CardContent className="flex flex-col items-center justify-center gap-3 p-8 text-center">
              <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary">
                <Brain className="h-5 w-5" aria-hidden="true" />
              </span>
              <div className="max-w-md">
                <h2 className="font-medium">No memory yet</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  BreachPilot records skill confidence, cross-mission lessons, and attack facts as runs complete. This
                  dashboard will populate once outcomes have been observed.
                </p>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Main content: overview + tabs */}
        {!isInitialLoading && !(hasError && !hasCached) && !isEmptyStore && (
          <>
            <section aria-labelledby="memory-overview-heading" className="space-y-3">
              <div>
                <h2 id="memory-overview-heading" className="text-sm font-semibold">
                  Overview
                </h2>
                <p className="text-xs text-muted-foreground">Snapshot of accumulated operator knowledge.</p>
              </div>
              <MemoryOverviewCards overview={overview} loading={isInitialLoading} />
            </section>

            <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-3">
              <div className="overflow-x-auto scrollbar-thin">
                <TabsList className="inline-flex h-auto min-w-full justify-start gap-1 p-1 sm:min-w-0">
                  <TabsTrigger
                    value="confidence"
                    className="gap-2 data-[state=active]:bg-background"
                  >
                    Skill confidence
                    <Badge variant="muted" className="ml-1 px-1.5 py-0 text-[11px] font-mono tabular-nums">
                      {rawConfidence.length}
                    </Badge>
                  </TabsTrigger>
                  <TabsTrigger value="lessons" className="gap-2">
                    Lessons
                    <Badge variant="muted" className="ml-1 px-1.5 py-0 text-[11px] font-mono tabular-nums">
                      {rawLessons.length}
                    </Badge>
                  </TabsTrigger>
                  <TabsTrigger value="attack" className="gap-2">
                    Attack memory
                    <Badge variant="muted" className="ml-1 px-1.5 py-0 text-[11px] font-mono tabular-nums">
                      {rawAttack.length}
                    </Badge>
                  </TabsTrigger>
                </TabsList>
              </div>

              {/* Skill confidence tab */}
              <TabsContent value="confidence" className="mt-3 space-y-3 focus-visible:outline-none">
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
              </TabsContent>

              {/* Lessons tab */}
              <TabsContent value="lessons" className="mt-3 space-y-3 focus-visible:outline-none">
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
              </TabsContent>

              {/* Attack memory tab */}
              <TabsContent value="attack" className="mt-3 space-y-3 focus-visible:outline-none">
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
                        <Select
                          value={attackTarget || "__all__"}
                          onValueChange={(v) => setAttackTarget(v === "__all__" ? "" : v)}
                        >
                          <SelectTrigger
                            className="h-8 w-full sm:w-[180px] text-xs"
                            aria-label="Filter attack memory by target"
                          >
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
                          <SelectTrigger
                            className="h-8 w-full sm:w-[180px] text-xs"
                            aria-label="Filter attack memory by category"
                          >
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
              </TabsContent>
            </Tabs>
          </>
        )}
      </div>
    </TooltipProvider>
  );
}

// ── overview ────────────────────────────────────────────────────────────────

function MemoryOverviewCards({
  overview,
}: {
  overview: MemoryOverview;
  loading?: boolean;
}) {
  const avgLabel =
    overview.avgConfidence == null
      ? "No confidence data"
      : `${formatPercent(overview.avgConfidence)} average · ${overview.weightedSuccessRate != null ? `${formatPercent(overview.weightedSuccessRate)} weighted success` : "—"}`;
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
      <MemoryStat
        icon={Layers3}
        label="Learned actions"
        value={String(overview.learnedActions)}
        sub={`${overview.observations} observations`}
        help="Distinct action types with recorded outcomes"
      />
      <MemoryStat
        icon={Eye}
        label="Observations"
        value={String(overview.observations)}
        sub={overview.observations > 0 ? "Total recorded outcomes" : "No observations yet"}
      />
      <MemoryStat
        icon={BookOpen}
        label="Recorded lessons"
        value={String(overview.recordedLessons)}
        sub={overview.recordedLessons > 0 ? "Cross-mission learnings" : "No lessons yet"}
      />
      <MemoryStat
        icon={Database}
        label="Attack facts"
        value={String(overview.attackFacts)}
        sub={overview.attackFacts > 0 ? "Extracted facts & artefacts" : "No facts yet"}
      />
      <MemoryStat
        icon={Target}
        label="Known targets"
        value={String(overview.knownTargets)}
        sub={overview.knownTargets > 0 ? "Unique target IPs" : "No target history"}
      />
      <MemoryStat
        icon={Gauge}
        label="Avg confidence"
        value={formatPercent(overview.avgConfidence)}
        sub={avgLabel}
        tone={
          overview.avgConfidence == null
            ? "neutral"
            : overview.avgConfidence >= 75
              ? "success"
              : overview.avgConfidence >= 45
                ? "warning"
                : "danger"
        }
        help="Mean confidence across learned actions. Weighted success = successes / observations."
      />
    </div>
  );
}

type Tone = "neutral" | "success" | "danger" | "warning";

function MemoryStat({
  icon: Icon,
  label,
  value,
  sub,
  tone = "neutral",
  help,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  sub: string;
  tone?: Tone;
  help?: string;
}) {
  const toneClasses: Record<Tone, { icon: string; value: string; border: string }> = {
    neutral: { icon: "bg-primary/10 text-primary", value: "text-foreground", border: "border-primary/15" },
    success: {
      icon: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
      value: "text-emerald-700 dark:text-emerald-300",
      border: "border-emerald-500/20",
    },
    danger: {
      icon: "bg-destructive/10 text-red-600 dark:text-red-300",
      value: "text-red-600 dark:text-red-300",
      border: "border-destructive/20",
    },
    warning: {
      icon: "bg-amber-500/10 text-amber-700 dark:text-amber-300",
      value: "text-amber-700 dark:text-amber-300",
      border: "border-amber-500/20",
    },
  };
  const classes = toneClasses[tone];
  return (
    <Card className={cn("h-full", classes.border)}>
      <CardContent className="flex min-h-[7.25rem] flex-col justify-between gap-3 p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
            {label}
            {help && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    className="inline-flex h-4 w-4 items-center justify-center rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    aria-label={`${label} information`}
                  >
                    <Info className="h-3 w-3" aria-hidden="true" />
                  </button>
                </TooltipTrigger>
                <TooltipContent className="max-w-[16rem] border border-border bg-popover text-popover-foreground shadow-lg">
                  {help}
                </TooltipContent>
              </Tooltip>
            )}
          </span>
          <span className={cn("flex h-7 w-7 items-center justify-center rounded-md", classes.icon)}>
            <Icon className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
        </div>
        <div className="min-w-0">
          <div className={cn("truncate font-mono text-2xl font-semibold tabular-nums", classes.value)}>{value}</div>
          <div className="mt-1 truncate text-xs text-muted-foreground">{sub}</div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── confidence ──────────────────────────────────────────────────────────────

function confidenceTone(confidence: number): Tone {
  if (confidence >= 0.75) return "success";
  if (confidence >= 0.45) return "warning";
  return "danger";
}

function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, value * 100));
  const tone = confidenceTone(value);
  const label = tone === "success" ? "High" : tone === "warning" ? "Med" : "Low";
  const barClass =
    tone === "success" ? "bg-emerald-500" : tone === "warning" ? "bg-amber-500" : "bg-destructive";
  return (
    <div className="flex min-w-[120px] items-center gap-2">
      <div
        className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(pct)}
        aria-label={`Confidence ${Math.round(pct)} percent, ${label}`}
      >
        <div className={cn("h-full rounded-full transition-[width]", barClass)} style={{ width: `${pct}%` }} />
      </div>
      <span className="inline-flex items-center gap-1 font-mono text-xs tabular-nums">
        {formatPercent(pct)}
        <span
          className={cn(
            "rounded px-1 py-0 text-[10px] font-medium leading-none",
            tone === "success" && "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
            tone === "warning" && "bg-amber-500/10 text-amber-700 dark:text-amber-300",
            tone === "danger" && "bg-destructive/10 text-destructive",
          )}
          aria-hidden="true"
        >
          {label}
        </span>
        <span className="sr-only">({label})</span>
      </span>
    </div>
  );
}

function DistributionBar({
  successes,
  failures,
  partials,
  observations,
}: {
  successes: number;
  failures: number;
  partials: number;
  observations: number;
}) {
  if (observations <= 0) return <span className="text-muted-foreground">—</span>;
  const s = Math.max(0, successes);
  const f = Math.max(0, failures);
  const p = Math.max(0, partials);
  const total = s + f + p;
  // If counts don't sum to observations (edge), normalize to total; fallback to observations
  const denom = total > 0 ? total : observations;
  return (
    <div className="flex w-[96px] items-center gap-1" aria-hidden="true">
      <div className="flex h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
        {s > 0 && <div className="bg-emerald-500" style={{ width: `${(s / denom) * 100}%` }} />}
        {p > 0 && <div className="bg-amber-500" style={{ width: `${(p / denom) * 100}%` }} />}
        {f > 0 && <div className="bg-destructive" style={{ width: `${(f / denom) * 100}%` }} />}
      </div>
    </div>
  );
}

function ConfidenceTable({ items }: { items: MemoryConfidence[] }) {
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full border-collapse text-xs">
        <caption className="sr-only">Skill outcome confidence</caption>
        <thead>
          <tr className="border-b bg-muted/30">
            <th scope="col" className="p-2 text-left font-semibold">
              Action
            </th>
            <th scope="col" className="p-2 text-left font-semibold">
              Obs
            </th>
            <th scope="col" className="p-2 text-left font-semibold">
              Success
            </th>
            <th scope="col" className="p-2 text-left font-semibold">
              Failure
            </th>
            <th scope="col" className="p-2 text-left font-semibold">
              Partial
            </th>
            <th scope="col" className="p-2 text-left font-semibold">
              Confidence
            </th>
            <th scope="col" className="p-2 text-left font-semibold">
              Distribution
            </th>
            <th scope="col" className="p-2 text-left font-semibold">
              Last seen
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.action_type} className="border-b last:border-0 even:bg-muted/20 hover:bg-muted/30">
              <td className="max-w-[260px] truncate p-2 font-mono" title={c.action_type}>
                {c.action_type}
              </td>
              <td className="p-2 font-mono tabular-nums">{c.observations}</td>
              <td className="p-2 font-mono tabular-nums text-emerald-600 dark:text-emerald-300">{c.successes}</td>
              <td className="p-2 font-mono tabular-nums text-destructive">{c.failures}</td>
              <td className="p-2 font-mono tabular-nums text-amber-600 dark:text-amber-300">{c.partials}</td>
              <td className="p-2">
                <ConfidenceMeter value={c.confidence} />
              </td>
              <td className="p-2">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="inline-flex">
                      <DistributionBar
                        successes={c.successes}
                        failures={c.failures}
                        partials={c.partials}
                        observations={c.observations}
                      />
                    </span>
                  </TooltipTrigger>
                  <TooltipContent className="border border-border bg-popover text-popover-foreground shadow-lg">
                    <span className="font-mono text-xs">
                      {c.successes} success · {c.partials} partial · {c.failures} fail
                    </span>
                  </TooltipContent>
                </Tooltip>
              </td>
              <td className="whitespace-nowrap p-2 text-muted-foreground" title={c.last_seen}>
                {formatRelative(c.last_seen)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── lessons ─────────────────────────────────────────────────────────────────

function outcomeMeta(outcome: string): { variant: "success" | "danger" | "outline" | "warn"; label: string; icon: typeof CheckCircle2 } {
  const o = (outcome ?? "").toLowerCase();
  if (o === "success") return { variant: "success", label: "success", icon: CheckCircle2 };
  if (o === "failure") return { variant: "danger", label: "failure", icon: XCircle };
  return { variant: "outline", label: o || "partial", icon: AlertTriangle };
}

function LessonsList({ items }: { items: MemoryLesson[] }) {
  return (
    <ul className="divide-y rounded-md border" role="list">
      {items.map((l) => {
        const meta = outcomeMeta(l.outcome);
        const Icon = meta.icon;
        return (
          <li
            key={l.id}
            className="flex flex-col gap-1.5 p-2.5 transition-colors hover:bg-muted/20 sm:flex-row sm:items-start sm:justify-between"
          >
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={meta.variant} className="gap-1 text-[10px] capitalize">
                  <Icon className="h-3 w-3" aria-hidden="true" />
                  {meta.label}
                </Badge>
                <span className="font-mono text-xs text-muted-foreground break-all">{l.action_type}</span>
              </div>
              {l.target_signature ? (
                <div className="mt-1.5 break-words font-mono text-xs text-muted-foreground">{l.target_signature}</div>
              ) : (
                <div className="mt-1 text-xs italic text-muted-foreground/60">No target signature</div>
              )}
            </div>
            <time
              dateTime={l.created_at}
              title={l.created_at}
              className="shrink-0 whitespace-nowrap text-xs tabular-nums text-muted-foreground sm:ml-4"
            >
              {formatRelative(l.created_at)}
            </time>
          </li>
        );
      })}
    </ul>
  );
}

// ── attack memory ───────────────────────────────────────────────────────────

function AttackMemoryList({ items }: { items: AttackMemoryItem[] }) {
  return (
    <ul className="space-y-1.5" role="list">
      {items.map((m) => {
        const hasValue = Boolean(m.item_value);
        return (
          <li
            key={m.id}
            className="rounded-md border p-2.5 transition-colors hover:bg-muted/20"
          >
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <Badge variant="outline" className="text-[10px] font-medium">
                {m.category || "unknown"}
              </Badge>
              <span className="font-mono text-muted-foreground">{m.target_ip || "—"}</span>
              {m.source_tool && (
                <span className="font-mono text-muted-foreground">· {m.source_tool}</span>
              )}
              {m.success ? (
                <Badge variant="success" className="gap-1 text-[10px]">
                  <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                  success
                </Badge>
              ) : (
                <Badge variant="danger" className="gap-1 text-[10px]">
                  <XCircle className="h-3 w-3" aria-hidden="true" />
                  fail
                </Badge>
              )}
              <span className="ml-auto inline-flex items-center gap-2 text-muted-foreground">
                {m.seen_count > 1 && (
                  <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] tabular-nums">
                    Seen {m.seen_count}×
                  </span>
                )}
                <time dateTime={m.last_seen_at} title={m.last_seen_at} className="whitespace-nowrap tabular-nums">
                  {formatRelative(m.last_seen_at)}
                </time>
              </span>
            </div>
            <div className="mt-2 flex items-start gap-2">
              <div className="min-w-0 flex-1 break-words font-mono text-xs leading-relaxed">
                {m.item_key ? <span className="text-muted-foreground">{m.item_key}: </span> : null}
                <span className="break-words text-foreground">{hasValue ? m.item_value : "—"}</span>
              </div>
              {hasValue && (
                <CopyButton
                  value={m.item_value}
                  label="Copy"
                  size="sm"
                  className="h-7 shrink-0 px-2 text-xs"
                />
              )}
            </div>
            {(m.session_id || m.id) && (
              <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                {m.session_id && <span className="font-mono">session {m.session_id.slice(0, 8)}</span>}
                <span className="font-mono">id {m.id.slice(0, 8)}</span>
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

// ── generic empty/skeleton ──────────────────────────────────────────────────

function MemoryEmptyState({ message }: { message: string }) {
  return (
    <div
      className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground"
      role="status"
      aria-live="polite"
    >
      {message}
    </div>
  );
}

function MemorySkeleton() {
  return (
    <div className="space-y-5" role="status" aria-label="Loading memory" aria-live="polite">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <Card key={i} className="border-primary/10">
            <CardContent className="flex min-h-[7.25rem] flex-col justify-between gap-3 p-4">
              <div className="flex items-center justify-between">
                <Skeleton className="h-3 w-20" />
                <Skeleton className="h-7 w-7 rounded-md" />
              </div>
              <div className="space-y-2">
                <Skeleton className="h-7 w-16" />
                <Skeleton className="h-3 w-28" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      <Card>
        <CardHeader className="pb-3">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="mt-2 h-3 w-64" />
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Skeleton className="h-8 flex-1" />
            <Skeleton className="h-8 w-32" />
            <Skeleton className="h-8 w-32" />
          </div>
          <SkeletonRows count={5} />
        </CardContent>
      </Card>
    </div>
  );
}
