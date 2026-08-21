import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  CheckCircle2,
  Crosshair,
  Lock,
  Play,
  Search,
  SearchX,
  ShieldAlert,
  ShieldCheck,
  Target,
  X,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/Loading";
import { useGoals } from "@/api/hooks";
import type { GoalPreset, RiskTag } from "@/api/types";

type RiskFilter = "all" | RiskTag;

interface RiskMeta {
  label: string;
  variant: "success" | "warn" | "danger";
  Icon: LucideIcon;
  /** Text tint for the risk icon + stat number. */
  tint: string;
  /** Active filter-chip styling (matches the app's Badge risk palette). */
  activeCls: string;
  /** Concise risk requirement shown in the card footer. */
  requirement: string;
}

const RISK_META: Record<RiskTag, RiskMeta> = {
  safe: {
    label: "Safe",
    variant: "success",
    Icon: ShieldCheck,
    tint: "text-emerald-300",
    activeCls: "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
    requirement: "Standard / safe goal",
  },
  gated: {
    label: "Gated",
    variant: "warn",
    Icon: Lock,
    tint: "text-yellow-300",
    activeCls: "border-yellow-500/50 bg-yellow-500/10 text-yellow-300",
    requirement: "Requires standard_authorized or higher",
  },
  high: {
    label: "High",
    variant: "danger",
    Icon: ShieldAlert,
    tint: "text-red-300",
    activeCls: "border-red-500/50 bg-red-500/10 text-red-300",
    requirement: "Requires high_authorized_testing",
  },
};

const FILTERS: Array<{ value: RiskFilter; label: string; icon: LucideIcon }> = [
  { value: "all", label: "All", icon: Target },
  { value: "safe", label: "Safe", icon: ShieldCheck },
  { value: "gated", label: "Gated", icon: Lock },
  { value: "high", label: "High", icon: ShieldAlert },
];

interface GoalCounts {
  all: number;
  safe: number;
  gated: number;
  high: number;
  available: number;
}

export function GoalsPage() {
  const goals = useGoals();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<RiskFilter>("all");

  const rows = useMemo(() => goals.data?.goals ?? [], [goals.data]);

  const counts = useMemo(() => {
    const c: GoalCounts = { all: rows.length, safe: 0, gated: 0, high: 0, available: 0 };
    for (const g of rows) {
      c[g.risk] += 1;
      if (g.compatible) c.available += 1;
    }
    return c;
  }, [rows]);

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((g) => {
      if (filter !== "all" && g.risk !== filter) return false;
      if (!q) return true;
      const meta = RISK_META[g.risk];
      return [g.name, g.description, g.risk, meta.label].join(" ").toLowerCase().includes(q);
    });
  }, [rows, query, filter]);

  const hasActiveFilters = query.trim().length > 0 || filter !== "all";

  const clearFilters = () => {
    setQuery("");
    setFilter("all");
  };

  // Safe goals are recon-compatible; gated/high imply exploitation → attack mode.
  // The wizard honors both ?path= (mode) and ?goal= (preselected, compatibility-checked).
  const startGoal = (g: GoalPreset) => {
    navigate(`/runs/new?path=${g.risk === "safe" ? "recon" : "attack"}&goal=${encodeURIComponent(g.name)}`);
  };

  return (
    <div className="mx-auto w-full max-w-6xl space-y-4 p-4 md:p-6">
      {/* Header */}
      <header className="flex flex-wrap items-start gap-3">
        <div className="rounded-md border bg-secondary/40 p-2 text-primary" aria-hidden>
          <Crosshair className="h-5 w-5" />
        </div>
        <div className="min-w-0 space-y-0.5">
          <h1 className="text-lg font-semibold">Goals</h1>
          <p className="text-sm text-muted-foreground">
            Choose an objective for the agent. Goal availability depends on the active authorization / risk profile.
          </p>
          <p className="text-xs text-muted-foreground">
            {counts.all} preset objectives · {counts.available} compatible with the current profile
          </p>
        </div>
      </header>

      {/* Summary stats */}
      <GoalStats counts={counts} />

      {/* Search + risk filters */}
      <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center">
        <div className="relative w-full sm:max-w-xs">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search goals..."
            aria-label="Search goals"
            className="h-8 pl-8 pr-8"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              aria-label="Clear search"
              className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
        <div className="flex flex-wrap gap-1.5 sm:ml-auto" role="group" aria-label="Filter goals by risk">
          {FILTERS.map((f) => (
            <RiskFilterButton
              key={f.value}
              filter={f.value}
              label={f.label}
              icon={f.icon}
              count={f.value === "all" ? counts.all : counts[f.value]}
              active={filter === f.value}
              onClick={() => setFilter(f.value)}
            />
          ))}
        </div>
      </div>

      {/* Risk legend */}
      <RiskLegend />

      {/* Loading / error / empty states */}
      {goals.isLoading && <GoalCardGridSkeleton />}
      {goals.error && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">
          <ShieldAlert className="h-4 w-4 shrink-0" aria-hidden />
          <span>Failed to load goals.</span>
          <Button size="sm" variant="outline" className="ml-auto" onClick={() => goals.refetch()}>
            Retry
          </Button>
        </div>
      )}
      {!goals.isLoading && !goals.error && list.length === 0 && (
        <EmptyGoals onClear={hasActiveFilters ? clearFilters : undefined} />
      )}

      {/* Goal grid */}
      {!goals.isLoading && !goals.error && list.length > 0 && (
        <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
          {list.map((g) => (
            <GoalCard key={g.name} goal={g} onStart={startGoal} />
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Sub-components ─────────────────────────────────────────────────────── */

function GoalStats({ counts }: { counts: GoalCounts }) {
  const tiles: Array<{ key: string; label: string; value: number; Icon: LucideIcon; tint?: string }> = [
    { key: "all", label: "Total", value: counts.all, Icon: Target },
    { key: "safe", label: "Safe", value: counts.safe, Icon: ShieldCheck, tint: "text-emerald-300" },
    { key: "gated", label: "Gated", value: counts.gated, Icon: Lock, tint: "text-yellow-300" },
    { key: "high", label: "High", value: counts.high, Icon: ShieldAlert, tint: "text-red-300" },
    { key: "available", label: "Available", value: counts.available, Icon: CheckCircle2, tint: "text-primary" },
  ];
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-3 lg:grid-cols-5">
      {tiles.map((t) => (
        <div key={t.key} className="flex items-center gap-2.5 bg-card/60 px-3 py-2">
          <t.Icon className={cn("h-4 w-4 shrink-0", t.tint ?? "text-muted-foreground")} aria-hidden />
          <div className="min-w-0">
            <div className={cn("font-mono text-lg leading-tight tabular-nums", t.tint ?? "text-foreground")}>
              {t.value}
            </div>
            <div className="truncate text-[10px] uppercase tracking-wide text-muted-foreground">{t.label}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function RiskFilterButton({
  filter,
  label,
  icon: Icon,
  count,
  active,
  onClick,
}: {
  filter: RiskFilter;
  label: string;
  icon: LucideIcon;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  const meta = filter === "all" ? null : RISK_META[filter];
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
        active
          ? meta?.activeCls ?? "border-primary/60 bg-primary/10 text-primary"
          : "border-border text-muted-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden />
      {label}
      <span className={cn("tabular-nums", active ? "opacity-90" : "text-muted-foreground/70")}>{count}</span>
    </button>
  );
}

function RiskLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 rounded-md border bg-card/30 px-3 py-2 text-xs text-muted-foreground">
      <span className="inline-flex items-center gap-1.5">
        <ShieldCheck className="h-3.5 w-3.5 text-emerald-300" aria-hidden />
        Safe — low-risk objectives available under normal authorized operation.
      </span>
      <span className="inline-flex items-center gap-1.5">
        <Lock className="h-3.5 w-3.5 text-yellow-300" aria-hidden />
        Gated — requires an authorized risk profile.
      </span>
      <span className="inline-flex items-center gap-1.5">
        <ShieldAlert className="h-3.5 w-3.5 text-red-300" aria-hidden />
        High — requires explicit high-authorized-testing configuration.
      </span>
    </div>
  );
}

function GoalCard({ goal, onStart }: { goal: GoalPreset; onStart: (g: GoalPreset) => void }) {
  const meta = RISK_META[goal.risk];
  const Icon = meta.Icon;
  const blocked = !goal.compatible;

  return (
    <Card
      className={cn(
        "flex flex-col bg-card/40",
        blocked
          ? "cursor-default opacity-75 hover:-translate-y-0 hover:shadow-sm"
          : "hover:border-primary/40",
      )}
    >
      <CardContent className="flex flex-1 flex-col p-3.5">
        {/* Header */}
        <div className="flex items-start justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2">
            <Icon className={cn("h-4 w-4 shrink-0", blocked ? "text-muted-foreground" : meta.tint)} aria-hidden />
            <span className="truncate font-mono text-sm font-semibold">{goal.name}</span>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {blocked && (
              <Badge variant="muted" className="text-[10px]">
                <Lock className="h-3 w-3" aria-hidden /> Unavailable
              </Badge>
            )}
            <Badge variant={meta.variant} className="text-[10px]">
              <Icon className="h-3 w-3" aria-hidden />
              {meta.label}
            </Badge>
          </div>
        </div>

        {/* Body */}
        <p className="mt-2 line-clamp-3 text-sm leading-relaxed text-muted-foreground" title={goal.description}>
          {goal.description}
        </p>

        {/* Footer */}
        <div className="mt-3 flex items-center justify-between gap-2 border-t pt-2.5">
          <span
            className={cn(
              "inline-flex min-w-0 items-center gap-1.5 text-xs",
              blocked ? "text-red-300/90" : "text-muted-foreground",
            )}
            title={meta.requirement}
          >
            {blocked && <Lock className="h-3.5 w-3.5 shrink-0" aria-hidden />}
            <span className="truncate">{meta.requirement}</span>
          </span>
          {!blocked && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              className="h-7 shrink-0 px-2.5 text-xs"
              onClick={() => onStart(goal)}
            >
              <Play className="h-3 w-3" aria-hidden /> Use goal
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyGoals({ onClear }: { onClear?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-8 text-center">
      <SearchX className="h-7 w-7 text-muted-foreground/60" aria-hidden />
      <p className="text-sm text-muted-foreground">
        {onClear ? "No goals match your filters." : "No goals available."}
      </p>
      {onClear && (
        <Button type="button" size="sm" variant="outline" className="mt-1" onClick={onClear}>
          Clear filters
        </Button>
      )}
    </div>
  );
}

function GoalCardSkeleton() {
  return (
    <div className="flex flex-col rounded-lg border bg-card/40 p-3.5">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Skeleton className="h-4 w-4 rounded" />
          <Skeleton className="h-4 w-28" />
        </div>
        <Skeleton className="h-4 w-16 rounded-full" />
      </div>
      <Skeleton className="mt-3 h-3 w-full" />
      <Skeleton className="mt-1.5 h-3 w-4/5" />
      <div className="mt-3 flex items-center justify-between gap-2 border-t pt-2.5">
        <Skeleton className="h-3 w-36" />
        <Skeleton className="h-6 w-20 rounded-md" />
      </div>
    </div>
  );
}

function GoalCardGridSkeleton({ count = 6 }: { count?: number }) {
  return (
    <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3" role="status" aria-live="polite" aria-label="Loading goals">
      {Array.from({ length: count }).map((_, i) => (
        <GoalCardSkeleton key={i} />
      ))}
    </div>
  );
}
