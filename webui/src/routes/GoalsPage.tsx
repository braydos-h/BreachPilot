import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Bookmark,
  CheckCircle2,
  Crosshair,
  Lock,
  Pencil,
  Play,
  Plus,
  Search,
  SearchX,
  ShieldAlert,
  ShieldCheck,
  Target,
  Trash2,
  X,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/Loading";
import { useCreateGoal, useDeleteGoal, useGoals, useUpdateGoal } from "@/api/hooks";
import { ApiError } from "@/api/client";
import type { CustomGoal, GoalPreset, RiskTag } from "@/api/types";
import { CustomGoalDialog } from "@/components/goals/CustomGoalDialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

type RiskFilter = "all" | RiskTag | "custom";

interface RiskMeta {
  label: string;
  variant: "success" | "warn" | "danger";
  Icon: LucideIcon;
  tint: string;
  activeCls: string;
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
  { value: "custom", label: "Custom", icon: Bookmark },
];

interface GoalCounts {
  all: number;
  safe: number;
  gated: number;
  high: number;
  custom: number;
  available: number;
}

export function GoalsPage() {
  const goals = useGoals();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<RiskFilter>("all");

  const createGoal = useCreateGoal();
  const updateGoal = useUpdateGoal();
  const deleteGoal = useDeleteGoal();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingGoal, setEditingGoal] = useState<CustomGoal | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CustomGoal | null>(null);
  const [serverError, setServerError] = useState("");

  const presets = useMemo(() => goals.data?.goals ?? [], [goals.data]);
  const customGoals = useMemo(() => goals.data?.custom_goals ?? [], [goals.data]);

  const counts = useMemo(() => {
    const c: GoalCounts = { all: presets.length + customGoals.length, safe: 0, gated: 0, high: 0, custom: customGoals.length, available: 0 };
    for (const g of presets) {
      c[g.risk] += 1;
      if (g.compatible) c.available += 1;
    }
    c.available += customGoals.length;
    return c;
  }, [presets, customGoals]);

  const filteredPresets = useMemo(() => {
    const q = query.trim().toLowerCase();
    return presets.filter((g) => {
      if (filter !== "all" && filter !== "custom" && g.risk !== filter) return false;
      if (filter === "custom") return false;
      if (!q) return true;
      const meta = RISK_META[g.risk];
      return [g.name, g.description, g.risk, meta.label].join(" ").toLowerCase().includes(q);
    });
  }, [presets, query, filter]);

  const filteredCustom = useMemo(() => {
    const q = query.trim().toLowerCase();
    return customGoals.filter((g) => {
      if (filter !== "all" && filter !== "custom") return false;
      if (!q) return true;
      return [g.name, g.objective, "custom"].join(" ").toLowerCase().includes(q);
    });
  }, [customGoals, query, filter]);

  const hasActiveFilters = query.trim().length > 0 || filter !== "all";

  const clearFilters = () => {
    setQuery("");
    setFilter("all");
  };

  const startPreset = (g: GoalPreset) => {
    navigate(`/runs/new?path=${g.risk === "safe" ? "recon" : "attack"}&goal=${encodeURIComponent(g.name)}`);
  };

  const startCustom = (g: CustomGoal) => {
    navigate(`/runs/new?path=attack&customGoal=${encodeURIComponent(g.id)}`);
  };

  const openCreate = () => {
    setEditingGoal(null);
    setServerError("");
    setDialogOpen(true);
  };

  const openEdit = (g: CustomGoal) => {
    setEditingGoal(g);
    setServerError("");
    setDialogOpen(true);
  };

  const handleDialogSubmit = (data: { name: string; objective: string }) => {
    setServerError("");
    if (editingGoal) {
      updateGoal.mutate(
        { id: editingGoal.id, name: data.name, objective: data.objective },
        {
          onSuccess: () => {
            setDialogOpen(false);
            setEditingGoal(null);
            setServerError("");
          },
          onError: (err) => {
            const msg = err instanceof ApiError ? err.message : "Failed to update goal.";
            setServerError(msg);
          },
        },
      );
    } else {
      createGoal.mutate(data, {
        onSuccess: () => {
          setDialogOpen(false);
          setServerError("");
        },
        onError: (err) => {
          const msg = err instanceof ApiError ? err.message : "Failed to create goal.";
          setServerError(msg);
        },
      });
    }
  };

  const handleDeleteConfirm = () => {
    if (!deleteTarget) return;
    deleteGoal.mutate(deleteTarget.id, {
      onSuccess: () => setDeleteTarget(null),
    });
  };

  const isSaving = createGoal.isPending || updateGoal.isPending;
  const combinedLength = filteredPresets.length + filteredCustom.length;

  return (
    <div className="mx-auto w-full max-w-6xl space-y-4 p-4 md:p-6">
      <header className="flex flex-wrap items-start gap-3">
        <div className="rounded-md border bg-secondary/40 p-2 text-primary" aria-hidden>
          <Crosshair className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1 space-y-0.5">
          <h1 className="text-lg font-semibold">Goals</h1>
          <p className="text-sm text-muted-foreground">
            Choose an objective for the agent. Goal availability depends on the active authorization / risk profile.
          </p>
          <p className="text-xs text-muted-foreground">
            {presets.length} preset objectives · {customGoals.length} custom goals · {counts.available} compatible with the current profile
          </p>
        </div>
        <Button type="button" size="sm" onClick={openCreate} className="ml-auto shrink-0">
          <Plus className="h-4 w-4" /> Add custom goal
        </Button>
      </header>

      <GoalStats counts={counts} />

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
              count={f.value === "all" ? counts.all : f.value === "custom" ? counts.custom : counts[f.value as RiskTag]}
              active={filter === f.value}
              onClick={() => setFilter(f.value)}
            />
          ))}
        </div>
      </div>

      <RiskLegend />

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
      {!goals.isLoading && !goals.error && combinedLength === 0 && (
        <EmptyGoals onClear={hasActiveFilters ? clearFilters : undefined} />
      )}

      {!goals.isLoading && !goals.error && combinedLength > 0 && (
        <div className="grid gap-2.5 sm:grid-cols-2 xl:grid-cols-3">
          {filteredPresets.map((g) => (
            <GoalCard key={`preset-${g.name}`} goal={g} onStart={startPreset} />
          ))}
          {filteredCustom.map((g) => (
            <CustomGoalCard
              key={`custom-${g.id}`}
              goal={g}
              onStart={startCustom}
              onEdit={openEdit}
              onDelete={setDeleteTarget}
            />
          ))}
        </div>
      )}

      <CustomGoalDialog
        open={dialogOpen}
        onOpenChange={(o) => {
          setDialogOpen(o);
          if (!o) {
            setEditingGoal(null);
            setServerError("");
          }
        }}
        initial={editingGoal}
        onSubmit={handleDialogSubmit}
        isPending={isSaving}
        serverError={serverError}
      />

      <Dialog open={deleteTarget !== null} onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete custom goal?</DialogTitle>
            <DialogDescription>
              {deleteTarget
                ? `This will permanently delete "${deleteTarget.name}". This action cannot be undone.`
                : "This will permanently delete this custom goal."}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => setDeleteTarget(null)} disabled={deleteGoal.isPending}>
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={handleDeleteConfirm}
              disabled={deleteGoal.isPending}
            >
              {deleteGoal.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function GoalStats({ counts }: { counts: GoalCounts }) {
  const tiles: Array<{ key: string; label: string; value: number; Icon: LucideIcon; tint?: string }> = [
    { key: "all", label: "Total", value: counts.all, Icon: Target },
    { key: "safe", label: "Safe", value: counts.safe, Icon: ShieldCheck, tint: "text-emerald-300" },
    { key: "gated", label: "Gated", value: counts.gated, Icon: Lock, tint: "text-yellow-300" },
    { key: "high", label: "High", value: counts.high, Icon: ShieldAlert, tint: "text-red-300" },
    { key: "custom", label: "Custom", value: counts.custom, Icon: Bookmark, tint: "text-violet-300" },
    { key: "available", label: "Available", value: counts.available, Icon: CheckCircle2, tint: "text-primary" },
  ];
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-3 lg:grid-cols-6">
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
  const meta = filter === "all" || filter === "custom" ? null : RISK_META[filter as RiskTag];
  const customActiveCls = "border-violet-500/50 bg-violet-500/10 text-violet-300";
  const activeCls = filter === "custom" ? customActiveCls : meta?.activeCls;
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background",
        active
          ? activeCls ?? "border-primary/60 bg-primary/10 text-primary"
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
      <span className="inline-flex items-center gap-1.5">
        <Bookmark className="h-3.5 w-3.5 text-violet-300" aria-hidden />
        Custom — user-created objectives.
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

        <p className="mt-2 line-clamp-3 text-sm leading-relaxed text-muted-foreground" title={goal.description}>
          {goal.description}
        </p>

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

function CustomGoalCard({
  goal,
  onStart,
  onEdit,
  onDelete,
}: {
  goal: CustomGoal;
  onStart: (g: CustomGoal) => void;
  onEdit: (g: CustomGoal) => void;
  onDelete: (g: CustomGoal) => void;
}) {
  return (
    <Card className="flex flex-col bg-card/40 hover:border-violet-500/40">
      <CardContent className="flex flex-1 flex-col p-3.5">
        <div className="flex items-start justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2">
            <Bookmark className="h-4 w-4 shrink-0 text-violet-300" aria-hidden />
            <span className="truncate font-mono text-sm font-semibold">{goal.name}</span>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <Badge variant="violet" className="text-[10px]">
              <Bookmark className="h-3 w-3" aria-hidden />
              Custom
            </Badge>
          </div>
        </div>

        <p className="mt-2 line-clamp-3 text-sm leading-relaxed text-muted-foreground" title={goal.objective}>
          {goal.objective}
        </p>

        <div className="mt-3 flex items-center justify-between gap-2 border-t pt-2.5">
          <div className="flex items-center gap-1">
            <Button
              type="button"
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-xs"
              onClick={() => onEdit(goal)}
              aria-label={`Edit ${goal.name}`}
            >
              <Pencil className="h-3 w-3" aria-hidden /> Edit
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-xs text-muted-foreground hover:text-destructive"
              onClick={() => onDelete(goal)}
              aria-label={`Delete ${goal.name}`}
            >
              <Trash2 className="h-3 w-3" aria-hidden /> Delete
            </Button>
          </div>
          <Button
            type="button"
            size="sm"
            variant="outline"
            className="h-7 shrink-0 px-2.5 text-xs"
            onClick={() => onStart(goal)}
          >
            <Play className="h-3 w-3" aria-hidden /> Use goal
          </Button>
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
