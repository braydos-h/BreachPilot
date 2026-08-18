import { useMemo, useState } from "react";
import { ShieldCheck, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { SkeletonRows } from "@/components/Loading";
import { useGoals } from "@/api/hooks";
import type { GoalPreset } from "@/api/types";

const RISK_LABELS: Record<string, { label: string; cls: string }> = {
  safe: { label: "Safe", cls: "text-green-300" },
  gated: { label: "Gated", cls: "text-yellow-300" },
  high: { label: "High", cls: "text-red-300" },
};

export function GoalsPage() {
  const goals = useGoals();
  const [filter, setFilter] = useState<"all" | "safe" | "gated" | "high">("all");

  const list = useMemo(() => {
    const rows = goals.data?.goals ?? [];
    return filter === "all" ? rows : rows.filter((g) => g.risk === filter);
  }, [goals.data, filter]);

  const counts = useMemo(() => {
    const rows = goals.data?.goals ?? [];
    return {
      all: rows.length,
      safe: rows.filter((g) => g.risk === "safe").length,
      gated: rows.filter((g) => g.risk === "gated").length,
      high: rows.filter((g) => g.risk === "high").length,
    };
  }, [goals.data]);

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div>
        <h1 className="text-lg font-semibold">Goals</h1>
        <p className="text-sm text-muted-foreground">
          Preset objectives you can assign to a run. Higher-risk goals require a matching risk profile opt-in.
        </p>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {(
          [
            ["all", `All (${counts.all})`],
            ["safe", `Safe (${counts.safe})`],
            ["gated", `Gated (${counts.gated})`],
            ["high", `High (${counts.high})`],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            onClick={() => setFilter(value)}
            className={cn(
              "rounded-full border px-2.5 py-1 text-xs transition-colors",
              filter === value
                ? "border-primary/60 bg-primary/10 text-primary"
                : "border-border text-muted-foreground hover:bg-accent hover:text-foreground",
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {goals.isLoading && <SkeletonRows count={6} />}
      {goals.error && <div className="text-sm text-destructive">Failed to load goals.</div>}

      <div className="grid gap-2.5 sm:grid-cols-2">
        {list.map((g) => (
          <GoalCard key={g.name} goal={g} />
        ))}
      </div>
      {!goals.isLoading && !goals.error && list.length === 0 && (
        <p className="text-sm text-muted-foreground">No goals in this category.</p>
      )}
    </div>
  );
}

function GoalCard({ goal }: { goal: GoalPreset }) {
  const risk = RISK_LABELS[goal.risk] ?? RISK_LABELS.safe;
  const Icon = goal.risk === "safe" ? ShieldCheck : ShieldAlert;
  return (
    <Card className="bg-card/40">
      <CardContent className="p-3.5">
        <div className="flex items-center justify-between gap-2">
          <span className="font-mono text-sm font-semibold">{goal.name}</span>
          <Badge variant="outline" className={cn("text-[10px]", risk.cls)}>
            <Icon className="h-3 w-3" />
            {risk.label}
          </Badge>
        </div>
        <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">{goal.description}</p>
        {goal.risk === "high" && (
          <p className="mt-2 rounded border border-destructive/30 bg-destructive/10 px-2 py-1 text-xs text-red-200">
            Requires risk_profile: high_authorized_testing to select.
          </p>
        )}
        {goal.risk === "gated" && (
          <p className="mt-2 rounded border border-yellow-500/30 bg-yellow-500/10 px-2 py-1 text-xs text-yellow-300">
            Requires risk_profile: standard_authorized or higher to select.
          </p>
        )}
      </CardContent>
    </Card>
  );
}
