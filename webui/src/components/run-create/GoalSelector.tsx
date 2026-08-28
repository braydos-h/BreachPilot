import { useMemo, useState } from "react";
import { Lock, Search, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { SegmentedControl } from "@/components/ui/segmented";
import type { GoalPreset, RiskTag, RunMode } from "@/api/types";

const RISK_BADGE: Record<RiskTag, "success" | "warn" | "danger"> = {
  safe: "success",
  gated: "warn",
  high: "danger",
};
const RISK_LABEL: Record<RiskTag, string> = { safe: "Safe", gated: "Gated", high: "High" };
const RISK_ORDER: RiskTag[] = ["safe", "gated", "high"];

interface GoalSelectorProps {
  mode: RunMode;
  goalMode: "preset" | "custom";
  setGoalMode: (v: "preset" | "custom") => void;
  goal: string;
  setGoal: (v: string) => void;
  customGoal: string;
  setCustomGoal: (v: string) => void;
  goalGroups: Record<string, GoalPreset[]>;
}

/** Preset / custom goal selection. Presets render as a searchable goal browser
 *  showing name, description, risk badge and compatibility state. */
export function GoalSelector({
  mode,
  goalMode,
  setGoalMode,
  goal,
  setGoal,
  customGoal,
  setCustomGoal,
  goalGroups,
}: GoalSelectorProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const selected = useMemo(
    () => RISK_ORDER.flatMap((risk) => goalGroups[risk] ?? []).find((g) => g.name === goal) ?? null,
    [goal, goalGroups],
  );

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    return RISK_ORDER.map((risk) => ({
      risk,
      goals: (goalGroups[risk] ?? []).filter(
        (g) =>
          !q ||
          g.name.toLowerCase().includes(q) ||
          (g.description ?? "").toLowerCase().includes(q),
      ),
    }));
  }, [query, goalGroups]);

  const anyMatch = groups.some((g) => g.goals.length > 0);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2.5">
        <Label className="text-sm font-semibold">Goal</Label>
        <SegmentedControl
          value={goalMode}
          onChange={(v) => setGoalMode(v as "preset" | "custom")}
          options={[
            { value: "preset", label: "Preset" },
            { value: "custom", label: "Custom" },
          ]}
        />
      </div>

      {goalMode === "preset" ? (
        <Popover open={open} onOpenChange={setOpen}>
          <PopoverTrigger asChild>
            <button
              type="button"
              className={cn(
                "flex w-full items-center justify-between gap-3 rounded-lg border p-4 text-left transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                selected
                  ? "border-border bg-background/40 hover:border-muted-foreground/40"
                  : "border-dashed border-muted-foreground/40 hover:border-muted-foreground/60 hover:bg-accent/30",
              )}
            >
              {selected ? (
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-semibold">{selected.name}</span>
                    <Badge variant={RISK_BADGE[selected.risk]} className="text-[10px]">
                      {RISK_LABEL[selected.risk]}
                    </Badge>
                    {!selected.compatible && (
                      <Badge variant="muted" className="text-[10px]">
                        <Lock className="h-3 w-3" aria-hidden /> Unavailable
                      </Badge>
                    )}
                  </span>
                  <span className="mt-1 block text-xs leading-relaxed text-muted-foreground">
                    {selected.description}
                  </span>
                </span>
              ) : (
                <span className="min-w-0 flex-1">
                  <span className="text-sm text-muted-foreground">Select a preset goal</span>
                  <span className="mt-1 block text-xs text-muted-foreground/70">
                    Objectives defined by the mission profile, from safe recon to high-impact exploitation.
                  </span>
                </span>
              )}
              <span className="inline-flex shrink-0 items-center gap-1.5 rounded-md border px-2 py-1 text-xs text-muted-foreground">
                <Search className="h-3 w-3" aria-hidden /> Browse
              </span>
            </button>
          </PopoverTrigger>
          <PopoverContent align="start" sideOffset={6} className="w-[min(28rem,calc(100vw-2rem))] p-0">
            <div className="border-b p-2.5">
              <div className="relative">
                <Search
                  className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                  aria-hidden
                />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search goals..."
                  aria-label="Search goals"
                  className="h-8 pl-8 pr-8"
                  autoFocus
                />
                {query && (
                  <button
                    type="button"
                    onClick={() => setQuery("")}
                    aria-label="Clear goal search"
                    className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            </div>
            <div className="max-h-80 overflow-y-auto p-1.5 scrollbar-thin">
              {!anyMatch ? (
                <p className="p-3 text-center text-xs text-muted-foreground">
                  No goals match your search.
                </p>
              ) : (
                groups.map((group) =>
                  group.goals.length === 0 ? null : (
                    <div key={group.risk} className="mb-1">
                      <div className="px-2 py-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                        {RISK_LABEL[group.risk]}
                      </div>
                      {group.goals.map((g) => (
                        <button
                          key={g.name}
                          type="button"
                          onClick={() => {
                            setGoal(g.name);
                            setOpen(false);
                            setQuery("");
                          }}
                          className={cn(
                            "flex w-full flex-col gap-1 rounded-md px-2.5 py-2 text-left text-sm transition-colors",
                            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                            g.name === goal ? "bg-primary/10 text-primary" : "hover:bg-accent",
                            !g.compatible && "opacity-70",
                          )}
                        >
                          <span className="flex items-center justify-between gap-2">
                            <span className="font-mono font-medium">{g.name}</span>
                            <span className="flex shrink-0 items-center gap-1.5">
                              {!g.compatible && (
                                <Badge variant="muted" className="text-[10px]">
                                  <Lock className="h-3 w-3" aria-hidden /> Unavailable
                                </Badge>
                              )}
                              <Badge variant={RISK_BADGE[g.risk]} className="text-[10px]">
                                {RISK_LABEL[g.risk]}
                              </Badge>
                            </span>
                          </span>
                          <span className="text-xs leading-relaxed text-muted-foreground">
                            {g.description}
                          </span>
                        </button>
                      ))}
                    </div>
                  ),
                )
              )}
            </div>
          </PopoverContent>
        </Popover>
      ) : (
        <div className="space-y-1.5">
          <Textarea
            value={customGoal}
            onChange={(e) => setCustomGoal(e.target.value)}
            placeholder={
              "Describe the objective in your own words — e.g. “Obtain a verified foothold on " +
              "the target, then attempt privilege escalation to a domain account.”"
            }
            aria-label="Custom goal"
            className="min-h-[6.5rem]"
          />
          <p className="text-xs text-muted-foreground">
            The agent plans around this objective instead of a preset outcome.
          </p>
        </div>
      )}

      {mode === "recon" && (
        <p className="text-xs text-muted-foreground">Recon mode ignores the goal and runs recon-first.</p>
      )}
    </div>
  );
}
