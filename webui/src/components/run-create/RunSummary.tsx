import { Swords } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { executionProfileLabel, type ExecutionProfileId } from "./profile";
import type { ObserverMode, RunMode, SkillsMode } from "@/api/types";

interface RunSummaryProps {
  mode: RunMode;
  target: string;
  goalMode: "preset" | "custom";
  goal: string;
  customGoal: string;
  model: string;
  profile: ExecutionProfileId;
  powerUpCount: number;
  skillsMode: SkillsMode;
  observerMode: ObserverMode;
  reconFirst: boolean | null;
  yes: boolean;
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <dt className="shrink-0 text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 truncate text-right text-xs font-medium text-foreground">{value}</dd>
    </div>
  );
}

const NONE = "Not selected";

/** Live run summary sidebar. Sticky on desktop; shows a compact card on
 *  mobile. Empty selections render as "Not selected" so nothing silently
 *  defaults. Attack gets a slightly stronger header, not an all-red panel. */
export function RunSummary({
  mode,
  target,
  goalMode,
  goal,
  customGoal,
  model,
  profile,
  powerUpCount,
  skillsMode,
  observerMode,
  reconFirst,
  yes,
}: RunSummaryProps) {
  const goalValue =
    goalMode === "custom" ? (customGoal.trim() || NONE) : goal || NONE;
  const reconLabel =
    reconFirst === null ? "Auto" : reconFirst ? "On" : "Off";
  const isAttack = mode === "attack";

  return (
    <Card className="h-fit">
      <CardContent className="space-y-3 pt-5">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "flex h-8 w-8 items-center justify-center rounded-md border",
              isAttack
                ? "border-amber-500/30 bg-amber-500/10 text-amber-300"
                : "border-primary/30 bg-primary/10 text-primary",
            )}
            aria-hidden
          >
            <Swords className="h-4 w-4" />
          </span>
          <div>
            <h2 className="text-sm font-semibold">{isAttack ? "Attack run" : "Recon run"}</h2>
            <p className="text-xs text-muted-foreground">Live configuration summary</p>
          </div>
        </div>

        <dl className="divide-y divide-border/60">
          <Row label="Target" value={target || NONE} />
          <Row label="Mode" value={mode === "attack" ? "Attack" : "Recon"} />
          <Row label="Goal" value={goalValue} />
          <Row label="Model" value={model || NONE} />
          <Row label="Profile" value={executionProfileLabel(profile)} />
          <Row label="Power-ups" value={`${powerUpCount} enabled`} />
          <Row label="Skills" value={skillsMode === "off" ? "Off" : skillsMode.charAt(0).toUpperCase() + skillsMode.slice(1)} />
          <Row label="Observer" value={observerMode.charAt(0).toUpperCase() + observerMode.slice(1)} />
          <Row label="Recon first" value={reconLabel} />
          <Row label="Confirmation" value={yes ? "Skipped" : "Required"} />
        </dl>
      </CardContent>
    </Card>
  );
}
