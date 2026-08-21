import { Lock } from "lucide-react";
import { cn } from "@/lib/utils";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { SegmentedControl, TriStateToggle } from "@/components/RunForm";
import type { ObserverMode } from "@/api/types";

const POWER_UPS = [
  { key: "swarm", label: "Swarm", hint: "Multi-agent swarm execution.", requires: null },
  { key: "parallel_swarm", label: "Parallel swarm", hint: "Swarm agents run in parallel.", requires: "swarm" },
  { key: "critic", label: "Critic", hint: "Critic agent critiques swarm steps.", requires: "swarm" },
  { key: "reflection", label: "Reflection", hint: "Swarm self-reflects on each step.", requires: "swarm" },
  { key: "adaptive_exploits", label: "Adaptive exploits", hint: "Adapt exploit attempts to recon findings.", requires: null },
  { key: "long_session", label: "Long session", hint: "Extend the agent session past the default cap.", requires: null },
  { key: "multi_model_consult", label: "Multi-model consult", hint: "Consult peer models during the run.", requires: null },
  { key: "ultrathink", label: "Ultrathink", hint: "Allocate extra thinking budget per step.", requires: null },
] as const;

const OBSERVER_OPTIONS = ["heuristic", "llm", "hybrid"] as const;

interface AdvancedExecutionSettingsProps {
  flags: string[];
  powerUps: Record<string, boolean>;
  onTogglePowerUp: (key: string) => void;
  observerMode: ObserverMode;
  setObserverMode: (v: ObserverMode) => void;
  reconFirst: boolean | null;
  setReconFirst: (v: boolean | null) => void;
}

/** Power-ups, observer mode and recon-first. Hidden from the model if the
 *  backend capability flag is absent; swarm-dependent options dim with a
 *  "Requires swarm" note while swarm is off. */
export function AdvancedExecutionSettings({
  flags,
  powerUps,
  onTogglePowerUp,
  observerMode,
  setObserverMode,
  reconFirst,
  setReconFirst,
}: AdvancedExecutionSettingsProps) {
  const visible = POWER_UPS.filter((p) => flags.includes(p.key));
  const swarm = !!powerUps.swarm;

  return (
    <div className="space-y-5">
      <div className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
        {visible.map((p) => {
          const requiresSwarm = p.requires === "swarm";
          const disabled = requiresSwarm && !swarm;
          const checked = !!powerUps[p.key];
          return (
            <div
              key={p.key}
              className={cn(
                "flex items-start justify-between gap-3 rounded-lg border px-3 py-2.5",
                disabled && "opacity-50",
              )}
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-sm font-medium">{p.label}</span>
                  {requiresSwarm && (
                    <Badge variant="muted" className="text-[10px]">
                      <Lock className="h-3 w-3" aria-hidden /> Requires swarm
                    </Badge>
                  )}
                </div>
                <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{p.hint}</p>
              </div>
              <Switch
                checked={checked}
                onCheckedChange={() => onTogglePowerUp(p.key)}
                disabled={disabled}
                aria-label={p.label}
              />
            </div>
          );
        })}
      </div>

      <div className="grid gap-x-6 gap-y-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label className="text-sm font-semibold">Observer mode</Label>
          <SegmentedControl
            value={observerMode}
            onChange={(v) => setObserverMode(v as ObserverMode)}
            options={OBSERVER_OPTIONS.map((o) => ({ value: o, label: o.charAt(0).toUpperCase() + o.slice(1) }))}
          />
          <p className="text-xs text-muted-foreground">
            How the agent interprets tool results after each step. Hybrid = balanced default.
          </p>
        </div>
        <div className="space-y-2">
          <Label className="text-sm font-semibold">Recon first</Label>
          <TriStateToggle value={reconFirst} onChange={setReconFirst} labels={{ true: "On", false: "Off", null: "Auto" }} />
          <p className="text-xs text-muted-foreground">
            Run a reconnaissance phase before the goal phase. Auto = only when no goal is selected.
          </p>
        </div>
      </div>
    </div>
  );
}
