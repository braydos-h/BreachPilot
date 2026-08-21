import { Fragment, memo } from "react";
import { Check, Loader2, Square } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RunState } from "@/api/types";
import { isTerminalState } from "@/api/types";
import { phaseInfo, STEP_PHASES, type DerivedRun } from "@/lib/deriveRun";

interface PhaseTrackerProps {
  derived: DerivedRun;
  runState?: RunState;
  className?: string;
}

type NodeState = "done" | "current" | "future" | "interrupted";

function nodeState(
  derived: DerivedRun,
  terminal: boolean,
  runState: RunState | undefined,
  stepIndex: number,
): NodeState {
  const orderIndex = stepIndex + 1; // STEP_PHASES[0] (recon) == PHASE_ORDER[1]
  if (terminal && runState === "completed") return "done";
  if (terminal) {
    if (orderIndex < derived.lastReachedIndex) return "done";
    if (orderIndex === derived.lastReachedIndex) return "interrupted";
    return "future";
  }
  if (derived.phaseIndex >= 0) {
    if (orderIndex < derived.phaseIndex) return "done";
    if (orderIndex === derived.phaseIndex) return "current";
    return "future";
  }
  // Out-of-sequence phase (research_assistant / swarm phases): the reached
  // steps are done, nothing is "current".
  return orderIndex <= derived.lastReachedIndex ? "done" : "future";
}

/**
 * Five-step phase stepper (Recon → Enumeration → Vuln Research → Validation →
 * Reporting) with done / current / interrupted / future states. The single
 * "current" phase reads on the right; out-of-sequence phases (starting,
 * research_assistant, swarm phases) render gracefully with no highlighted step.
 */
export const PhaseTracker = memo(function PhaseTracker({
  derived,
  runState,
  className,
}: PhaseTrackerProps) {
  const terminal = isTerminalState(runState as RunState);
  const info = phaseInfo(derived.phase);
  const doneCount = STEP_PHASES.reduce(
    (acc, _, i) => acc + (nodeState(derived, terminal, runState, i) === "done" ? 1 : 0),
    0,
  );
  const anyActive =
    !terminal && derived.phaseIndex >= 1 && derived.phaseIndex <= STEP_PHASES.length;

  const caption =
    terminal && runState === "completed"
      ? "Run complete"
      : terminal
        ? `Stopped in ${info.label}`
        : `${info.label} — ${info.summary}`;

  return (
    <div className={cn("flex w-full items-center gap-3", className)}>
      <div className="hidden shrink-0 items-center gap-1.5 xl:flex">
        {!terminal ? (
          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-primary" aria-hidden />
        ) : (
          <Check className="h-3.5 w-3.5 shrink-0 text-emerald-400" aria-hidden />
        )}
        <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Phase</span>
        <span className={cn("font-mono text-xs", terminal && runState !== "completed" ? "text-red-300" : "text-foreground")}>
          {info.label}
        </span>
      </div>
      <div className="flex shrink-0 items-center gap-1 xl:hidden">
        {!terminal ? (
          <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-primary" aria-hidden />
        ) : (
          <Check className="h-3.5 w-3.5 shrink-0 text-emerald-400" aria-hidden />
        )}
        <span className={cn("truncate font-mono text-xs", terminal && runState !== "completed" ? "text-red-300" : "text-foreground")}>
          {info.label}
        </span>
      </div>
      <div
        className="flex flex-1 items-center"
        role="progressbar"
        aria-valuenow={doneCount + (anyActive ? 1 : 0)}
        aria-valuemin={0}
        aria-valuemax={STEP_PHASES.length}
        aria-label={`Phase progress: ${info.label}`}
      >
        {STEP_PHASES.map((p, i) => {
          const st = nodeState(derived, terminal, runState, i);
          const stepInfo = phaseInfo(p);
          return (
            <Fragment key={p}>
              {i > 0 && (
                <div
                  aria-hidden
                  className={cn(
                    "mx-1 h-0.5 flex-1 rounded-full",
                    st === "done" || st === "interrupted" ? "bg-emerald-500/50" : "bg-muted-foreground/20",
                  )}
                />
              )}
              <div className="flex shrink-0 flex-col items-center gap-0.5">
                <div
                  className={cn(
                    "flex h-5 w-5 items-center justify-center rounded-full border text-[10px] font-semibold transition-colors",
                    st === "done" && "border-emerald-500/40 bg-emerald-500/15 text-emerald-400",
                    st === "current" && "border-primary bg-primary/15 text-primary",
                    st === "interrupted" && "border-destructive/50 bg-destructive/10 text-red-400",
                    st === "future" && "border-border bg-card/40 text-muted-foreground",
                  )}
                  title={`${stepInfo.label} — ${stepInfo.summary}`}
                >
                  {st === "done" ? (
                    <Check className="h-3 w-3" aria-hidden />
                  ) : st === "interrupted" ? (
                    <Square className="h-2.5 w-2.5" aria-hidden />
                  ) : st === "current" ? (
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary/70" />
                      <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-primary" />
                    </span>
                  ) : (
                    <span aria-hidden>{i + 1}</span>
                  )}
                </div>
                <div
                  className={cn(
                    "hidden text-center text-[9px] font-medium uppercase tracking-wide xl:block",
                    st === "current"
                      ? "text-foreground"
                      : st === "done" || st === "interrupted"
                        ? "text-muted-foreground"
                        : "text-muted-foreground/60",
                  )}
                >
                  {stepInfo.short}
                </div>
              </div>
            </Fragment>
          );
        })}
      </div>
      <span className="hidden shrink-0 truncate text-[11px] text-muted-foreground xl:block" aria-hidden>
        {caption}
      </span>
    </div>
  );
});
