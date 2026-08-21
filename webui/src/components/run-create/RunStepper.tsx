import { Check, ClipboardCheck, Settings2, ShieldCheck, Target } from "lucide-react";
import { cn } from "@/lib/utils";

export const STEPS = ["opsec", "settings", "target", "review"] as const;
export type Step = (typeof STEPS)[number];

export const STEP_META: Array<{ key: Step; label: string; icon: typeof Target }> = [
  { key: "opsec", label: "OPSEC", icon: ShieldCheck },
  { key: "settings", label: "Configure", icon: Settings2 },
  { key: "target", label: "Target", icon: Target },
  { key: "review", label: "Review & launch", icon: ClipboardCheck },
];

interface RunStepperProps {
  current: Step;
  /** Whether a step may be clicked right now (back = safe, next = validated). */
  canVisit: Record<Step, boolean>;
  onNavigate: (step: Step) => void;
}

/** Guided step navigation: completed steps are clickable going back, the next
 *  step is clickable when validation allows it, everything further is locked. */
export function RunStepper({ current, canVisit, onNavigate }: RunStepperProps) {
  const idx = STEPS.indexOf(current);
  return (
    <nav aria-label="Wizard steps" className="flex items-center gap-1.5 overflow-x-auto pb-1">
      {STEP_META.map((s, i) => {
        const Icon = s.icon;
        const done = i < idx;
        const active = i === idx;
        const clickable = i !== idx && canVisit[s.key];
        return (
          <div key={s.key} className="flex shrink-0 items-center gap-1.5">
            <button
              type="button"
              onClick={() => clickable && onNavigate(s.key)}
              disabled={!clickable}
              aria-current={active ? "step" : undefined}
              className={cn(
                "group flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                clickable && "cursor-pointer hover:bg-accent",
                active && "border-primary/40 bg-primary/10 font-medium text-primary",
                done && !active && "border-transparent text-emerald-400",
                !active && !done && "border-transparent text-muted-foreground/70",
              )}
            >
              <span
                className={cn(
                  "flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold",
                  active && "bg-primary text-primary-foreground",
                  done && "bg-emerald-500/15 text-emerald-400",
                  !active && !done && "bg-muted text-muted-foreground",
                )}
                aria-hidden
              >
                {done ? <Check className="h-3 w-3" /> : <Icon className="h-3 w-3" />}
              </span>
              <span className="hidden sm:inline">{s.label}</span>
              {done && <span className="sr-only">(completed)</span>}
            </button>
            {i < STEP_META.length - 1 && (
              <div
                className={cn("h-px w-4 md:w-8", i < idx ? "bg-emerald-500/40" : "bg-border")}
                aria-hidden
              />
            )}
          </div>
        );
      })}
    </nav>
  );
}
